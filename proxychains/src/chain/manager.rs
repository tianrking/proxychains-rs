//! Proxy chain manager

use std::net::Ipv4Addr;

use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::{ChainType, Config, ProxyData, ProxyState};
use crate::error::{Error, Result};
use crate::proxy::{connect_to_proxy, tunnel_through_proxy, TargetAddress};

use super::selector::{count_alive, mark_blocked, mark_down, ProxySelector};

/// Error codes for chain operations (compatible with C version)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    Success = 0,
    MemoryFail = 1,
    SocketError = 2,
    ChainDown = 3,
    ChainEmpty = 4,
    Blocked = 5,
}

impl From<ChainError> for Error {
    fn from(e: ChainError) -> Self {
        match e {
            ChainError::Success => Error::Chain("Success".to_string()),
            ChainError::MemoryFail => Error::MemoryFail,
            ChainError::SocketError => Error::SocketError,
            ChainError::ChainDown => Error::ChainDown,
            ChainError::ChainEmpty => Error::ChainEmpty,
            ChainError::Blocked => Error::Blocked,
        }
    }
}

/// Chain manager state
pub struct ChainManager {
    config: Config,
    selector: ProxySelector,
    /// Mutable proxy state (for tracking which proxies are up/down)
    proxy_states: Mutex<Vec<ProxyData>>,
}

impl ChainManager {
    /// Create a new chain manager
    pub fn new(config: Config) -> Self {
        let selector = ProxySelector::from_chain_type(config.chain_type);
        let proxy_states = Mutex::new(config.proxies.clone());

        Self {
            config,
            selector,
            proxy_states,
        }
    }

    /// Connect to target through proxy chain
    pub fn connect_proxy_chain(
        &self,
        target_ip: Ipv4Addr,
        target_port: u16,
        target_domain: Option<&str>,
    ) -> Result<std::net::TcpStream> {
        let mut proxy_states = self.proxy_states.lock();

        if proxy_states.is_empty() {
            return Err(Error::ChainEmpty);
        }

        let target = if let Some(domain) = target_domain {
            TargetAddress::from_both(target_ip, domain)
        } else {
            TargetAddress::from_ip(target_ip)
        };

        match self.config.chain_type {
            ChainType::Strict => self.strict_chain(&mut proxy_states, &target, target_port),
            ChainType::Dynamic => self.dynamic_chain(&mut proxy_states, &target, target_port),
            ChainType::Random => self.random_chain(&mut proxy_states, &target, target_port),
            ChainType::LoadBalance => self.load_balance_chain(&mut proxy_states, &target, target_port),
            ChainType::Failover => self.failover_chain(&mut proxy_states, &target, target_port),
        }
    }

    /// Strict chain - all proxies must work
    fn strict_chain(
        &self,
        proxies: &mut [ProxyData],
        target: &TargetAddress,
        target_port: u16,
    ) -> Result<std::net::TcpStream> {
        debug!("Starting strict chain connection");

        // First, connect to the first proxy
        let first_proxy = &proxies[0];
        let mut stream = match connect_to_proxy(first_proxy, self.config.tcp_connect_timeout) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to first proxy: {}", e);
                mark_down(&mut proxies[0]);
                return Err(Error::ChainDown);
            }
        };

        stream.set_read_timeout(Some(self.config.tcp_read_timeout))?;
        stream.set_write_timeout(Some(self.config.tcp_read_timeout))?;

        // If only one proxy, tunnel directly to target
        if proxies.len() == 1 {
            tunnel_through_proxy(
                &mut stream,
                first_proxy,
                target,
                target_port,
                self.config.tcp_read_timeout,
            )?;
            return Ok(stream);
        }

        // Chain through remaining proxies
        for i in 1..proxies.len() {
            let next_proxy = &proxies[i];
            let next_target = TargetAddress::from_ip(next_proxy.ip);

            info!(
                "Chaining to proxy {}:{}",
                next_proxy.ip, next_proxy.port
            );

            if let Err(e) = tunnel_through_proxy(
                &mut stream,
                &proxies[i - 1],
                &next_target,
                next_proxy.port,
                self.config.tcp_read_timeout,
            ) {
                error!("Failed to chain to proxy {}: {}", i, e);
                mark_down(&mut proxies[i]);
                return Err(Error::ChainDown);
            }
        }

        // Final hop to target
        let last_proxy = &proxies[proxies.len() - 1];
        info!(
            "Connecting to target {}:{} through chain",
            target.host(),
            target_port
        );

        if let Err(e) = tunnel_through_proxy(
            &mut stream,
            last_proxy,
            target,
            target_port,
            self.config.tcp_read_timeout,
        ) {
            error!("Failed to connect to target: {}", e);
            if matches!(e, Error::Blocked) {
                mark_blocked(&mut proxies[proxies.len() - 1]);
            }
            return Err(e);
        }

        info!("Strict chain established successfully");
        Ok(stream)
    }

    /// Dynamic chain - skip dead proxies
    fn dynamic_chain(
        &self,
        proxies: &mut [ProxyData],
        target: &TargetAddress,
        target_port: u16,
    ) -> Result<std::net::TcpStream> {
        'again: loop {
            debug!("Starting dynamic chain connection (attempt)");

            // Calculate available proxies
            let alive_count = count_alive(proxies);
            if alive_count == 0 {
                error!("No alive proxies available");
                return Err(Error::ChainEmpty);
            }

            // Select first alive proxy
            let mut offset = 0;
            let first_idx = match self.find_alive_proxy(proxies, &mut offset) {
                Some(idx) => idx,
                None => {
                    error!("No alive proxy found");
                    return Err(Error::ChainEmpty);
                }
            };

            // Connect to first proxy
            let mut stream = match connect_to_proxy(&proxies[first_idx], self.config.tcp_connect_timeout) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to connect to proxy {}: {}", first_idx, e);
                    mark_down(&mut proxies[first_idx]);
                    continue 'again;
                }
            };

            stream.set_read_timeout(Some(self.config.tcp_read_timeout))?;
            stream.set_write_timeout(Some(self.config.tcp_read_timeout))?;

            let mut current_idx = first_idx;

            // Chain through remaining proxies
            while let Some(next_idx) = self.find_alive_proxy(proxies, &mut offset) {
                let next_proxy = &proxies[next_idx];
                let next_target = TargetAddress::from_ip(next_proxy.ip);

                debug!(
                    "Dynamic chain: connecting to proxy {}:{}",
                    next_proxy.ip, next_proxy.port
                );

                if let Err(e) = tunnel_through_proxy(
                    &mut stream,
                    &proxies[current_idx],
                    &next_target,
                    next_proxy.port,
                    self.config.tcp_read_timeout,
                ) {
                    warn!("Failed to chain to proxy {}: {}", next_idx, e);
                    mark_down(&mut proxies[next_idx]);
                    continue 'again;
                }

                current_idx = next_idx;
            }

            // Connect to target
            debug!(
                "Dynamic chain: connecting to target {}:{}",
                target.host(),
                target_port
            );

            if let Err(e) = tunnel_through_proxy(
                &mut stream,
                &proxies[current_idx],
                target,
                target_port,
                self.config.tcp_read_timeout,
            ) {
                warn!("Failed to connect to target: {}", e);
                if matches!(e, Error::Blocked) {
                    mark_blocked(&mut proxies[current_idx]);
                }
                continue 'again;
            }

            info!("Dynamic chain established successfully");
            return Ok(stream);
        }
    }

    /// Random chain - randomly select proxies
    fn random_chain(
        &self,
        proxies: &mut [ProxyData],
        target: &TargetAddress,
        target_port: u16,
    ) -> Result<std::net::TcpStream> {
        let max_chain = self.config.chain_len.unwrap_or(proxies.len());
        let alive_count = count_alive(proxies);

        if alive_count == 0 {
            return Err(Error::ChainEmpty);
        }

        if alive_count < max_chain {
            warn!(
                "Not enough alive proxies ({} < {})",
                alive_count, max_chain
            );
            return Err(Error::ChainDown);
        }

        'again: loop {
            // Randomly select proxies
            let selected_indices = self.select_random_proxies(proxies, max_chain);
            if selected_indices.is_empty() {
                return Err(Error::ChainEmpty);
            }

            // Connect to first selected proxy
            let first_idx = selected_indices[0];
            let mut stream = match connect_to_proxy(&proxies[first_idx], self.config.tcp_connect_timeout) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to connect to random proxy {}: {}", first_idx, e);
                    mark_down(&mut proxies[first_idx]);
                    continue 'again;
                }
            };

            stream.set_read_timeout(Some(self.config.tcp_read_timeout))?;
            stream.set_write_timeout(Some(self.config.tcp_read_timeout))?;

            let mut current_idx = first_idx;

            // Chain through remaining selected proxies
            for &next_idx in &selected_indices[1..] {
                let next_proxy = &proxies[next_idx];
                let next_target = TargetAddress::from_ip(next_proxy.ip);

                if let Err(e) = tunnel_through_proxy(
                    &mut stream,
                    &proxies[current_idx],
                    &next_target,
                    next_proxy.port,
                    self.config.tcp_read_timeout,
                ) {
                    warn!("Failed in random chain at proxy {}: {}", next_idx, e);
                    mark_down(&mut proxies[next_idx]);
                    continue 'again;
                }

                current_idx = next_idx;
            }

            // Connect to target
            if let Err(e) = tunnel_through_proxy(
                &mut stream,
                &proxies[current_idx],
                target,
                target_port,
                self.config.tcp_read_timeout,
            ) {
                warn!("Failed to connect to target in random chain: {}", e);
                continue 'again;
            }

            info!("Random chain established successfully");
            return Ok(stream);
        }
    }

    /// Load balance chain - round robin selection
    fn load_balance_chain(
        &self,
        proxies: &mut [ProxyData],
        target: &TargetAddress,
        target_port: u16,
    ) -> Result<std::net::TcpStream> {
        // For load balancing, just use one proxy at a time
        let alive_count = count_alive(proxies);
        if alive_count == 0 {
            return Err(Error::ChainEmpty);
        }

        // Select a proxy using round robin
        let mut offset = 0;
        let selected_idx = match self.selector.select_index(proxies, &mut offset) {
            Some(idx) => idx,
            None => return Err(Error::ChainEmpty),
        };

        let proxy = &proxies[selected_idx];
        debug!(
            "Load balance: selected proxy {}:{}",
            proxy.ip, proxy.port
        );

        // Connect to proxy
        let mut stream = connect_to_proxy(proxy, self.config.tcp_connect_timeout)?;
        stream.set_read_timeout(Some(self.config.tcp_read_timeout))?;
        stream.set_write_timeout(Some(self.config.tcp_read_timeout))?;

        // Connect to target
        tunnel_through_proxy(
            &mut stream,
            proxy,
            target,
            target_port,
            self.config.tcp_read_timeout,
        )?;

        info!("Load balance connection established");
        Ok(stream)
    }

    /// Failover chain - try proxies in order until one works
    fn failover_chain(
        &self,
        proxies: &mut [ProxyData],
        target: &TargetAddress,
        target_port: u16,
    ) -> Result<std::net::TcpStream> {
        for i in 0..proxies.len() {
            if proxies[i].state != ProxyState::Play {
                continue;
            }

            debug!("Failover: trying proxy {}", i);

            match connect_to_proxy(&proxies[i], self.config.tcp_connect_timeout) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(self.config.tcp_read_timeout))?;
                    stream.set_write_timeout(Some(self.config.tcp_read_timeout))?;

                    match tunnel_through_proxy(
                        &mut stream,
                        &proxies[i],
                        target,
                        target_port,
                        self.config.tcp_read_timeout,
                    ) {
                        Ok(()) => {
                            info!("Failover: connected through proxy {}", i);
                            return Ok(stream);
                        }
                        Err(e) => {
                            warn!("Failover: proxy {} failed: {}", i, e);
                            mark_down(&mut proxies[i]);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failover: failed to connect to proxy {}: {}", i, e);
                    mark_down(&mut proxies[i]);
                }
            }
        }

        error!("Failover: all proxies exhausted");
        Err(Error::ChainDown)
    }

    /// Find the next alive proxy
    fn find_alive_proxy(&self, proxies: &[ProxyData], offset: &mut usize) -> Option<usize> {
        while *offset < proxies.len() {
            let idx = *offset;
            *offset += 1;
            if proxies[idx].state == ProxyState::Play {
                return Some(idx);
            }
        }
        None
    }

    /// Select random proxies
    fn select_random_proxies(&self, proxies: &[ProxyData], count: usize) -> Vec<usize> {
        use rand::seq::SliceRandom;

        let available: Vec<usize> = proxies
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == ProxyState::Play)
            .map(|(i, _)| i)
            .collect();

        let mut rng = rand::thread_rng();
        let mut selected: Vec<usize> = available;
        selected.shuffle(&mut rng);
        selected.truncate(count);
        selected
    }

    /// Reset all proxy states
    pub fn reset_states(&self) {
        let mut states = self.proxy_states.lock();
        for proxy in states.iter_mut() {
            proxy.state = ProxyState::Play;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> Config {
        let mut config = Config::default();
        config.proxies = vec![
            ProxyData::new(Ipv4Addr::new(192, 168, 1, 1), 1080, crate::config::ProxyType::Socks5),
        ];
        config
    }

    #[test]
    fn test_chain_manager_creation() {
        let config = create_test_config();
        let manager = ChainManager::new(config);
        assert!(manager.config.has_proxies());
    }

    #[test]
    fn test_chain_error_conversion() {
        let err: Error = ChainError::ChainEmpty.into();
        assert!(matches!(err, Error::ChainEmpty));
    }
}
