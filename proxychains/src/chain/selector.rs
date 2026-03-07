//! Proxy chain selector strategies

use std::sync::atomic::{AtomicUsize, Ordering};

use rand::seq::SliceRandom;
use rand::Rng;

use crate::config::{ChainType, ProxyData, ProxyState};

/// Selection strategy for proxies
#[derive(Debug, Clone, Copy)]
pub enum SelectStrategy {
    /// First available (FIFO)
    Fifo,
    /// Random selection
    Random,
    /// Round robin
    RoundRobin,
    /// Least connections
    LeastConnections,
}

/// Proxy selector
pub struct ProxySelector {
    strategy: SelectStrategy,
    round_robin_counter: AtomicUsize,
}

impl ProxySelector {
    /// Create a new proxy selector
    pub fn new(strategy: SelectStrategy) -> Self {
        Self {
            strategy,
            round_robin_counter: AtomicUsize::new(0),
        }
    }

    /// Create selector from chain type
    pub fn from_chain_type(chain_type: ChainType) -> Self {
        let strategy = match chain_type {
            ChainType::Strict | ChainType::Dynamic => SelectStrategy::Fifo,
            ChainType::Random => SelectStrategy::Random,
            ChainType::LoadBalance => SelectStrategy::RoundRobin,
            ChainType::Failover => SelectStrategy::Fifo,
        };
        Self::new(strategy)
    }

    /// Select a proxy from the list by index
    pub fn select_index(&self, proxies: &[ProxyData], offset: &mut usize) -> Option<usize> {
        match self.strategy {
            SelectStrategy::Fifo => self.select_fifo_index(proxies, offset),
            SelectStrategy::Random => self.select_random_index(proxies),
            SelectStrategy::RoundRobin => self.select_round_robin_index(proxies),
            SelectStrategy::LeastConnections => self.select_fifo_index(proxies, offset),
        }
    }

    /// FIFO selection - returns index
    fn select_fifo_index(&self, proxies: &[ProxyData], offset: &mut usize) -> Option<usize> {
        while *offset < proxies.len() {
            let idx = *offset;
            *offset += 1;
            if proxies[idx].state == ProxyState::Play {
                return Some(idx);
            }
        }
        None
    }

    /// Random selection - returns index
    fn select_random_index(&self, proxies: &[ProxyData]) -> Option<usize> {
        // Get indices of available proxies
        let available: Vec<usize> = proxies
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == ProxyState::Play)
            .map(|(i, _)| i)
            .collect();

        if available.is_empty() {
            return None;
        }

        // Use thread RNG
        let mut rng = rand::thread_rng();
        available.choose(&mut rng).copied()
    }

    /// Round robin selection - returns index
    fn select_round_robin_index(&self, proxies: &[ProxyData]) -> Option<usize> {
        let len = proxies.len();
        if len == 0 {
            return None;
        }

        // Try to find an available proxy starting from current counter
        let start = self.round_robin_counter.load(Ordering::Relaxed) % len;
        for i in 0..len {
            let idx = (start + i) % len;
            if proxies[idx].state == ProxyState::Play {
                self.round_robin_counter.fetch_add(1, Ordering::Relaxed);
                return Some(idx);
            }
        }

        None
    }
}

impl Default for ProxySelector {
    fn default() -> Self {
        Self::new(SelectStrategy::Fifo)
    }
}

/// Calculate the number of alive (available) proxies
pub fn count_alive(proxies: &[ProxyData]) -> usize {
    proxies
        .iter()
        .filter(|p| p.state == ProxyState::Play)
        .count()
}

/// Reset all proxies to Play state
pub fn release_all(proxies: &mut [ProxyData]) {
    for proxy in proxies.iter_mut() {
        proxy.state = ProxyState::Play;
    }
}

/// Mark a proxy as down
pub fn mark_down(proxy: &mut ProxyData) {
    proxy.state = ProxyState::Down;
}

/// Mark a proxy as blocked
pub fn mark_blocked(proxy: &mut ProxyData) {
    proxy.state = ProxyState::Blocked;
}

/// Mark a proxy as busy
pub fn mark_busy(proxy: &mut ProxyData) {
    proxy.state = ProxyState::Busy;
}

/// Get a random integer
pub fn get_random_int(range: usize) -> usize {
    if range == 0 {
        return 0;
    }

    let mut rng = rand::thread_rng();
    rng.gen_range(0..range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_proxies() -> Vec<ProxyData> {
        vec![
            ProxyData::new(Ipv4Addr::new(192, 168, 1, 1), 1080, crate::config::ProxyType::Socks5),
            ProxyData::new(Ipv4Addr::new(192, 168, 1, 2), 1080, crate::config::ProxyType::Socks5),
            ProxyData::new(Ipv4Addr::new(192, 168, 1, 3), 1080, crate::config::ProxyType::Socks5),
        ]
    }

    #[test]
    fn test_fifo_selection() {
        let proxies = create_test_proxies();
        let selector = ProxySelector::new(SelectStrategy::Fifo);
        let mut offset = 0;

        let first = selector.select_index(&proxies, &mut offset);
        assert_eq!(first, Some(0));

        let second = selector.select_index(&proxies, &mut offset);
        assert_eq!(second, Some(1));
    }

    #[test]
    fn test_count_alive() {
        let mut proxies = create_test_proxies();
        assert_eq!(count_alive(&proxies), 3);

        proxies[0].state = ProxyState::Down;
        assert_eq!(count_alive(&proxies), 2);

        proxies[1].state = ProxyState::Blocked;
        assert_eq!(count_alive(&proxies), 1);
    }

    #[test]
    fn test_release_all() {
        let mut proxies = create_test_proxies();
        proxies[0].state = ProxyState::Down;
        proxies[1].state = ProxyState::Blocked;

        release_all(&mut proxies);

        for proxy in &proxies {
            assert_eq!(proxy.state, ProxyState::Play);
        }
    }
}
