//! Configuration types for proxychains

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::time::Duration;
use crate::error::{Error, Result};

/// Proxy protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    #[default]
    Socks5,
    Socks4,
    Http,
    Raw,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Socks4 => write!(f, "socks4"),
            ProxyType::Http => write!(f, "http"),
            ProxyType::Raw => write!(f, "raw"),
        }
    }
}

impl std::str::FromStr for ProxyType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "socks5" | "socks5h" => Ok(ProxyType::Socks5),
            "socks4" | "socks4a" => Ok(ProxyType::Socks4),
            "http" | "connect" => Ok(ProxyType::Http),
            "raw" => Ok(ProxyType::Raw),
            _ => Err(format!("Unknown proxy type: {}", s)),
        }
    }
}

/// Proxy state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyState {
    #[default]
    Play,
    Down,
    Blocked,
    Busy,
}

/// Chain type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainType {
    #[default]
    Dynamic,
    Strict,
    Random,
    LoadBalance,
    Failover,
}

impl std::fmt::Display for ChainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainType::Dynamic => write!(f, "dynamic"),
            ChainType::Strict => write!(f, "strict"),
            ChainType::Random => write!(f, "random"),
            ChainType::LoadBalance => write!(f, "load_balance"),
            ChainType::Failover => write!(f, "failover"),
        }
    }
}

/// Proxy data structure
#[derive(Debug, Clone)]
pub struct ProxyData {
    /// Proxy hostname (domain or IPv4 literal)
    pub host: String,
    /// Proxy IP address
    pub ip: Ipv4Addr,
    /// Proxy port
    pub port: u16,
    /// Proxy type
    pub proxy_type: ProxyType,
    /// Proxy state
    pub state: ProxyState,
    /// Username for authentication
    pub user: Option<String>,
    /// Password for authentication
    pub pass: Option<String>,
}

impl Default for ProxyData {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 1080,
            proxy_type: ProxyType::default(),
            state: ProxyState::default(),
            user: None,
            pass: None,
        }
    }
}

impl ProxyData {
    /// Create a new proxy data
    pub fn new(ip: Ipv4Addr, port: u16, proxy_type: ProxyType) -> Self {
        Self {
            host: ip.to_string(),
            ip,
            port,
            proxy_type,
            ..Default::default()
        }
    }

    /// Create a proxy from host string (domain or IPv4 literal).
    pub fn new_host(host: impl Into<String>, port: u16, proxy_type: ProxyType) -> Self {
        let host = host.into();
        let ip = host
            .parse::<Ipv4Addr>()
            .unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
        Self {
            host,
            ip,
            port,
            proxy_type,
            ..Default::default()
        }
    }

    /// Set authentication credentials
    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.user = Some(user);
        self.pass = Some(pass);
        self
    }

    /// Get socket address
    pub fn socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }

    /// Resolve configured host to IPv4 address.
    pub fn resolve_ipv4(&self) -> Result<Ipv4Addr> {
        if self.host.eq_ignore_ascii_case("localhost") {
            return Ok(Ipv4Addr::new(127, 0, 0, 1));
        }
        if let Ok(ip) = self.host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }

        let mut addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| Error::Dns(format!("Failed to resolve proxy host {}: {}", self.host, e)))?;

        addrs
            .find_map(|addr| match addr.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| Error::Dns(format!("No IPv4 address for proxy host {}", self.host)))
    }

    /// Resolve proxy host and build socket address.
    pub fn resolved_socket_addr(&self) -> Result<SocketAddrV4> {
        Ok(SocketAddrV4::new(self.resolve_ipv4()?, self.port))
    }
}

/// Local network for bypass
#[derive(Debug, Clone)]
pub struct LocalNet {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl LocalNet {
    pub fn new(address: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Self { address, netmask }
    }

    /// Check if an IP is in this local network
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let addr_bits = u32::from(self.address);
        let mask_bits = u32::from(self.netmask);
        let ip_bits = u32::from(*ip);
        (addr_bits & mask_bits) == (ip_bits & mask_bits)
    }
}

/// DNAT rule
#[derive(Debug, Clone)]
pub struct DnatRule {
    pub original: Ipv4Addr,
    pub original_port: u16,
    pub new: Ipv4Addr,
    pub new_port: u16,
}

impl DnatRule {
    pub fn new(original: Ipv4Addr, original_port: u16, new: Ipv4Addr, new_port: u16) -> Self {
        Self {
            original,
            original_port,
            new,
            new_port,
        }
    }
}

/// Main configuration structure
#[derive(Debug, Clone)]
pub struct Config {
    /// Chain type
    pub chain_type: ChainType,
    /// Maximum chain length for random mode
    pub chain_len: Option<usize>,
    /// Quiet mode - suppress output
    pub quiet_mode: bool,
    /// Proxy DNS through the chain
    pub proxy_dns: bool,
    /// Remote DNS subnet for fake IPs
    pub remote_dns_subnet: u8,
    /// TCP read timeout
    pub tcp_read_timeout: Duration,
    /// TCP connect timeout
    pub tcp_connect_timeout: Duration,
    /// Maximum retry attempts when establishing a chain
    pub max_chain_retries: usize,
    /// Local networks to bypass
    pub localnets: Vec<LocalNet>,
    /// DNAT rules
    pub dnats: Vec<DnatRule>,
    /// Proxy list
    pub proxies: Vec<ProxyData>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_type: ChainType::default(),
            chain_len: None,
            quiet_mode: false,
            proxy_dns: false,
            remote_dns_subnet: 224,
            tcp_read_timeout: Duration::from_millis(15000),
            tcp_connect_timeout: Duration::from_millis(8000),
            max_chain_retries: 8,
            localnets: Vec::new(),
            dnats: Vec::new(),
            proxies: Vec::new(),
        }
    }
}

impl Config {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an IP should bypass the proxy
    pub fn should_bypass(&self, ip: &Ipv4Addr) -> bool {
        // Always bypass localhost
        if ip.is_loopback() {
            return true;
        }

        // Check localnets
        for localnet in &self.localnets {
            if localnet.contains(ip) {
                return true;
            }
        }

        false
    }

    /// Check if an IP should bypass the proxy (IPv4/IPv6).
    pub fn should_bypass_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.should_bypass(v4),
            // Mirror localhost/local semantics for IPv6 to avoid unintended proxying
            // of link-local/unspecified traffic.
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        }
    }

    /// Apply DNAT rule if applicable
    pub fn apply_dnat(&self, ip: &Ipv4Addr, port: u16) -> (Ipv4Addr, u16) {
        for dnat in &self.dnats {
            if &dnat.original == ip && dnat.original_port == port {
                return (dnat.new, dnat.new_port);
            }
        }
        (*ip, port)
    }

    /// Apply DNAT rule for IPv4/IPv6.
    pub fn apply_dnat_ip(&self, ip: &IpAddr, port: u16) -> (IpAddr, u16) {
        match ip {
            IpAddr::V4(v4) => {
                let (new_ip, new_port) = self.apply_dnat(v4, port);
                (IpAddr::V4(new_ip), new_port)
            }
            IpAddr::V6(v6) => (IpAddr::V6(*v6), port),
        }
    }

    /// Get number of proxies
    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    /// Check if configuration has any proxies
    pub fn has_proxies(&self) -> bool {
        !self.proxies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_ipv6_bypass_local_scopes() {
        let cfg = Config::default();
        assert!(cfg.should_bypass_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(cfg.should_bypass_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(cfg.should_bypass_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 1, 2, 3, 4
        ))));
        assert!(cfg.should_bypass_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 1, 2, 3, 4
        ))));
        assert!(!cfg.should_bypass_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
    }
}
