//! Proxy protocol implementations
//!
//! This module provides implementations for various proxy protocols:
//! - SOCKS5 (RFC 1928)
//! - SOCKS4/4a
//! - HTTP CONNECT
//! - Raw (direct connection)

mod http;
mod raw;
mod socks4;
mod socks5;

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::{ProxyData, ProxyType};
use crate::error::{Error, Result};
use crate::net::connect_with_timeout;

pub use http::*;
pub use raw::*;
pub use socks4::*;
pub use socks5::*;

/// Target address for proxy connection
#[derive(Debug, Clone)]
pub enum TargetAddress {
    /// IP address only
    Ip(Ipv4Addr),
    /// Domain name only
    Domain(String),
    /// Both IP and domain (for SOCKS4a/5)
    Both { ip: Ipv4Addr, domain: String },
}

impl TargetAddress {
    /// Create from IP address
    pub fn from_ip(ip: Ipv4Addr) -> Self {
        TargetAddress::Ip(ip)
    }

    /// Create from domain name
    pub fn from_domain(domain: impl Into<String>) -> Self {
        TargetAddress::Domain(domain.into())
    }

    /// Create with both IP and domain
    pub fn from_both(ip: Ipv4Addr, domain: impl Into<String>) -> Self {
        TargetAddress::Both {
            ip,
            domain: domain.into(),
        }
    }

    /// Get the IP address if available
    pub fn ip(&self) -> Option<&Ipv4Addr> {
        match self {
            TargetAddress::Ip(ip) => Some(ip),
            TargetAddress::Domain(_) => None,
            TargetAddress::Both { ip, .. } => Some(ip),
        }
    }

    /// Get the domain name if available
    pub fn domain(&self) -> Option<&str> {
        match self {
            TargetAddress::Ip(_) => None,
            TargetAddress::Domain(d) => Some(d),
            TargetAddress::Both { domain, .. } => Some(domain),
        }
    }

    /// Get host string (domain or IP string)
    pub fn host(&self) -> String {
        match self {
            TargetAddress::Ip(ip) => ip.to_string(),
            TargetAddress::Domain(d) => d.clone(),
            TargetAddress::Both { domain, .. } => domain.clone(),
        }
    }
}

/// Connect to a proxy server
pub fn connect_to_proxy(proxy: &ProxyData, timeout: Duration) -> Result<std::net::TcpStream> {
    let addr = proxy.socket_addr();
    connect_with_timeout(&addr, timeout)
}

/// Tunnel through a proxy to a target
pub fn tunnel_through_proxy<T: Read + Write>(
    stream: &mut T,
    proxy: &ProxyData,
    target: &TargetAddress,
    target_port: u16,
    timeout: Duration,
) -> Result<()> {
    match proxy.proxy_type {
        ProxyType::Socks5 => {
            // For SOCKS5, prefer domain if available
            let target_addr = if let Some(domain) = target.domain() {
                TargetAddr::from_domain(domain)
            } else if let Some(ip) = target.ip() {
                TargetAddr::from_ip(*ip)
            } else {
                return Err(Error::InvalidAddress);
            };
            socks5_connect(stream, proxy, &target_addr, target_port, timeout)
        }
        ProxyType::Socks4 => {
            // SOCKS4 requires IP, SOCKS4a can use domain
            let ip = target.ip().copied().unwrap_or(Ipv4Addr::new(0, 0, 0, 1));
            if let Some(domain) = target.domain() {
                socks4a_connect(stream, proxy, &ip, domain, target_port, timeout)
            } else {
                socks4_connect(stream, proxy, &ip, target_port, timeout)
            }
        }
        ProxyType::Http => {
            // HTTP CONNECT can use either
            http_connect(stream, proxy, &target.host(), target_port, timeout)
        }
        ProxyType::Raw => {
            // Raw does nothing
            raw_connect(stream, proxy, timeout)
        }
    }
}

/// Establish a full proxy chain connection
pub fn establish_proxy_chain(
    proxies: &[ProxyData],
    target: &TargetAddress,
    target_port: u16,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<std::net::TcpStream> {
    if proxies.is_empty() {
        return Err(Error::ChainEmpty);
    }

    // Connect to first proxy
    let first_proxy = &proxies[0];
    let mut stream = connect_to_proxy(first_proxy, connect_timeout)?;

    // Set read timeout
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(read_timeout))?;

    // If only one proxy, tunnel directly to target
    if proxies.len() == 1 {
        tunnel_through_proxy(&mut stream, first_proxy, target, target_port, read_timeout)?;
        return Ok(stream);
    }

    // Chain through multiple proxies
    for i in 1..proxies.len() {
        // Tunnel to next proxy (or final target)
        if i == proxies.len() - 1 {
            // Last hop - connect to target
            tunnel_through_proxy(
                &mut stream,
                &proxies[i - 1],
                target,
                target_port,
                read_timeout,
            )?;
        } else {
            // Intermediate hop - connect to next proxy
            let next_proxy = &proxies[i];
            let next_target = TargetAddress::from_ip(next_proxy.ip);
            tunnel_through_proxy(
                &mut stream,
                &proxies[i - 1],
                &next_target,
                next_proxy.port,
                read_timeout,
            )?;
        }
    }

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_address() {
        let ip = TargetAddress::from_ip(Ipv4Addr::new(192, 168, 1, 1));
        assert!(ip.ip().is_some());
        assert!(ip.domain().is_none());

        let domain = TargetAddress::from_domain("example.com");
        assert!(domain.ip().is_none());
        assert!(domain.domain().is_some());

        let both = TargetAddress::from_both(Ipv4Addr::new(192, 168, 1, 1), "example.com");
        assert!(both.ip().is_some());
        assert!(both.domain().is_some());
    }
}
