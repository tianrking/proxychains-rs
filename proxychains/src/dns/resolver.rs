//! DNS resolver for proxychains

use std::ffi::CString;
use std::net::Ipv4Addr;

use crate::dns::cache::{in_etc_hosts, DnsCache};
use crate::error::{Error, Result};

/// Global DNS cache instance
static DNS_CACHE: once_cell::sync::Lazy<DnsCache> =
    once_cell::sync::Lazy::new(|| DnsCache::default_subnet());

/// DNS resolver
pub struct DnsResolver {
    cache: &'static DnsCache,
    proxy_dns: bool,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub fn new(proxy_dns: bool, _subnet: u8) -> Self {
        Self {
            cache: &DNS_CACHE,
            proxy_dns,
        }
    }

    /// Create with default settings
    pub fn default_resolver() -> Self {
        Self::new(true, 224)
    }

    /// Resolve a hostname
    ///
    /// If proxy_dns is enabled and hostname is not in /etc/hosts,
    /// returns a fake IP that will be resolved through the proxy.
    /// Otherwise, uses the system resolver.
    pub fn resolve(&self, hostname: &str) -> Result<Ipv4Addr> {
        // First check /etc/hosts
        if let Some(ip) = in_etc_hosts(hostname) {
            return Ok(ip);
        }

        // If proxy DNS is enabled, return fake IP
        if self.proxy_dns {
            let fake_ip = self.cache.get_or_create(hostname);
            return Ok(fake_ip);
        }

        // Use system resolver
        self.system_resolve(hostname)
    }

    /// Get hostname from fake IP
    pub fn get_hostname(&self, ip: &Ipv4Addr) -> Option<String> {
        if self.cache.is_fake_ip(ip) {
            self.cache.get_hostname(ip)
        } else {
            None
        }
    }

    /// Check if IP is a fake IP (needs remote resolution)
    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        self.cache.is_fake_ip(ip)
    }

    /// System resolver using getaddrinfo
    fn system_resolve(&self, hostname: &str) -> Result<Ipv4Addr> {
        let c_hostname = CString::new(hostname)?;

        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_INET; // IPv4 only
        hints.ai_socktype = libc::SOCK_STREAM;

        let mut result: *mut libc::addrinfo = std::ptr::null_mut();

        let ret = unsafe {
            libc::getaddrinfo(c_hostname.as_ptr(), std::ptr::null(), &hints, &mut result)
        };

        if ret != 0 {
            return Err(Error::Dns(format!(
                "Failed to resolve {}: {}",
                hostname, ret
            )));
        }

        if result.is_null() {
            return Err(Error::Dns(format!("No addresses for {}", hostname)));
        }

        // Get the first IPv4 address
        let addr = unsafe {
            let ai = *result;
            if ai.ai_family == libc::AF_INET {
                let addr_in = ai.ai_addr as *const libc::sockaddr_in;
                let ip_bytes = (*addr_in).sin_addr.s_addr.to_ne_bytes();
                Ipv4Addr::from(ip_bytes)
            } else {
                libc::freeaddrinfo(result);
                return Err(Error::Dns(format!("No IPv4 address for {}", hostname)));
            }
        };

        unsafe {
            libc::freeaddrinfo(result);
        }

        Ok(addr)
    }

    /// Get reference to global DNS cache
    pub fn cache(&self) -> &'static DnsCache {
        self.cache
    }
}

/// Check if an IP is a fake IP
pub fn is_fake_ip(ip: &Ipv4Addr) -> bool {
    DNS_CACHE.is_fake_ip(ip)
}

/// Get hostname from fake IP
pub fn get_hostname_from_ip(ip: &Ipv4Addr) -> Option<String> {
    if DNS_CACHE.is_fake_ip(ip) {
        DNS_CACHE.get_hostname(ip)
    } else {
        None
    }
}

/// Resolve hostname to fake IP (for proxy DNS)
pub fn resolve_to_fake_ip(hostname: &str, _subnet: u8) -> Ipv4Addr {
    DNS_CACHE.get_or_create(hostname)
}

/// Parse hosts file and lookup hostname
pub fn lookup_in_hosts(hostname: &str) -> Option<Ipv4Addr> {
    in_etc_hosts(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_resolver() {
        let resolver = DnsResolver::new(true, 224);

        // Test fake IP generation
        let ip = resolver.resolve("example.invalid").unwrap();
        assert!(resolver.is_fake_ip(&ip));

        // Same hostname should return same IP
        let ip2 = resolver.resolve("example.invalid").unwrap();
        assert_eq!(ip, ip2);

        // Should be able to get hostname back
        let hostname = resolver.get_hostname(&ip).unwrap();
        assert_eq!(hostname, "example.invalid");
    }

    #[test]
    fn test_is_fake_ip() {
        let resolver = DnsResolver::new(true, 224);

        let ip = resolver.resolve("test.invalid").unwrap();
        assert!(is_fake_ip(&ip));

        let real_ip = Ipv4Addr::new(8, 8, 8, 8);
        assert!(!is_fake_ip(&real_ip));
    }
}
