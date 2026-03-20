//! DNS cache for storing hostname to fake IP mappings

use std::collections::HashMap;
use std::net::Ipv4Addr;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};

/// DNS cache entry
#[derive(Debug, Clone)]
pub struct DnsEntry {
    /// The hostname
    pub hostname: String,
    /// The fake IP assigned
    pub fake_ip: Ipv4Addr,
    /// Hash for lookup
    pub hash: u32,
}

/// DNS cache for internal IP mapping
pub struct DnsCache {
    /// Map from fake IP to hostname
    ip_to_host: RwLock<HashMap<Ipv4Addr, DnsEntry>>,
    /// Map from hostname to fake IP
    host_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    /// Counter for generating fake IPs
    counter: RwLock<u32>,
    /// Remote DNS subnet (default: 224)
    subnet: u8,
    /// Maximum entries
    max_entries: usize,
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new(subnet: u8) -> Self {
        Self {
            ip_to_host: RwLock::new(HashMap::new()),
            host_to_ip: RwLock::new(HashMap::new()),
            counter: RwLock::new(0),
            subnet,
            max_entries: 65535,
        }
    }

    /// Create with default subnet (224)
    pub fn default_subnet() -> Self {
        Self::new(224)
    }

    /// Get or create a fake IP for a hostname
    pub fn get_or_create(&self, hostname: &str) -> Ipv4Addr {
        // Check if already cached
        {
            let host_to_ip = self.host_to_ip.read();
            if let Some(&ip) = host_to_ip.get(hostname) {
                return ip;
            }
        }

        // Create new entry
        let mut counter = self.counter.write();
        *counter += 1;

        // Check for overflow
        if *counter >= self.max_entries as u32 {
            // Reset counter and clear cache
            *counter = 1;
            self.ip_to_host.write().clear();
            self.host_to_ip.write().clear();
        }

        let fake_ip = self.make_internal_ip(*counter);

        // Store in cache
        let entry = DnsEntry {
            hostname: hostname.to_string(),
            fake_ip,
            hash: self.hash_hostname(hostname),
        };

        self.ip_to_host.write().insert(fake_ip, entry);
        self.host_to_ip.write().insert(hostname.to_string(), fake_ip);

        fake_ip
    }

    /// Get hostname from fake IP
    pub fn get_hostname(&self, ip: &Ipv4Addr) -> Option<String> {
        let ip_to_host = self.ip_to_host.read();
        ip_to_host.get(ip).map(|e| e.hostname.clone())
    }

    /// Check if an IP is a fake IP
    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == self.subnet
    }

    /// Get the subnet being used
    pub fn subnet(&self) -> u8 {
        self.subnet
    }

    /// Generate an internal/fake IP address
    fn make_internal_ip(&self, index: u32) -> Ipv4Addr {
        // Format: subnet.(index>>16).(index>>8).(index)
        let index = index + 1; // Start at .0.0.1
        Ipv4Addr::new(
            self.subnet,
            ((index >> 16) & 0xFF) as u8,
            ((index >> 8) & 0xFF) as u8,
            (index & 0xFF) as u8,
        )
    }

    /// Hash a hostname for quick lookup
    fn hash_hostname(&self, hostname: &str) -> u32 {
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        let result = hasher.finalize();
        u32::from_le_bytes([result[0], result[1], result[2], result[3]])
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.ip_to_host.write().clear();
        self.host_to_ip.write().clear();
        *self.counter.write() = 0;
    }

    /// Get cache size
    pub fn size(&self) -> usize {
        self.ip_to_host.read().len()
    }

    /// Check if hostname is cached
    pub fn contains(&self, hostname: &str) -> bool {
        self.host_to_ip.read().contains_key(hostname)
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::default_subnet()
    }
}

/// Parse hosts file (platform-independent)
/// Deprecated: Use crate::dns::hosts::parse_hosts_file instead
#[deprecated(note = "Use crate::dns::parse_hosts_file instead")]
pub fn parse_etc_hosts() -> HashMap<String, Ipv4Addr> {
    crate::dns::parse_hosts_file()
}

/// Check if hostname is in hosts file (platform-independent)
/// Deprecated: Use crate::dns::hosts::lookup_in_hosts instead
#[deprecated(note = "Use crate::dns::lookup_in_hosts instead")]
pub fn in_etc_hosts(hostname: &str) -> Option<Ipv4Addr> {
    crate::dns::lookup_in_hosts(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache() {
        let cache = DnsCache::default();

        let ip1 = cache.get_or_create("example.com");
        assert!(cache.is_fake_ip(&ip1));
        assert!(cache.contains("example.com"));

        let hostname = cache.get_hostname(&ip1);
        assert_eq!(hostname, Some("example.com".to_string()));

        // Same hostname should return same IP
        let ip2 = cache.get_or_create("example.com");
        assert_eq!(ip1, ip2);

        // Different hostname should return different IP
        let ip3 = cache.get_or_create("test.com");
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_fake_ip_format() {
        let cache = DnsCache::new(224);

        // First IP should be 224.0.0.1
        let ip1 = cache.get_or_create("test1.com");
        assert_eq!(ip1.octets()[0], 224);

        // Check it's recognized as fake
        assert!(cache.is_fake_ip(&ip1));
    }

    #[test]
    fn test_clear_cache() {
        let cache = DnsCache::default();

        cache.get_or_create("example.com");
        assert!(cache.size() > 0);

        cache.clear();
        assert_eq!(cache.size(), 0);
    }
}
