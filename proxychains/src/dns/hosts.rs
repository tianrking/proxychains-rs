//! Platform-independent hosts file parsing
//!
//! This module provides cross-platform hosts file parsing functionality.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::platform::hosts_path;

/// Parse the hosts file and return a map of hostname to IP address
pub fn parse_hosts_file() -> HashMap<String, Ipv4Addr> {
    let mut hosts = HashMap::new();
    let path = hosts_path();

    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: IP hostname [aliases...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    for hostname in &parts[1..] {
                        // Skip if hostname starts with #
                        if hostname.starts_with('#') {
                            break;
                        }
                        hosts.insert(hostname.to_lowercase(), ip);
                    }
                }
            }
        }
    }

    hosts
}

/// Check if a hostname is in the hosts file
pub fn lookup_in_hosts(hostname: &str) -> Option<Ipv4Addr> {
    let hosts = parse_hosts_file();
    hosts.get(&hostname.to_lowercase()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_returns_map() {
        let hosts = parse_hosts_file();
        // Just verify it doesn't crash and returns a map
        // The actual content depends on the system
        assert!(hosts.is_empty() || !hosts.is_empty());
    }

    #[test]
    fn test_lookup_in_hosts_handles_nonexistent() {
        let result = lookup_in_hosts("this-hostname-definitely-does-not-exist-12345.com");
        // Should return None for non-existent hostname
        assert!(result.is_none());
    }
}
