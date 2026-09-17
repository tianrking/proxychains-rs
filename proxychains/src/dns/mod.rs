//! DNS handling module
//!
//! This module provides DNS resolution capabilities including:
//! - Fake IP mapping for remote DNS resolution
//! - hosts file lookup
//! - System DNS resolution

mod cache;
mod hosts;
mod resolver;

// Re-export specific items to avoid ambiguity
pub use cache::{DnsCache, DnsEntry};
pub use hosts::{lookup_in_hosts, parse_hosts_file};
pub use resolver::{get_hostname_from_ip, is_fake_ip, resolve_to_fake_ip, DnsResolver};
