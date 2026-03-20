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
pub use hosts::{parse_hosts_file, lookup_in_hosts};
pub use resolver::{DnsResolver, is_fake_ip, get_hostname_from_ip, resolve_to_fake_ip};
