//! # proxychains
//!
//! A Rust implementation of the classic proxychains tool for proxy chaining.
//!
//! ## Features
//!
//! - Multiple proxy protocols: SOCKS4, SOCKS4a, SOCKS5, HTTP CONNECT
//! - Chain modes: Strict, Dynamic, Random, Load Balance, Failover
//! - DNS handling: Local resolution, Remote DNS through proxy, Fake IP mapping
//! - IPv6 support (planned)
//! - LD_PRELOAD hooks for transparent proxying
//!
//! ## Example
//!
//! ```rust,ignore
//! use proxychains::{Config, ConfigParser, ChainManager};
//!
//! // Parse configuration
//! let parser = ConfigParser::new();
//! let config = parser.parse()?;
//!
//! // Create chain manager
//! let manager = ChainManager::new(config);
//!
//! // Connect through proxy chain
//! let stream = manager.connect_proxy_chain(
//!     "93.184.216.34".parse()?,  // Target IP
//!     80,                         // Target port
//!     Some("example.com"),        // Optional domain
//! )?;
//! ```

pub mod chain;
pub mod config;
pub mod dns;
pub mod error;
pub mod hook;
pub mod net;
pub mod platform;
pub mod proxy;

// Re-exports for convenience
pub use chain::{ChainManager, ChainError};
pub use config::{Config, ConfigParser, ProxyData, ProxyType, ChainType};
pub use dns::{DnsResolver, DnsCache};
pub use error::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "proxychains-rs";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
