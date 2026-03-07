//! DNS handling module
//!
//! This module provides DNS resolution capabilities including:
//! - Fake IP mapping for remote DNS resolution
//! - /etc/hosts lookup
//! - System DNS resolution

mod cache;
mod resolver;

pub use cache::*;
pub use resolver::*;
