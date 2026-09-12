//! Network utilities module
//!
//! This module provides platform-specific network utilities for:
//! - Socket operations
//! - Timeout handling
//! - IP address utilities

thread_local! { static INTERNAL_NETWORK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
pub(crate) struct InternalNetwork;
impl InternalNetwork {
    pub(crate) fn enter() -> Self { INTERNAL_NETWORK.with(|n| n.set(n.get()+1)); Self }
}
impl Drop for InternalNetwork { fn drop(&mut self) { INTERNAL_NETWORK.with(|n| n.set(n.get()-1)); } }
pub(crate) fn is_internal_network() -> bool { INTERNAL_NETWORK.with(|n| n.get()!=0) }

#[cfg(unix)]
mod socket;

#[cfg(unix)]
mod timeout;

// Windows-specific modules
#[cfg(windows)]
mod socket_windows;
#[cfg(windows)]
mod timeout_windows;

// Re-export based on platform
#[cfg(unix)]
pub use socket::*;

#[cfg(unix)]
pub use timeout::*;

#[cfg(windows)]
pub use socket_windows::*;

#[cfg(windows)]
pub use timeout_windows::{
    read_bytes_timeout,
    write_bytes_timeout,
    connect_with_timeout,
    is_connected,
    set_socket_timeout,
};
