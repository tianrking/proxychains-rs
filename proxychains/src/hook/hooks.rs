//! Hook implementations for network functions
//!
//! This module provides the actual hook implementations that intercept
//! network calls and redirect them through the proxy chain.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::os::unix::io::IntoRawFd;
use std::sync::OnceLock;

use libc::{c_int, socklen_t};
use tracing::{debug, error, info, trace};

use crate::chain::ChainManager;
use crate::config::Config;
use crate::dns::is_fake_ip;
use crate::error::Result;
use crate::net::{get_ip_from_sockaddr, get_port_from_sockaddr};

use super::interpose::{
    init_original_functions, original_connect, original_freeaddrinfo, original_getaddrinfo,
    original_gethostbyname, original_getnameinfo,
};

/// Global state for the hook library
pub struct HookState {
    pub config: Config,
    pub chain_manager: ChainManager,
    pub dns_resolver: crate::dns::DnsResolver,
    pub initialized: bool,
}

impl HookState {
    pub fn new(config: Config) -> Self {
        let chain_manager = ChainManager::new(config.clone());
        let dns_resolver = crate::dns::DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);
        Self {
            config,
            chain_manager,
            dns_resolver,
            initialized: true,
        }
    }
}

/// Global hook state
static HOOK_STATE: OnceLock<HookState> = OnceLock::new();

/// Initialize the hook library
pub fn init_hooks(config: Config) -> Result<()> {
    // Initialize original functions first
    init_original_functions()?;

    // Create hook state
    let state = HookState::new(config);

    // Store globally
    if HOOK_STATE.set(state).is_err() {
        error!("Hook state already initialized");
    }

    info!("Proxychains hooks initialized");
    Ok(())
}

/// Check if hooks are initialized
pub fn is_initialized() -> bool {
    HOOK_STATE.get().map_or(false, |s| s.initialized)
}

/// Get the hook state
fn get_hook_state() -> Option<HookState> {
    HOOK_STATE.get().map(|s| HookState {
        config: s.config.clone(),
        chain_manager: ChainManager::new(s.config.clone()),
        dns_resolver: crate::dns::DnsResolver::new(s.config.proxy_dns, s.config.remote_dns_subnet),
        initialized: s.initialized,
    })
}

/// Hook for connect() system call
///
/// This intercepts TCP connections and redirects them through the proxy chain.
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_connect(
    sock: c_int,
    addr: *const libc::sockaddr,
    len: socklen_t,
) -> c_int {
    trace!("hook_connect called: sock={}", sock);

    // Check if initialized
    let state = match get_hook_state() {
        Some(s) => s,
        None => {
            return original_connect(sock, addr, len);
        }
    };

    // Get target address
    let target_ip = match get_ip_from_sockaddr(addr) {
        Some(ip) => ip,
        None => return original_connect(sock, addr, len),
    };

    let target_port = get_port_from_sockaddr(addr);

    // Check if we should bypass this connection
    if state.config.should_bypass(&target_ip) {
        debug!("Bypassing proxy for local address: {}:{}", target_ip, target_port);
        return original_connect(sock, addr, len);
    }

    // Apply DNAT if configured
    let (final_ip, final_port) = state.config.apply_dnat(&target_ip, target_port);

    // Check if this is a fake IP (needs remote DNS resolution)
    let target_domain = if is_fake_ip(&final_ip) {
        state.dns_resolver.get_hostname(&final_ip)
    } else {
        None
    };

    // Check if proxy DNS is enabled and we have a domain
    if state.config.proxy_dns && target_domain.is_some() {
        debug!(
            "Connecting to {}:{} ({}) through proxy chain",
            final_ip, final_port,
            target_domain.as_ref().unwrap()
        );
    } else {
        debug!(
            "Connecting to {}:{} through proxy chain",
            final_ip, final_port
        );
    }

    // Close the original socket (we'll create a new one through the proxy)
    libc::close(sock);

    // Connect through proxy chain
    match state.chain_manager.connect_proxy_chain(
        final_ip,
        final_port,
        target_domain.as_deref(),
    ) {
        Ok(proxy_stream) => {
            // Get the file descriptor from the proxy stream
            let proxy_fd = proxy_stream.into_raw_fd();

            // Use dup2 to make it the same fd as the original socket
            let result = libc::dup2(proxy_fd, sock);
            libc::close(proxy_fd);

            if result < 0 {
                error!("Failed to duplicate socket fd");
                return -1;
            }

            info!("Proxy connection established");
            0
        }
        Err(e) => {
            error!("Failed to establish proxy chain: {}", e);
            // Set errno using nix
            let _ = nix::errno::Errno::last_raw();
            unsafe {
                *libc::__error() = libc::ECONNREFUSED;
            }
            -1
        }
    }
}

/// Hook for getaddrinfo() system call
///
/// When proxy_dns is enabled, this returns fake IPs that will be
/// resolved through the proxy.
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    trace!("hook_getaddrinfo called");

    // Check if initialized and proxy_dns is enabled
    let state = match get_hook_state() {
        Some(s) if s.config.proxy_dns => s,
        _ => return original_getaddrinfo(node, service, hints, res),
    };

    // If no node specified, use original
    if node.is_null() {
        return original_getaddrinfo(node, service, hints, res);
    }

    // Get the hostname
    let hostname = match CStr::from_ptr(node).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return original_getaddrinfo(node, service, hints, res),
    };

    debug!("getaddrinfo hook for: {}", hostname);

    // Check /etc/hosts first
    if let Some(_ip) = crate::dns::lookup_in_hosts(&hostname) {
        debug!("Found {} in /etc/hosts", hostname);
        // Use original function for hosts entries
        return original_getaddrinfo(node, service, hints, res);
    }

    // Generate fake IP
    let _fake_ip = match state.dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_getaddrinfo: {}", hostname, e);
            return original_getaddrinfo(node, service, hints, res);
        }
    };

    debug!("Assigned fake IP {} for {}", _fake_ip, hostname);

    // For now, use original getaddrinfo
    // A full implementation would return fake IPs
    original_getaddrinfo(node, service, hints, res)
}

/// Hook for gethostbyname() system call
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_gethostbyname(name: *const c_char) -> *mut libc::hostent {
    trace!("hook_gethostbyname called");

    // Check if initialized and proxy_dns is enabled
    let state = match get_hook_state() {
        Some(s) if s.config.proxy_dns => s,
        _ => return original_gethostbyname(name),
    };

    if name.is_null() {
        return original_gethostbyname(name);
    }

    // Get the hostname
    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return original_gethostbyname(name),
    };

    debug!("gethostbyname hook for: {}", hostname);

    // Check /etc/hosts first
    if let Some(_ip) = crate::dns::lookup_in_hosts(&hostname) {
        debug!("Found {} in /etc/hosts", hostname);
        return original_gethostbyname(name);
    }

    // Generate fake IP
    let _fake_ip = match state.dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_gethostbyname: {}", hostname, e);
            return original_gethostbyname(name);
        }
    };

    debug!("Assigned fake IP {} for {}", _fake_ip, hostname);

    // This is a simplified implementation
    // A full implementation would need to manage a static buffer
    // For now, fall back to original
    original_gethostbyname(name)
}

/// Hook for freeaddrinfo() system call
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_freeaddrinfo(res: *mut libc::addrinfo) {
    trace!("hook_freeaddrinfo called");
    // Our getaddrinfo hook currently falls back to the system allocator, so
    // free through libc to avoid mismatched allocator/free behavior.
    original_freeaddrinfo(res);
}

/// Hook for getnameinfo() system call
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_getnameinfo(
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    host: *mut c_char,
    hostlen: libc::socklen_t,
    serv: *mut c_char,
    servlen: libc::socklen_t,
    flags: libc::c_int,
) -> libc::c_int {
    trace!("hook_getnameinfo called");

    // For now, just pass through to original
    // A full implementation would reverse lookup fake IPs
    original_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_state_creation() {
        let config = Config::default();
        let state = HookState::new(config);
        assert!(state.initialized);
    }
}
