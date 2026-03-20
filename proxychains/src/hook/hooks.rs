//! Hook implementations for network functions
//!
//! This module provides the actual hook implementations that intercept
//! network calls and redirect them through the proxy chain.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::raw::c_char;
use std::os::unix::io::IntoRawFd;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libc::{c_int, socklen_t};
use parking_lot::Mutex;
use tracing::{debug, error, info, trace};

use crate::chain::ChainManager;
use crate::config::Config;
use crate::dns::is_fake_ip;
use crate::error::Result;
use crate::ConfigParser;
use crate::net::{get_ipaddr_from_sockaddr, get_ip_from_sockaddr, get_port_from_sockaddr};

use super::interpose::{
    init_original_functions, original_connect, original_freeaddrinfo, original_getaddrinfo,
    original_gethostbyname, original_getnameinfo,
};

/// Global state for the hook library
pub struct HookState {
    pub config: Config,
    pub initialized: bool,
    pub next_reload_check: Instant,
}

impl HookState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            initialized: true,
            next_reload_check: Instant::now() + Duration::from_secs(2),
        }
    }
}

/// Global hook state
static HOOK_STATE: OnceLock<Mutex<HookState>> = OnceLock::new();
/// Track addrinfo/sockaddr allocations created by our getaddrinfo hook.
static CUSTOM_ADDRINFO_ALLOCATIONS: OnceLock<Mutex<HashMap<usize, CustomAddrinfoAllocation>>> =
    OnceLock::new();

thread_local! {
    static GETHOSTBYNAME_STORE: RefCell<Option<Box<HostentStore>>> = const { RefCell::new(None) };
}

struct HostentStore {
    name: CString,
    addr: [u8; 4],
    addr_list: [*mut c_char; 2],
    hostent: libc::hostent,
}

#[derive(Clone, Copy)]
struct CustomAddrinfoAllocation {
    sockaddr_ptr: usize,
    family: libc::c_int,
}

fn custom_alloc_map() -> &'static Mutex<HashMap<usize, CustomAddrinfoAllocation>> {
    CUSTOM_ADDRINFO_ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

const CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(2);

struct HookSnapshot {
    config: Config,
    dns_resolver: crate::dns::DnsResolver,
    initialized: bool,
}

fn maybe_reload_config(state: &mut HookState) {
    let now = Instant::now();
    if now < state.next_reload_check {
        return;
    }
    state.next_reload_check = now + CONFIG_RELOAD_INTERVAL;

    match ConfigParser::new().parse() {
        Ok(config) => {
            let old_count = state.config.proxies.len();
            let new_count = config.proxies.len();
            state.config = config;
            debug!(
                "Reloaded proxychains config (proxies: {} -> {})",
                old_count, new_count
            );
        }
        Err(e) => {
            debug!("Config reload skipped due to parse error: {}", e);
        }
    }
}

fn parse_service_port(service: *const c_char) -> u16 {
    if service.is_null() {
        return 0;
    }
    unsafe {
        CStr::from_ptr(service)
            .to_str()
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0)
    }
}

unsafe fn write_hostname_to_buf(host: *mut c_char, hostlen: libc::socklen_t, hostname: &str) -> c_int {
    if host.is_null() || hostlen <= 1 {
        return libc::EAI_FAIL;
    }
    let bytes = hostname.as_bytes();
    if bytes.len() + 1 > hostlen as usize {
        return libc::EAI_OVERFLOW;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), host as *mut u8, bytes.len());
    *host.add(bytes.len()) = 0;
    0
}

unsafe fn store_fake_addrinfo_result(
    fake_ip: std::net::Ipv4Addr,
    service_port: u16,
    hints: *const libc::addrinfo,
    requested_family: libc::c_int,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    match requested_family {
        libc::AF_INET => {
            let mut sockaddr: libc::sockaddr_in = std::mem::zeroed();
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sockaddr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            sockaddr.sin_family = libc::AF_INET as libc::sa_family_t;
            sockaddr.sin_port = service_port.to_be();
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(fake_ip.octets()),
            };

            let sockaddr_ptr = Box::into_raw(Box::new(sockaddr));
            let mut ai: libc::addrinfo = std::mem::zeroed();
            ai.ai_flags = if hints.is_null() { 0 } else { (*hints).ai_flags };
            ai.ai_family = libc::AF_INET;
            ai.ai_socktype = if hints.is_null() {
                libc::SOCK_STREAM
            } else {
                (*hints).ai_socktype
            };
            ai.ai_protocol = if hints.is_null() {
                libc::IPPROTO_TCP
            } else {
                (*hints).ai_protocol
            };
            ai.ai_addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            ai.ai_addr = sockaddr_ptr as *mut libc::sockaddr;
            ai.ai_canonname = std::ptr::null_mut();
            ai.ai_next = std::ptr::null_mut();

            let ai_ptr = Box::into_raw(Box::new(ai));
            *res = ai_ptr;
            custom_alloc_map().lock().insert(
                ai_ptr as usize,
                CustomAddrinfoAllocation {
                    sockaddr_ptr: sockaddr_ptr as usize,
                    family: libc::AF_INET,
                },
            );
            0
        }
        libc::AF_INET6 => {
            let mut mapped = [0u8; 16];
            mapped[10] = 0xff;
            mapped[11] = 0xff;
            mapped[12..16].copy_from_slice(&fake_ip.octets());

            let mut sockaddr: libc::sockaddr_in6 = std::mem::zeroed();
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
                sockaddr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            sockaddr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sockaddr.sin6_port = service_port.to_be();
            sockaddr.sin6_addr = libc::in6_addr { s6_addr: mapped };
            sockaddr.sin6_scope_id = 0;

            let sockaddr_ptr = Box::into_raw(Box::new(sockaddr));
            let mut ai: libc::addrinfo = std::mem::zeroed();
            ai.ai_flags = if hints.is_null() { 0 } else { (*hints).ai_flags };
            ai.ai_family = libc::AF_INET6;
            ai.ai_socktype = if hints.is_null() {
                libc::SOCK_STREAM
            } else {
                (*hints).ai_socktype
            };
            ai.ai_protocol = if hints.is_null() {
                libc::IPPROTO_TCP
            } else {
                (*hints).ai_protocol
            };
            ai.ai_addrlen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            ai.ai_addr = sockaddr_ptr as *mut libc::sockaddr;
            ai.ai_canonname = std::ptr::null_mut();
            ai.ai_next = std::ptr::null_mut();

            let ai_ptr = Box::into_raw(Box::new(ai));
            *res = ai_ptr;
            custom_alloc_map().lock().insert(
                ai_ptr as usize,
                CustomAddrinfoAllocation {
                    sockaddr_ptr: sockaddr_ptr as usize,
                    family: libc::AF_INET6,
                },
            );
            0
        }
        _ => libc::EAI_FAMILY,
    }
}

/// Initialize the hook library
pub fn init_hooks(config: Config) -> Result<()> {
    // Initialize original functions first
    init_original_functions()?;

    // Create hook state
    let state = HookState::new(config);

    // Store globally
    if HOOK_STATE.set(Mutex::new(state)).is_err() {
        error!("Hook state already initialized");
    }

    info!("Proxychains hooks initialized");
    Ok(())
}

/// Check if hooks are initialized
pub fn is_initialized() -> bool {
    HOOK_STATE
        .get()
        .map_or(false, |s| s.lock().initialized)
}

/// Get the hook state
fn get_hook_state() -> Option<HookSnapshot> {
    let lock = HOOK_STATE.get()?;
    let mut state = lock.lock();
    maybe_reload_config(&mut state);
    let config = state.config.clone();
    let dns_resolver = crate::dns::DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);
    Some(HookSnapshot {
        config,
        dns_resolver,
        initialized: state.initialized,
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
    let target_ip = match get_ipaddr_from_sockaddr(addr) {
        Some(ip) => ip,
        None => return original_connect(sock, addr, len),
    };

    let target_port = get_port_from_sockaddr(addr);

    // Check if we should bypass this connection
    if state.config.should_bypass_ip(&target_ip) {
        debug!("Bypassing proxy for local address: {}:{}", target_ip, target_port);
        return original_connect(sock, addr, len);
    }

    // Apply DNAT if configured
    let (dnat_ip, final_port) = state.config.apply_dnat_ip(&target_ip, target_port);

    // Check if this is a fake IP (needs remote DNS resolution). For IPv6-mapped
    // fake addresses, collapse to IPv4 so SOCKS4a path can still use the domain.
    let (final_ip, target_domain) = match dnat_ip {
        IpAddr::V4(v4) if is_fake_ip(&v4) => (IpAddr::V4(v4), state.dns_resolver.get_hostname(&v4)),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if is_fake_ip(&v4) {
                    (IpAddr::V4(v4), state.dns_resolver.get_hostname(&v4))
                } else {
                    (IpAddr::V6(v6), None)
                }
            } else {
                (IpAddr::V6(v6), None)
            }
        }
        _ => (dnat_ip, None),
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
    let chain_manager = ChainManager::new(state.config.clone());
    match chain_manager.connect_proxy_chain(
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
            // Set errno in a platform-specific way.
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = libc::ECONNREFUSED;
            }
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            {
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

    // Preserve behavior for literal IP strings.
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return original_getaddrinfo(node, service, hints, res);
    }

    let requested_family = if hints.is_null() {
        libc::AF_INET
    } else {
        match (*hints).ai_family {
            libc::AF_UNSPEC => libc::AF_INET,
            libc::AF_INET => libc::AF_INET,
            libc::AF_INET6 => libc::AF_INET6,
            _ => return libc::EAI_FAMILY,
        }
    };

    // Generate fake IP
    let fake_ip = match state.dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_getaddrinfo: {}", hostname, e);
            return libc::EAI_NONAME;
        }
    };

    let service_port = parse_service_port(service);
    let ret = store_fake_addrinfo_result(fake_ip, service_port, hints, requested_family, res);
    if ret != 0 {
        return ret;
    }

    debug!("Assigned fake IP {} for {}", fake_ip, hostname);

    0
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

    // Preserve behavior for literal IP strings.
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return original_gethostbyname(name);
    }

    // Generate fake IP
    let fake_ip = match state.dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_gethostbyname: {}", hostname, e);
            return std::ptr::null_mut();
        }
    };

    debug!("Assigned fake IP {} for {}", fake_ip, hostname);

    let name_cstr = match CString::new(hostname) {
        Ok(v) => v,
        Err(_) => return original_gethostbyname(name),
    };

    GETHOSTBYNAME_STORE.with(|slot| {
        let mut boxed = Box::new(HostentStore {
            name: name_cstr,
            addr: fake_ip.octets(),
            addr_list: [std::ptr::null_mut(); 2],
            hostent: std::mem::zeroed(),
        });

        boxed.addr_list[0] = boxed.addr.as_mut_ptr() as *mut c_char;
        boxed.addr_list[1] = std::ptr::null_mut();

        boxed.hostent.h_name = boxed.name.as_ptr() as *mut c_char;
        boxed.hostent.h_aliases = std::ptr::null_mut();
        boxed.hostent.h_addrtype = libc::AF_INET;
        boxed.hostent.h_length = 4;
        boxed.hostent.h_addr_list = boxed.addr_list.as_mut_ptr();

        let hostent_ptr = &mut boxed.hostent as *mut libc::hostent;
        *slot.borrow_mut() = Some(boxed);
        hostent_ptr
    })
}

/// Hook for freeaddrinfo() system call
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn hook_freeaddrinfo(res: *mut libc::addrinfo) {
    trace!("hook_freeaddrinfo called");
    if res.is_null() {
        return;
    }

    if let Some(alloc) = custom_alloc_map().lock().remove(&(res as usize)) {
        if alloc.family == libc::AF_INET6 {
            let _ = Box::from_raw(alloc.sockaddr_ptr as *mut libc::sockaddr_in6);
        } else {
            let _ = Box::from_raw(alloc.sockaddr_ptr as *mut libc::sockaddr_in);
        }
        let _ = Box::from_raw(res);
        return;
    }

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

    if let Some(state) = get_hook_state() {
        if state.config.proxy_dns {
            if let Some(ip) = get_ip_from_sockaddr(sa) {
                if is_fake_ip(&ip) {
                    if let Some(hostname) = state.dns_resolver.get_hostname(&ip) {
                        return write_hostname_to_buf(host, hostlen, &hostname);
                    }
                }
            }
        }
    }

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
