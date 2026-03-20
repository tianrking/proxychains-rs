//! Windows-specific hook implementations.
//!
//! Winsock calls are intercepted via MinHook and forwarded through the proxy
//! chain on the original socket handle.

use std::collections::HashMap;
use std::ffi::{c_void, CStr};
use std::mem::{self, ManuallyDrop};
use std::net::Ipv4Addr;
use std::os::windows::io::FromRawSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};
use windows::Win32::Networking::WinSock::{
    ADDRINFOA, AF_INET, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN, SOCK_STREAM,
    SOCKET_ERROR, WSAECONNREFUSED, WSAEFAULT, WSAEINVAL, WSASetLastError,
};

use crate::config::{ChainType, Config, ProxyData, ProxyState};
use crate::dns::{is_fake_ip, DnsResolver};
use crate::error::{Error, Result};
use crate::net::{get_ip_from_sockaddr, get_port_from_sockaddr};
use crate::proxy::{tunnel_through_proxy, TargetAddress};

use super::interpose_windows::{
    init_original_functions, original_connect, original_freeaddrinfo, original_getaddrinfo,
    original_gethostbyname, original_getnameinfo,
};

/// Global state for the hook library (Windows).
pub struct HookState {
    pub config: Config,
    pub dns_resolver: DnsResolver,
    pub proxy_states: Mutex<Vec<ProxyData>>,
    pub load_balance_counter: AtomicUsize,
    pub initialized: bool,
}

impl HookState {
    pub fn new(config: Config) -> Self {
        let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);
        let proxy_states = Mutex::new(config.proxies.clone());
        Self {
            config,
            dns_resolver,
            proxy_states,
            load_balance_counter: AtomicUsize::new(0),
            initialized: true,
        }
    }
}

/// Global hook state.
static HOOK_STATE: OnceLock<HookState> = OnceLock::new();
/// Tracks custom addrinfo allocations created by `hook_getaddrinfo_impl`.
static CUSTOM_ADDRINFO_ALLOCATIONS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

fn custom_alloc_map() -> &'static Mutex<HashMap<usize, usize>> {
    CUSTOM_ADDRINFO_ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Initialize the hook library.
pub fn init_hooks(config: Config) -> Result<()> {
    init_original_functions()?;

    let state = HookState::new(config);
    if HOOK_STATE.set(state).is_err() {
        warn!("Hook state already initialized");
    }

    info!("Proxychains Windows hooks initialized");
    Ok(())
}

/// Check if hooks are initialized.
pub fn is_initialized() -> bool {
    HOOK_STATE.get().map_or(false, |s| s.initialized)
}

fn get_hook_state() -> Option<&'static HookState> {
    HOOK_STATE.get()
}

fn make_sockaddr_in(ip: Ipv4Addr, port: u16) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        },
        sin_zero: [0; 8],
    }
}

unsafe fn connect_socket_to_proxy(sock: usize, proxy: &ProxyData) -> Result<()> {
    let sockaddr = make_sockaddr_in(proxy.ip, proxy.port);
    let ret = original_connect(
        sock,
        &sockaddr as *const SOCKADDR_IN as *const c_void,
        mem::size_of::<SOCKADDR_IN>() as i32,
    );
    if ret == SOCKET_ERROR {
        return Err(Error::ProxyConnection(format!(
            "Failed to connect to proxy {}:{}",
            proxy.ip, proxy.port
        )));
    }
    Ok(())
}

unsafe fn connect_chain_on_socket(
    sock: usize,
    selected: &[ProxyData],
    target: &TargetAddress,
    target_port: u16,
    timeout: std::time::Duration,
) -> std::result::Result<(), (Error, usize)> {
    if selected.is_empty() {
        return Err((Error::ChainEmpty, 0));
    }

    if let Err(e) = connect_socket_to_proxy(sock, &selected[0]) {
        return Err((e, 0));
    }

    // The application owns this socket. We must not close it from the hook.
    let mut stream = ManuallyDrop::new(std::net::TcpStream::from_raw_socket(sock as u64));
    let stream_ref: &mut std::net::TcpStream = &mut *stream;
    let _ = stream_ref.set_read_timeout(Some(timeout));
    let _ = stream_ref.set_write_timeout(Some(timeout));

    if selected.len() == 1 {
        if let Err(e) =
            tunnel_through_proxy(stream_ref, &selected[0], target, target_port, timeout)
        {
            return Err((e, 0));
        }
        return Ok(());
    }

    let mut current = 0usize;
    for next in 1..selected.len() {
        let next_target = TargetAddress::from_ip(selected[next].ip);
        if let Err(e) = tunnel_through_proxy(
            stream_ref,
            &selected[current],
            &next_target,
            selected[next].port,
            timeout,
        ) {
            return Err((e, next));
        }
        current = next;
    }

    if let Err(e) = tunnel_through_proxy(
        stream_ref,
        &selected[current],
        target,
        target_port,
        timeout,
    ) {
        return Err((e, current));
    }

    Ok(())
}

fn select_indices(state: &HookState, proxies: &[ProxyData]) -> Option<Vec<usize>> {
    let alive_indices: Vec<usize> = proxies
        .iter()
        .enumerate()
        .filter(|(_, p)| p.state == ProxyState::Play)
        .map(|(i, _)| i)
        .collect();

    match state.config.chain_type {
        ChainType::Strict => {
            if proxies.is_empty() {
                None
            } else {
                Some((0..proxies.len()).collect())
            }
        }
        ChainType::Dynamic => {
            if alive_indices.is_empty() {
                None
            } else {
                Some(alive_indices)
            }
        }
        ChainType::Random => {
            if alive_indices.is_empty() {
                return None;
            }
            let mut selected = alive_indices;
            let mut rng = rand::thread_rng();
            selected.shuffle(&mut rng);
            let max_chain = state.config.chain_len.unwrap_or(selected.len()).max(1);
            selected.truncate(max_chain.min(selected.len()));
            Some(selected)
        }
        ChainType::LoadBalance => {
            if alive_indices.is_empty() {
                return None;
            }
            let idx = state
                .load_balance_counter
                .fetch_add(1, Ordering::Relaxed)
                % alive_indices.len();
            Some(vec![alive_indices[idx]])
        }
        ChainType::Failover => alive_indices.first().copied().map(|i| vec![i]),
    }
}

fn parse_service_port(service: *const i8) -> u16 {
    if service.is_null() {
        return 0;
    }
    unsafe {
        match CStr::from_ptr(service).to_str() {
            Ok(s) => s.parse::<u16>().unwrap_or(0),
            Err(_) => 0,
        }
    }
}

/// Windows connect hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_connect_impl(
    sock: usize,
    addr: *const c_void,
    len: i32,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original_connect(sock, addr, len),
    };

    if addr.is_null() || len <= 0 {
        return original_connect(sock, addr, len);
    }

    let target_ip = match get_ip_from_sockaddr(addr) {
        Some(ip) => ip,
        None => return original_connect(sock, addr, len),
    };
    let target_port = get_port_from_sockaddr(addr);

    if state.config.should_bypass(&target_ip) {
        return original_connect(sock, addr, len);
    }

    let (final_ip, final_port) = state.config.apply_dnat(&target_ip, target_port);
    let target_domain = if is_fake_ip(&final_ip) {
        state.dns_resolver.get_hostname(&final_ip)
    } else {
        None
    };

    let target = if let Some(domain) = target_domain {
        TargetAddress::from_both(final_ip, domain)
    } else {
        TargetAddress::from_ip(final_ip)
    };

    let max_attempts = state.config.max_chain_retries.max(1);
    for attempt in 1..=max_attempts {
        let (selected_indices, selected_proxies) = {
            let proxies = state.proxy_states.lock();
            let Some(indices) = select_indices(state, &proxies) else {
                WSASetLastError(WSAECONNREFUSED.0);
                return SOCKET_ERROR;
            };
            let chosen = indices.iter().map(|&i| proxies[i].clone()).collect::<Vec<_>>();
            (indices, chosen)
        };

        match connect_chain_on_socket(
            sock,
            &selected_proxies,
            &target,
            final_port,
            state.config.tcp_read_timeout,
        ) {
            Ok(()) => return 0,
            Err((e, failed_hop)) => {
                let failed_proxy_global = selected_indices
                    .get(failed_hop)
                    .or_else(|| selected_indices.last())
                    .copied();
                if let Some(idx) = failed_proxy_global {
                    let mut proxies = state.proxy_states.lock();
                    if let Some(p) = proxies.get_mut(idx) {
                        p.state = if matches!(e, Error::Blocked) {
                            ProxyState::Blocked
                        } else {
                            ProxyState::Down
                        };
                    }
                }
                warn!("connect attempt {}/{} failed: {}", attempt, max_attempts, e);
            }
        }
    }

    WSASetLastError(WSAECONNREFUSED.0);
    SOCKET_ERROR
}

/// Windows getaddrinfo hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getaddrinfo_impl(
    pnode: *const i8,
    pservice: *const i8,
    phints: *const c_void,
    ppresult: *mut *mut c_void,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) if s.config.proxy_dns => s,
        _ => return original_getaddrinfo(pnode, pservice, phints, ppresult),
    };

    if pnode.is_null() || ppresult.is_null() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }

    if !phints.is_null() {
        let hints = &*(phints as *const ADDRINFOA);
        if hints.ai_family != 0 && hints.ai_family != AF_INET.0 as i32 {
            return original_getaddrinfo(pnode, pservice, phints, ppresult);
        }
    }

    let hostname = match CStr::from_ptr(pnode).to_str() {
        Ok(s) => s,
        Err(_) => return original_getaddrinfo(pnode, pservice, phints, ppresult),
    };

    if hostname.parse::<Ipv4Addr>().is_ok() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }

    if crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }

    let fake_ip = match state.dns_resolver.resolve(hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_getaddrinfo_impl: {}", hostname, e);
            return original_getaddrinfo(pnode, pservice, phints, ppresult);
        }
    };

    let service_port = parse_service_port(pservice);
    let sockaddr_box = Box::new(make_sockaddr_in(fake_ip, service_port));
    let sockaddr_ptr = Box::into_raw(sockaddr_box);

    let mut ai = ADDRINFOA::default();
    ai.ai_family = AF_INET.0 as i32;
    ai.ai_socktype = if phints.is_null() {
        SOCK_STREAM.0
    } else {
        (*(phints as *const ADDRINFOA)).ai_socktype
    };
    ai.ai_protocol = if phints.is_null() {
        IPPROTO_TCP.0
    } else {
        (*(phints as *const ADDRINFOA)).ai_protocol
    };
    ai.ai_addrlen = mem::size_of::<SOCKADDR_IN>();
    ai.ai_addr = sockaddr_ptr as *mut SOCKADDR;
    ai.ai_next = std::ptr::null_mut();

    let ai_ptr = Box::into_raw(Box::new(ai));
    *ppresult = ai_ptr as *mut c_void;
    custom_alloc_map()
        .lock()
        .insert(ai_ptr as usize, sockaddr_ptr as usize);

    debug!("Assigned fake IP {} for {}", fake_ip, hostname);
    0
}

/// Windows freeaddrinfo hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_freeaddrinfo_impl(pres: *mut c_void) {
    if pres.is_null() {
        return;
    }

    if let Some(sockaddr_ptr) = custom_alloc_map().lock().remove(&(pres as usize)) {
        let _ = Box::from_raw(sockaddr_ptr as *mut SOCKADDR_IN);
        let _ = Box::from_raw(pres as *mut ADDRINFOA);
        return;
    }

    original_freeaddrinfo(pres);
}

/// Windows gethostbyname hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_gethostbyname_impl(name: *const i8) -> *mut c_void {
    original_gethostbyname(name)
}

/// Windows getnameinfo hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getnameinfo_impl(
    sa: *const c_void,
    salen: i32,
    host: *mut i8,
    hostlen: u32,
    serv: *mut i8,
    servlen: u32,
    flags: i32,
) -> i32 {
    let Some(state) = get_hook_state() else {
        return original_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
    };

    if state.config.proxy_dns && !sa.is_null() && !host.is_null() && hostlen > 1 {
        if let Some(ip) = get_ip_from_sockaddr(sa) {
            if is_fake_ip(&ip) {
                if let Some(hostname) = state.dns_resolver.get_hostname(&ip) {
                    let bytes = hostname.as_bytes();
                    if bytes.len() + 1 > hostlen as usize {
                        WSASetLastError(WSAEFAULT.0);
                        return WSAEINVAL.0;
                    }
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), host as *mut u8, bytes.len());
                    *host.add(bytes.len()) = 0;
                    return 0;
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
