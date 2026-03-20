//! Windows-specific hook implementations.
//!
//! Winsock calls are intercepted via MinHook and forwarded through the proxy
//! chain on the original socket handle.

use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::mem::{self, ManuallyDrop};
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::io::FromRawSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};
use windows::Win32::Networking::WinSock::{
    ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IPPROTO_TCP, SOCKADDR,
    SOCKADDR_IN, SOCK_STREAM, SOCKET_ERROR, WSAEALREADY, WSAECONNREFUSED, WSAEFAULT,
    WSAEINPROGRESS, WSAEINVAL, WSAEWOULDBLOCK, WSAGetLastError, WSAHOST_NOT_FOUND, WSASetLastError,
    SOCKET, SEND_RECV_FLAGS, send,
};
use windows::core::GUID;
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::SetEvent;

use crate::config::{ChainType, Config, ProxyData, ProxyState};
use crate::dns::{is_fake_ip, DnsResolver};
use crate::error::{Error, Result};
use crate::net::{get_ip_from_sockaddr, get_ipaddr_from_sockaddr, get_port_from_sockaddr};
use crate::proxy::{tunnel_through_proxy, TargetAddress};
use crate::ConfigParser;

use super::interpose_windows::{
    init_original_functions, original_connect, original_freeaddrinfo, original_getaddrinfo,
    original_getaddrinfoexw, original_getaddrinfow, original_gethostbyname, original_getnameinfo,
    original_dns_query_a, original_dns_query_w, original_wsa_ioctl,
};
use super::reload::config_reload_interval;

/// Global state for the hook library (Windows).
pub struct HookState {
    pub config: Mutex<Config>,
    pub proxy_states: Mutex<Vec<ProxyData>>,
    pub load_balance_counter: AtomicUsize,
    pub next_reload_check: Mutex<Instant>,
    pub initialized: bool,
}

impl HookState {
    pub fn new(config: Config) -> Self {
        let proxy_states = Mutex::new(config.proxies.clone());
        Self {
            config: Mutex::new(config),
            proxy_states,
            load_balance_counter: AtomicUsize::new(0),
            next_reload_check: Mutex::new(Instant::now() + config_reload_interval()),
            initialized: true,
        }
    }
}

/// Global hook state.
static HOOK_STATE: OnceLock<HookState> = OnceLock::new();
/// Tracks custom addrinfo allocations created by `hook_getaddrinfo_impl`.
static CUSTOM_ADDRINFO_ALLOCATIONS: OnceLock<Mutex<HashMap<usize, CustomAddrinfoAllocation>>> =
    OnceLock::new();

#[derive(Clone, Copy)]
struct CustomAddrinfoAllocation {
    sockaddr_ptr: usize,
    family: i32,
    is_wide: bool,
}

fn custom_alloc_map() -> &'static Mutex<HashMap<usize, CustomAddrinfoAllocation>> {
    CUSTOM_ADDRINFO_ALLOCATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn maybe_reload_config(state: &HookState) {
    let now = Instant::now();
    {
        let mut next = state.next_reload_check.lock();
        if now < *next {
            return;
        }
        *next = now + config_reload_interval();
    }

    match ConfigParser::new().parse() {
        Ok(config) => {
            let old_count = state.config.lock().proxies.len();
            let new_count = config.proxies.len();
            *state.config.lock() = config.clone();
            *state.proxy_states.lock() = config.proxies.clone();
            debug!(
                "Reloaded proxychains config on Windows (proxies: {} -> {})",
                old_count, new_count
            );
        }
        Err(e) => {
            debug!("Config reload skipped due to parse error: {}", e);
        }
    }
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

fn make_sockaddr_in6_mapped_bytes(ip: Ipv4Addr, port: u16) -> [u8; 28] {
    let mut raw = [0u8; 28];
    raw[0..2].copy_from_slice(&(AF_INET6.0 as u16).to_ne_bytes());
    raw[2..4].copy_from_slice(&port.to_be_bytes());
    // flowinfo 4..8 left as 0
    raw[18] = 0xff;
    raw[19] = 0xff;
    raw[20..24].copy_from_slice(&ip.octets());
    // scope_id 24..28 left as 0
    raw
}

unsafe fn connect_socket_to_proxy(sock: usize, proxy: &ProxyData) -> Result<()> {
    let resolved_ip = proxy.resolve_ipv4()?;
    let sockaddr = make_sockaddr_in(resolved_ip, proxy.port);
    let ret = original_connect(
        sock,
        &sockaddr as *const SOCKADDR_IN as *const c_void,
        mem::size_of::<SOCKADDR_IN>() as i32,
    );
    if ret == SOCKET_ERROR {
        let wsa_error = WSAGetLastError().0;
        if wsa_error == WSAEWOULDBLOCK.0
            || wsa_error == WSAEINPROGRESS.0
            || wsa_error == WSAEALREADY.0
        {
            // Non-blocking sockets can report in-progress; let handshake IO complete it.
            return Ok(());
        }

        // IPv6 sockets cannot use IPv4 sockaddr directly. Retry using an IPv4-mapped
        // IPv6 destination (::ffff:a.b.c.d).
        let mapped = make_sockaddr_in6_mapped_bytes(resolved_ip, proxy.port);
        let mapped_ret = original_connect(
            sock,
            mapped.as_ptr() as *const c_void,
            mapped.len() as i32,
        );
        if mapped_ret == SOCKET_ERROR {
            let mapped_err = WSAGetLastError().0;
            if mapped_err == WSAEWOULDBLOCK.0
                || mapped_err == WSAEINPROGRESS.0
                || mapped_err == WSAEALREADY.0
            {
                return Ok(());
            }
            return Err(Error::ProxyConnection(format!(
                "Failed to connect to proxy {}:{} (WSA {}, retry WSA {})",
                proxy.host, proxy.port, wsa_error, mapped_err
            )));
        }
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
        let next_target = TargetAddress::from_ip(IpAddr::V4(selected[next].ip));
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
    let config = state.config.lock().clone();
    let alive_indices: Vec<usize> = proxies
        .iter()
        .enumerate()
        .filter(|(_, p)| p.state == ProxyState::Play)
        .map(|(i, _)| i)
        .collect();

    match config.chain_type {
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
            let max_chain = config.chain_len.unwrap_or(selected.len()).max(1);
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

fn parse_service_port_wide(service: *const u16) -> u16 {
    if service.is_null() {
        return 0;
    }
    unsafe {
        let mut len = 0usize;
        while *service.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(service, len);
        let s = String::from_utf16_lossy(slice);
        s.parse::<u16>().unwrap_or(0)
    }
}

fn parse_wide_string(ptr: *const u16) -> std::result::Result<String, ()> {
    if ptr.is_null() {
        return Err(());
    }
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).map_err(|_| ())
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
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if addr.is_null() || len <= 0 {
        return original_connect(sock, addr, len);
    }

    let target_ip = match get_ipaddr_from_sockaddr(addr) {
        Some(ip) => ip,
        None => return original_connect(sock, addr, len),
    };
    let target_port = get_port_from_sockaddr(addr);
    debug!("hook_connect_impl intercepted target {}:{}", target_ip, target_port);

    if config.should_bypass_ip(&target_ip) {
        return original_connect(sock, addr, len);
    }

    let (dnat_ip, final_port) = config.apply_dnat_ip(&target_ip, target_port);
    let (final_ip, target_domain) = match dnat_ip {
        IpAddr::V4(v4) if is_fake_ip(&v4) => (IpAddr::V4(v4), dns_resolver.get_hostname(&v4)),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if is_fake_ip(&v4) {
                    (IpAddr::V4(v4), dns_resolver.get_hostname(&v4))
                } else {
                    (IpAddr::V6(v6), None)
                }
            } else {
                (IpAddr::V6(v6), None)
            }
        }
        _ => (dnat_ip, None),
    };

    let target = if let Some(domain) = target_domain {
        TargetAddress::from_both(final_ip, domain)
    } else {
        TargetAddress::from_ip(final_ip)
    };

    let max_attempts = config.max_chain_retries.max(1);
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
            config.tcp_read_timeout,
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

/// Windows WSAConnect hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_wsa_connect_impl(
    sock: usize,
    name: *const c_void,
    namelen: i32,
    _caller_data: *const c_void,
    _callee_data: *const c_void,
    _sqos: *const c_void,
    _gqos: *const c_void,
) -> i32 {
    if !name.is_null() && namelen > 0 {
        if let (Some(ip), port) = (get_ipaddr_from_sockaddr(name), get_port_from_sockaddr(name)) {
            debug!("hook_wsa_connect_impl intercepted target {}:{}", ip, port);
        }
    }
    hook_connect_impl(sock, name, namelen)
}

const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
const WSAID_CONNECTEX: GUID = GUID::from_u128(0x25a207b9_ddf3_4660_8ee9_76e58c74063e);

/// ConnectEx replacement used when applications query extension function pointers via WSAIoctl.
///
/// This implementation is intentionally synchronous:
/// - It supports optional initial send buffer semantics (`lpSendBuffer` + `dwSendDataLength`).
#[cfg(windows)]
pub unsafe extern "system" fn hook_connect_ex_impl(
    sock: usize,
    name: *const c_void,
    namelen: i32,
    send_buf: *const c_void,
    send_len: u32,
    bytes_sent: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    if send_len > 0 && send_buf.is_null() {
        WSASetLastError(WSAEFAULT.0);
        return 0;
    }

    if !bytes_sent.is_null() {
        *bytes_sent = 0;
    }

    let ret = hook_connect_impl(sock, name, namelen);
    if ret == SOCKET_ERROR {
        0
    } else {
        if send_len > 0 {
            let send_slice =
                std::slice::from_raw_parts(send_buf as *const u8, send_len as usize);
            let sent = send(SOCKET(sock), send_slice, SEND_RECV_FLAGS(0));
            if sent == SOCKET_ERROR {
                return 0;
            }
            if !bytes_sent.is_null() {
                *bytes_sent = sent as u32;
            }
        }
        if !overlapped.is_null() {
            let ov = &mut *(overlapped as *mut OVERLAPPED);
            if !ov.hEvent.is_invalid() {
                let _ = SetEvent(ov.hEvent);
            }
        }
        1
    }
}

/// WSAIoctl hook implementation.
///
/// Intercepts `SIO_GET_EXTENSION_FUNCTION_POINTER` for `WSAID_CONNECTEX` and returns our own
/// ConnectEx function pointer so ConnectEx-based clients still go through proxy enforcement.
#[cfg(windows)]
pub unsafe extern "system" fn hook_wsa_ioctl_impl(
    sock: usize,
    io_control_code: u32,
    in_buffer: *mut c_void,
    in_buffer_len: u32,
    out_buffer: *mut c_void,
    out_buffer_len: u32,
    bytes_returned: *mut u32,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
) -> i32 {
    if io_control_code != SIO_GET_EXTENSION_FUNCTION_POINTER
        || in_buffer_len < std::mem::size_of::<GUID>() as u32
        || out_buffer_len < std::mem::size_of::<*const c_void>() as u32
        || in_buffer.is_null()
        || out_buffer.is_null()
    {
        return original_wsa_ioctl(
            sock,
            io_control_code,
            in_buffer,
            in_buffer_len,
            out_buffer,
            out_buffer_len,
            bytes_returned,
            overlapped,
            completion_routine,
        );
    }

    let requested = *(in_buffer as *const GUID);
    if requested != WSAID_CONNECTEX {
        return original_wsa_ioctl(
            sock,
            io_control_code,
            in_buffer,
            in_buffer_len,
            out_buffer,
            out_buffer_len,
            bytes_returned,
            overlapped,
            completion_routine,
        );
    }

    let replacement = hook_connect_ex_impl as *const c_void;
    std::ptr::copy_nonoverlapping(
        &replacement as *const *const c_void as *const u8,
        out_buffer as *mut u8,
        std::mem::size_of::<*const c_void>(),
    );
    if !bytes_returned.is_null() {
        *bytes_returned = std::mem::size_of::<*const c_void>() as u32;
    }
    0
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
        Some(s) => s,
        None => return original_getaddrinfo(pnode, pservice, phints, ppresult),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if pnode.is_null() || ppresult.is_null() {
        return WSAEINVAL.0;
    }

    let requested_family = if phints.is_null() {
        AF_INET.0 as i32
    } else {
        let hints = &*(phints as *const ADDRINFOA);
        if hints.ai_family == 0 || hints.ai_family == AF_INET.0 as i32 {
            AF_INET.0 as i32
        } else if hints.ai_family == AF_INET6.0 as i32 {
            AF_INET6.0 as i32
        } else {
            return WSAHOST_NOT_FOUND.0;
        }
    };

    let hostname = match CStr::from_ptr(pnode).to_str() {
        Ok(s) => s,
        Err(_) => return WSAEINVAL.0,
    };

    if hostname.parse::<IpAddr>().is_ok() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }

    if crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }

    let fake_ip = match dns_resolver.resolve(hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_getaddrinfo_impl: {}", hostname, e);
            return WSAHOST_NOT_FOUND.0;
        }
    };

    let service_port = parse_service_port(pservice);
    let (sockaddr_ptr, addrlen) = if requested_family == AF_INET6.0 as i32 {
        let sockaddr_raw = Box::new(make_sockaddr_in6_mapped_bytes(fake_ip, service_port));
        (
            Box::into_raw(sockaddr_raw) as *mut SOCKADDR,
            mem::size_of::<[u8; 28]>(),
        )
    } else {
        let sockaddr_box = Box::new(make_sockaddr_in(fake_ip, service_port));
        (
            Box::into_raw(sockaddr_box) as *mut SOCKADDR,
            mem::size_of::<SOCKADDR_IN>(),
        )
    };

    let mut ai = ADDRINFOA::default();
    ai.ai_family = requested_family;
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
    ai.ai_addrlen = addrlen;
    ai.ai_addr = sockaddr_ptr;
    ai.ai_next = std::ptr::null_mut();

    let ai_ptr = Box::into_raw(Box::new(ai));
    *ppresult = ai_ptr as *mut c_void;
    custom_alloc_map().lock().insert(
        ai_ptr as usize,
        CustomAddrinfoAllocation {
            sockaddr_ptr: sockaddr_ptr as usize,
            family: requested_family,
            is_wide: false,
        },
    );

    debug!("Assigned fake IP {} for {}", fake_ip, hostname);
    0
}

/// Windows GetAddrInfoW hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getaddrinfow_impl(
    pnode: *const u16,
    pservice: *const u16,
    phints: *const c_void,
    ppresult: *mut *mut c_void,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original_getaddrinfow(pnode, pservice, phints, ppresult),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns {
        return original_getaddrinfow(pnode, pservice, phints, ppresult);
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if pnode.is_null() || ppresult.is_null() {
        return WSAEINVAL.0;
    }

    let requested_family = if phints.is_null() {
        AF_INET.0 as i32
    } else {
        let hints = &*(phints as *const ADDRINFOW);
        if hints.ai_family == 0 || hints.ai_family == AF_INET.0 as i32 {
            AF_INET.0 as i32
        } else if hints.ai_family == AF_INET6.0 as i32 {
            AF_INET6.0 as i32
        } else {
            return WSAHOST_NOT_FOUND.0;
        }
    };

    let hostname = match parse_wide_string(pnode) {
        Ok(s) => s,
        Err(_) => return WSAEINVAL.0,
    };

    if hostname.parse::<IpAddr>().is_ok() {
        return original_getaddrinfow(pnode, pservice, phints, ppresult);
    }

    if crate::dns::lookup_in_hosts(&hostname).is_some() {
        return original_getaddrinfow(pnode, pservice, phints, ppresult);
    }

    let fake_ip = match dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_getaddrinfow_impl: {}", hostname, e);
            return WSAHOST_NOT_FOUND.0;
        }
    };

    let service_port = parse_service_port_wide(pservice);
    let (sockaddr_ptr, addrlen) = if requested_family == AF_INET6.0 as i32 {
        let sockaddr_raw = Box::new(make_sockaddr_in6_mapped_bytes(fake_ip, service_port));
        (
            Box::into_raw(sockaddr_raw) as *mut SOCKADDR,
            mem::size_of::<[u8; 28]>(),
        )
    } else {
        let sockaddr_box = Box::new(make_sockaddr_in(fake_ip, service_port));
        (
            Box::into_raw(sockaddr_box) as *mut SOCKADDR,
            mem::size_of::<SOCKADDR_IN>(),
        )
    };

    let mut ai = ADDRINFOW::default();
    ai.ai_family = requested_family;
    ai.ai_socktype = if phints.is_null() {
        SOCK_STREAM.0
    } else {
        (*(phints as *const ADDRINFOW)).ai_socktype
    };
    ai.ai_protocol = if phints.is_null() {
        IPPROTO_TCP.0
    } else {
        (*(phints as *const ADDRINFOW)).ai_protocol
    };
    ai.ai_addrlen = addrlen;
    ai.ai_addr = sockaddr_ptr;
    ai.ai_next = std::ptr::null_mut();

    let ai_ptr = Box::into_raw(Box::new(ai));
    *ppresult = ai_ptr as *mut c_void;
    custom_alloc_map().lock().insert(
        ai_ptr as usize,
        CustomAddrinfoAllocation {
            sockaddr_ptr: sockaddr_ptr as usize,
            family: requested_family,
            is_wide: true,
        },
    );

    debug!("Assigned fake IP {} for {} (GetAddrInfoW)", fake_ip, hostname);
    0
}

/// Windows GetAddrInfoExW hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getaddrinfoexw_impl(
    pname: *const u16,
    pservice: *const u16,
    namespace: u32,
    pnspid: *mut c_void,
    hints: *const c_void,
    ppresult: *mut *mut c_void,
    timeout: *mut c_void,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
    pname_handle: *mut c_void,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => {
            return original_getaddrinfoexw(
                pname,
                pservice,
                namespace,
                pnspid,
                hints,
                ppresult,
                timeout,
                overlapped,
                completion_routine,
                pname_handle,
            )
        }
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns {
        return original_getaddrinfoexw(
            pname,
            pservice,
            namespace,
            pnspid,
            hints,
            ppresult,
            timeout,
            overlapped,
            completion_routine,
            pname_handle,
        );
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if pname.is_null() {
        return WSAEINVAL.0;
    }

    let hostname = match parse_wide_string(pname) {
        Ok(s) => s,
        Err(_) => return WSAEINVAL.0,
    };

    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(&hostname).is_some() {
        return original_getaddrinfoexw(
            pname,
            pservice,
            namespace,
            pnspid,
            hints,
            ppresult,
            timeout,
            overlapped,
            completion_routine,
            pname_handle,
        );
    }

    let fake_ip = match dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(_) => return WSAHOST_NOT_FOUND.0,
    };

    let fake_wide: Vec<u16> = fake_ip
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    original_getaddrinfoexw(
        fake_wide.as_ptr(),
        pservice,
        namespace,
        pnspid,
        hints,
        ppresult,
        timeout,
        overlapped,
        completion_routine,
        pname_handle,
    )
}

const DNS_ERROR_RCODE_NAME_ERROR: i32 = 9003;

/// Windows DnsQuery_A hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_dns_query_a_impl(
    name: *const i8,
    query_type: u16,
    options: u32,
    extra: *mut c_void,
    result: *mut *mut c_void,
    reserved: *mut c_void,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original_dns_query_a(name, query_type, options, extra, result, reserved),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns || name.is_null() {
        return original_dns_query_a(name, query_type, options, extra, result, reserved);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_dns_query_a(name, query_type, options, extra, result, reserved);
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);
    let fake_ip = match dns_resolver.resolve(hostname) {
        Ok(ip) => ip,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    let fake_ip_c = match CString::new(fake_ip.to_string()) {
        Ok(v) => v,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    original_dns_query_a(
        fake_ip_c.as_ptr(),
        query_type,
        options,
        extra,
        result,
        reserved,
    )
}

/// Windows DnsQuery_W hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_dns_query_w_impl(
    name: *const u16,
    query_type: u16,
    options: u32,
    extra: *mut c_void,
    result: *mut *mut c_void,
    reserved: *mut c_void,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original_dns_query_w(name, query_type, options, extra, result, reserved),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns || name.is_null() {
        return original_dns_query_w(name, query_type, options, extra, result, reserved);
    }

    let hostname = match parse_wide_string(name) {
        Ok(s) => s,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(&hostname).is_some() {
        return original_dns_query_w(name, query_type, options, extra, result, reserved);
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);
    let fake_ip = match dns_resolver.resolve(&hostname) {
        Ok(ip) => ip,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    let fake_wide: Vec<u16> = fake_ip
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    original_dns_query_w(
        fake_wide.as_ptr(),
        query_type,
        options,
        extra,
        result,
        reserved,
    )
}

/// Windows freeaddrinfo hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_freeaddrinfo_impl(pres: *mut c_void) {
    if pres.is_null() {
        return;
    }

    if let Some(alloc) = custom_alloc_map().lock().remove(&(pres as usize)) {
        if alloc.family == AF_INET6.0 as i32 {
            let _ = Box::from_raw(alloc.sockaddr_ptr as *mut [u8; 28]);
        } else {
            let _ = Box::from_raw(alloc.sockaddr_ptr as *mut SOCKADDR_IN);
        }
        if alloc.is_wide {
            let _ = Box::from_raw(pres as *mut ADDRINFOW);
        } else {
            let _ = Box::from_raw(pres as *mut ADDRINFOA);
        }
        return;
    }

    original_freeaddrinfo(pres);
}

/// Windows gethostbyname hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_gethostbyname_impl(name: *const i8) -> *mut c_void {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original_gethostbyname(name),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns {
        return original_gethostbyname(name);
    }
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if name.is_null() {
        WSASetLastError(WSAEINVAL.0);
        return std::ptr::null_mut();
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => {
            WSASetLastError(WSAEINVAL.0);
            return std::ptr::null_mut();
        }
    };

    if hostname.parse::<IpAddr>().is_ok() {
        return original_gethostbyname(name);
    }

    if crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_gethostbyname(name);
    }

    let fake_ip = match dns_resolver.resolve(hostname) {
        Ok(ip) => ip,
        Err(e) => {
            error!("Failed to resolve {} in hook_gethostbyname_impl: {}", hostname, e);
            WSASetLastError(WSAHOST_NOT_FOUND.0);
            return std::ptr::null_mut();
        }
    };

    let fake_ip_cstr = match CString::new(fake_ip.to_string()) {
        Ok(v) => v,
        Err(_) => {
            WSASetLastError(WSAHOST_NOT_FOUND.0);
            return std::ptr::null_mut();
        }
    };

    let result = original_gethostbyname(fake_ip_cstr.as_ptr());
    if result.is_null() {
        WSASetLastError(WSAHOST_NOT_FOUND.0);
    }
    result
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
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    let dns_resolver = DnsResolver::new(config.proxy_dns, config.remote_dns_subnet);

    if config.proxy_dns && !sa.is_null() && !host.is_null() && hostlen > 1 {
        if let Some(ip) = get_ip_from_sockaddr(sa) {
            if is_fake_ip(&ip) {
                if let Some(hostname) = dns_resolver.get_hostname(&ip) {
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
