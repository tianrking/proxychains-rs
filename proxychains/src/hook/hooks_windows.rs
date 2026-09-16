//! Windows-specific hook implementations.
//!
//! Winsock calls are intercepted via MinHook and forwarded through the proxy
//! chain on the original socket handle.

use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::mem::{self, ManuallyDrop};
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::io::FromRawSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use parking_lot::Mutex;
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};
use windows::core::GUID;
use windows::Win32::Foundation::{DNS_REQUEST_PENDING, HANDLE};
use windows::Win32::NetworkManagement::Dns::{DNS_QUERY_REQUEST, DNS_QUERY_RESULT};
use windows::Win32::Networking::WinSock::{
    send, WSAGetLastError, WSASetLastError, ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, IN_ADDR,
    IN_ADDR_0, IPPROTO_TCP, SEND_RECV_FLAGS, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR,
    SOCK_STREAM, WSAEACCES, WSAEALREADY, WSAECONNREFUSED, WSAEFAULT, WSAEINPROGRESS, WSAEINVAL,
    WSAEWOULDBLOCK, WSAHOST_NOT_FOUND, WSAID_WSASENDMSG, WSA_IO_PENDING,
};
use windows::Win32::System::Threading::SetEvent;
use windows::Win32::System::IO::{PostQueuedCompletionStatus, OVERLAPPED};

use crate::chain::{mark_proxy_failure, mark_proxy_success, proxy_is_available, HealthProtocol};
use crate::config::{ChainType, Config, ProxyData, ProxyState, RouteAction, RouteProtocol};
use crate::dns::{is_fake_ip, DnsResolver};
use crate::error::{Error, Result};
use crate::net::{get_ip_from_sockaddr, get_ipaddr_from_sockaddr, get_port_from_sockaddr};
use crate::proxy::{tunnel_through_proxy, TargetAddress};
use crate::ConfigParser;

use super::interpose_windows::{
    init_original_functions, original_connect, original_dns_query_a, original_dns_query_ex,
    original_dns_query_utf8, original_dns_query_w, original_freeaddrinfo, original_getaddrinfo,
    original_getaddrinfoex_overlapped_result, original_getaddrinfoexa, original_getaddrinfoexw,
    original_getaddrinfow, original_gethostbyname, original_getnameinfo, original_wsa_ioctl,
};
use super::reload::config_reload_interval;

type LookupCompletionRoutine = unsafe extern "system" fn(u32, u32, *mut c_void);

struct AsyncDnsWContext {
    fake_name: Vec<u16>,
    callback: Option<LookupCompletionRoutine>,
}

struct AsyncDnsAContext {
    fake_name: CString,
    callback: Option<LookupCompletionRoutine>,
}

struct AsyncDnsExContext {
    _token: Box<u8>,
    _fake_name: Vec<u16>,
    original_context: *const c_void,
    callback: unsafe extern "system" fn(*const c_void, *mut DNS_QUERY_RESULT),
}

unsafe impl Send for AsyncDnsExContext {}
unsafe impl Sync for AsyncDnsExContext {}

static ASYNC_DNS_W: OnceLock<Mutex<HashMap<usize, AsyncDnsWContext>>> = OnceLock::new();
static ASYNC_DNS_A: OnceLock<Mutex<HashMap<usize, AsyncDnsAContext>>> = OnceLock::new();
static ASYNC_DNS_EX: OnceLock<Mutex<HashMap<usize, AsyncDnsExContext>>> = OnceLock::new();

fn async_dns_w() -> &'static Mutex<HashMap<usize, AsyncDnsWContext>> {
    ASYNC_DNS_W.get_or_init(|| Mutex::new(HashMap::new()))
}

fn async_dns_a() -> &'static Mutex<HashMap<usize, AsyncDnsAContext>> {
    ASYNC_DNS_A.get_or_init(|| Mutex::new(HashMap::new()))
}

fn async_dns_ex() -> &'static Mutex<HashMap<usize, AsyncDnsExContext>> {
    ASYNC_DNS_EX.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe extern "system" fn async_dns_w_complete(error: u32, bytes: u32, overlapped: *mut c_void) {
    if let Some(context) = async_dns_w().lock().remove(&(overlapped as usize)) {
        if let Some(callback) = context.callback {
            (callback)(error, bytes, overlapped);
        }
    }
}

unsafe extern "system" fn async_dns_a_complete(error: u32, bytes: u32, overlapped: *mut c_void) {
    if let Some(context) = async_dns_a().lock().remove(&(overlapped as usize)) {
        if let Some(callback) = context.callback {
            (callback)(error, bytes, overlapped);
        }
    }
}

unsafe extern "system" fn async_dns_ex_complete(
    context: *const c_void,
    results: *mut DNS_QUERY_RESULT,
) {
    if let Some(context) = async_dns_ex().lock().remove(&(context as usize)) {
        (context.callback)(context.original_context, results);
    }
}

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
/// Cancellation flags for ConnectEx operations that are still completing on a worker.
struct ConnectExPending {
    cancelled: AtomicBool,
    completed: AtomicBool,
    overlapped: usize,
    event: HANDLE,
    iocp: Option<(HANDLE, usize)>,
}

static CONNECTEX_PENDING: OnceLock<Mutex<HashMap<(usize, usize), Arc<ConnectExPending>>>> =
    OnceLock::new();

fn connectex_pending() -> &'static Mutex<HashMap<(usize, usize), Arc<ConnectExPending>>> {
    CONNECTEX_PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Mark all queued ConnectEx operations for a socket as cancelled before the OS handle closes.
pub(super) fn cancel_connect_ex(socket: usize) {
    for ((pending_socket, _), pending) in connectex_pending().lock().iter() {
        if *pending_socket == socket {
            pending.cancelled.store(true, Ordering::Release);
            if !pending.completed.swap(true, Ordering::AcqRel) {
                unsafe {
                    let ov = &mut *(pending.overlapped as *mut OVERLAPPED);
                    ov.Internal =
                        windows::Win32::Networking::WinSock::WSA_OPERATION_ABORTED.0 as usize;
                    ov.InternalHigh = 0;
                    if !pending.event.is_invalid() {
                        let _ = SetEvent(pending.event);
                    }
                    if let Some((port, key)) = pending.iocp {
                        let _ = PostQueuedCompletionStatus(port, 0, key, Some(ov));
                    }
                }
            }
        }
    }
}

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
    crate::trace::init_from_env();
    super::udp::init(&config)?;
    let state = HookState::new(config);
    if HOOK_STATE.set(state).is_err() {
        warn!("Hook state already initialized");
    }
    init_original_functions()?;

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
    let _internal = crate::net::InternalNetwork::enter();
    let addr = proxy.resolved_socket_addr()?;
    let sockaddr = socket2::SockAddr::from(addr);
    let ret = original_connect(sock, sockaddr.as_ptr().cast(), sockaddr.len() as i32);
    if ret == SOCKET_ERROR {
        let error = WSAGetLastError().0;
        if error == WSAEWOULDBLOCK.0 || error == WSAEINPROGRESS.0 || error == WSAEALREADY.0 {
            return Ok(());
        }
        if let std::net::SocketAddr::V4(v4) = addr {
            if error == 10047 || error == WSAEINVAL.0 || error == WSAEFAULT.0 {
                let mapped = socket2::SockAddr::from(std::net::SocketAddr::new(
                    v4.ip().to_ipv6_mapped().into(),
                    v4.port(),
                ));
                if original_connect(sock, mapped.as_ptr().cast(), mapped.len() as i32) == 0 {
                    return Ok(());
                }
                let retry = WSAGetLastError().0;
                if retry == WSAEWOULDBLOCK.0 || retry == WSAEINPROGRESS.0 || retry == WSAEALREADY.0
                {
                    return Ok(());
                }
                return Err(Error::Io(std::io::Error::from_raw_os_error(retry)));
            }
        }
        return Err(Error::Io(std::io::Error::from_raw_os_error(error)));
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
    let old_read = stream_ref.read_timeout().map_err(|e| (Error::Io(e), 0))?;
    let old_write = stream_ref.write_timeout().map_err(|e| (Error::Io(e), 0))?;
    struct RestoreTimeouts(
        ManuallyDrop<std::net::TcpStream>,
        Option<std::time::Duration>,
        Option<std::time::Duration>,
    );
    impl Drop for RestoreTimeouts {
        fn drop(&mut self) {
            let _ = self.0.set_read_timeout(self.1);
            let _ = self.0.set_write_timeout(self.2);
        }
    }
    // Restore the exact handle: Winsock duplicated handles can have separate
    // timeout values. ManuallyDrop borrows ownership without closing the socket.
    let _restore = RestoreTimeouts(
        ManuallyDrop::new(std::net::TcpStream::from_raw_socket(sock as u64)),
        old_read,
        old_write,
    );
    stream_ref
        .set_read_timeout(Some(timeout))
        .map_err(|e| (Error::Io(e), 0))?;
    stream_ref
        .set_write_timeout(Some(timeout))
        .map_err(|e| (Error::Io(e), 0))?;

    if selected.len() == 1 {
        if let Err(e) = tunnel_through_proxy(stream_ref, &selected[0], target, target_port, timeout)
        {
            return Err((e, 0));
        }
        return Ok(());
    }

    let mut current = 0usize;
    for next in 1..selected.len() {
        let next_target = TargetAddress::from_domain(selected[next].host.clone());
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

    if let Err(e) =
        tunnel_through_proxy(stream_ref, &selected[current], target, target_port, timeout)
    {
        return Err((e, current));
    }

    Ok(())
}

fn select_indices(state: &HookState, proxies: &[ProxyData]) -> Option<Vec<usize>> {
    let config = state.config.lock().clone();
    let alive_indices: Vec<usize> = proxies
        .iter()
        .enumerate()
        .filter(|(_, p)| p.state == ProxyState::Play && proxy_is_available(p, HealthProtocol::Tcp))
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
            let idx =
                state.load_balance_counter.fetch_add(1, Ordering::Relaxed) % alive_indices.len();
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
pub unsafe extern "system" fn hook_connect_impl(sock: usize, addr: *const c_void, len: i32) -> i32 {
    if crate::net::is_internal_network() {
        return original_connect(sock, addr, len);
    }
    if let Some(result) = super::udp_windows::connect(sock, addr, len) {
        return result;
    }
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
    let started = std::time::Instant::now();
    debug!(
        "hook_connect_impl intercepted target {}:{}",
        target_ip, target_port
    );

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
    let target_label = target_domain.as_deref().unwrap_or("ip").to_string();

    let route_action =
        config.route_action(RouteProtocol::Tcp, target_domain.as_deref(), final_port);
    if route_action == RouteAction::Reject {
        WSASetLastError(WSAEACCES.0);
        return SOCKET_ERROR;
    }
    if route_action == RouteAction::Direct
        || (route_action == RouteAction::Proxy && config.should_bypass_ip(&final_ip))
    {
        return original_connect(sock, addr, len);
    }

    let target = if let Some(ref domain) = target_domain {
        TargetAddress::from_both(final_ip, domain.clone())
    } else {
        TargetAddress::from_ip(final_ip)
    };

    // A failed handshake has already connected this application-owned socket.
    // It cannot safely be reconnected to another proxy; let the application retry
    // using a fresh socket, with failed-node state retained for selection.
    let route_group = config
        .route_proxy_group(RouteProtocol::Tcp, target_domain.as_deref(), final_port)
        .map(str::to_string);
    let route_proxies = if let Some(group) = route_group.as_deref() {
        let Some(proxies) = config.proxy_groups.get(group) else {
            WSASetLastError(WSAECONNREFUSED.0);
            return SOCKET_ERROR;
        };
        Some(proxies.clone())
    } else {
        None
    };
    let max_attempts = 1;
    for attempt in 1..=max_attempts {
        let (selected_indices, selected_proxies) = if let Some(proxies) = route_proxies.as_ref() {
            let Some(indices) = select_indices(state, proxies) else {
                WSASetLastError(WSAECONNREFUSED.0);
                return SOCKET_ERROR;
            };
            let chosen = indices
                .iter()
                .map(|&i| proxies[i].clone())
                .collect::<Vec<_>>();
            (indices, chosen)
        } else {
            let proxies = state.proxy_states.lock();
            let Some(indices) = select_indices(state, &proxies) else {
                WSASetLastError(WSAECONNREFUSED.0);
                return SOCKET_ERROR;
            };
            let chosen = indices
                .iter()
                .map(|&i| proxies[i].clone())
                .collect::<Vec<_>>();
            (indices, chosen)
        };
        match connect_chain_on_socket(
            sock,
            &selected_proxies,
            &target,
            final_port,
            config.tcp_read_timeout,
        ) {
            Ok(()) => {
                for proxy in &selected_proxies {
                    mark_proxy_success(proxy, HealthProtocol::Tcp);
                }
                crate::trace::record(crate::trace::ConnectionEvent {
                    schema_version: "1.0",
                    timestamp_ms: crate::trace::now_ms(),
                    pid: crate::trace::process_id(),
                    process: crate::trace::process_name(),
                    session_id: crate::trace::session_id(),
                    event: "connect",
                    protocol: "tcp",
                    target: &target_label,
                    port: final_port,
                    proxy: None,
                    stage: "target",
                    ok: true,
                    elapsed_ms: Some(started.elapsed().as_millis()),
                    error: None,
                });
                return 0;
            }
            Err((e, failed_hop)) => {
                let failed_proxy_global = selected_indices
                    .get(failed_hop)
                    .or_else(|| selected_indices.last())
                    .copied();
                if let Some(idx) = failed_proxy_global {
                    if route_proxies.is_some() {
                        if let Some(p) = selected_proxies.get(failed_hop) {
                            if !matches!(e, Error::Blocked) {
                                mark_proxy_failure(
                                    p,
                                    HealthProtocol::Tcp,
                                    config.proxy_health_cooldown,
                                );
                            }
                        }
                    } else {
                        let mut proxies = state.proxy_states.lock();
                        if let Some(p) = proxies.get_mut(idx) {
                            p.state = if matches!(e, Error::Blocked) {
                                ProxyState::Blocked
                            } else {
                                mark_proxy_failure(
                                    p,
                                    HealthProtocol::Tcp,
                                    config.proxy_health_cooldown,
                                );
                                ProxyState::Down
                            };
                        }
                    }
                }
                warn!("connect attempt {}/{} failed: {}", attempt, max_attempts, e);
            }
        }
    }

    crate::trace::record(crate::trace::ConnectionEvent {
        schema_version: "1.0",
        timestamp_ms: crate::trace::now_ms(),
        pid: crate::trace::process_id(),
        process: crate::trace::process_name(),
        session_id: crate::trace::session_id(),
        event: "connect",
        protocol: "tcp",
        target: &target_label,
        port: final_port,
        proxy: None,
        stage: "target",
        ok: false,
        elapsed_ms: Some(started.elapsed().as_millis()),
        error: Some("proxy chain connection failed"),
    });
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
const WSAID_WSARECVMSG: GUID = GUID::from_u128(0xf689d7c8_6f1f_436b_8a53_e54fe351c322);

/// ConnectEx replacement used when applications query extension function pointers via WSAIoctl.
///
/// It preserves synchronous ConnectEx when no OVERLAPPED is supplied. With an
/// OVERLAPPED, proxy establishment and the optional initial send run on a
/// worker and complete through the caller's event and/or IOCP association.
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

    if overlapped.is_null() {
        return connect_ex_sync(sock, name, namelen, send_buf, send_len, bytes_sent);
    }
    if name.is_null() || namelen <= 0 {
        WSASetLastError(WSAEINVAL.0);
        return 0;
    }
    let name_bytes = std::slice::from_raw_parts(name.cast::<u8>(), namelen as usize).to_vec();
    let send_bytes = if send_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(send_buf.cast::<u8>(), send_len as usize).to_vec()
    };
    let overlapped_ptr = overlapped as usize;
    let bytes_sent_ptr = bytes_sent as usize;
    let iocp = super::udp_windows::iocp_for(sock);
    let ov = &mut *(overlapped as *mut OVERLAPPED);
    let pending_key = (sock, overlapped_ptr);
    let pending = Arc::new(ConnectExPending {
        cancelled: AtomicBool::new(false),
        completed: AtomicBool::new(false),
        overlapped: overlapped_ptr,
        event: ov.hEvent,
        iocp,
    });
    connectex_pending()
        .lock()
        .insert(pending_key, pending.clone());
    ov.Internal = 0x103;
    ov.InternalHigh = 0;
    let spawned = std::thread::Builder::new()
        .name("proxychains-connectex".to_string())
        .spawn(move || unsafe {
            let result =
                hook_connect_impl(sock, name_bytes.as_ptr().cast(), name_bytes.len() as i32);
            let mut status = 0usize;
            let mut bytes = 0usize;
            if pending.cancelled.load(Ordering::Acquire) {
                status = windows::Win32::Networking::WinSock::WSA_OPERATION_ABORTED.0 as usize;
            } else if result == SOCKET_ERROR {
                status = WSAGetLastError().0 as usize;
            } else if !send_bytes.is_empty() {
                let sent = send(SOCKET(sock), &send_bytes, SEND_RECV_FLAGS(0));
                if sent == SOCKET_ERROR {
                    status = WSAGetLastError().0 as usize;
                } else {
                    bytes = sent as usize;
                }
            }
            if pending.cancelled.load(Ordering::Acquire) {
                status = windows::Win32::Networking::WinSock::WSA_OPERATION_ABORTED.0 as usize;
                bytes = 0;
            }
            if !pending.completed.swap(true, Ordering::AcqRel) {
                if bytes_sent_ptr != 0 {
                    *(bytes_sent_ptr as *mut u32) = bytes as u32;
                }
                let ov = &mut *(overlapped_ptr as *mut OVERLAPPED);
                ov.Internal = status;
                ov.InternalHigh = bytes;
                if !ov.hEvent.is_invalid() {
                    let _ = SetEvent(ov.hEvent);
                }
                if let Some((port, key)) = pending.iocp {
                    let _ = PostQueuedCompletionStatus(port, bytes as u32, key, Some(ov));
                }
            }
            connectex_pending().lock().remove(&pending_key);
        });
    if spawned.is_err() {
        connectex_pending().lock().remove(&pending_key);
        WSASetLastError(WSAEWOULDBLOCK.0);
        return 0;
    }
    WSASetLastError(WSA_IO_PENDING.0);
    0
}

#[cfg(windows)]
unsafe fn connect_ex_sync(
    sock: usize,
    name: *const c_void,
    namelen: i32,
    send_buf: *const c_void,
    send_len: u32,
    bytes_sent: *mut u32,
) -> i32 {
    let ret = hook_connect_impl(sock, name, namelen);
    if ret == SOCKET_ERROR {
        return 0;
    }
    if send_len > 0 {
        let send_slice = std::slice::from_raw_parts(send_buf.cast::<u8>(), send_len as usize);
        let sent = send(SOCKET(sock), send_slice, SEND_RECV_FLAGS(0));
        if sent == SOCKET_ERROR {
            return 0;
        }
        if !bytes_sent.is_null() {
            *bytes_sent = sent as u32;
        }
    }
    1
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
    if io_control_code == SIO_GET_EXTENSION_FUNCTION_POINTER
        && !in_buffer.is_null()
        && in_buffer_len >= std::mem::size_of::<GUID>() as u32
    {
        let requested = *(in_buffer as *const GUID);
        if requested == WSAID_WSASENDMSG || requested == WSAID_WSARECVMSG {
            if out_buffer.is_null() || out_buffer_len < std::mem::size_of::<*const c_void>() as u32
            {
                WSASetLastError(WSAEFAULT.0);
                return SOCKET_ERROR;
            }
            let replacement = if requested == WSAID_WSASENDMSG {
                super::udp_windows::wsa_sendmsg as *const c_void
            } else {
                super::udp_windows::wsa_recvmsg as *const c_void
            };
            std::ptr::copy_nonoverlapping(
                &replacement as *const *const c_void as *const u8,
                out_buffer as *mut u8,
                std::mem::size_of::<*const c_void>(),
            );
            if !bytes_returned.is_null() {
                *bytes_returned = std::mem::size_of::<*const c_void>() as u32;
            }
            return 0;
        }
    }

    if super::udp::enabled(sock)
        && (io_control_code == SIO_GET_EXTENSION_FUNCTION_POINTER
            || io_control_code
                == windows::Win32::Networking::WinSock::SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER)
    {
        // Do not expose unwrapped message or registered-I/O entry points.
        WSASetLastError(windows::Win32::Networking::WinSock::WSAEOPNOTSUPP.0);
        return SOCKET_ERROR;
    }
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
    if crate::net::is_internal_network() {
        return original_getaddrinfo(pnode, pservice, phints, ppresult);
    }
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
            error!(
                "Failed to resolve {} in hook_getaddrinfo_impl: {}",
                hostname, e
            );
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
    if crate::net::is_internal_network() {
        return original_getaddrinfow(pnode, pservice, phints, ppresult);
    }
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
            error!(
                "Failed to resolve {} in hook_getaddrinfow_impl: {}",
                hostname, e
            );
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

    debug!(
        "Assigned fake IP {} for {} (GetAddrInfoW)",
        fake_ip, hostname
    );
    0
}

#[cfg(windows)]
unsafe fn hook_getaddrinfoexw_async(
    config: &Config,
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
    if pname.is_null() {
        return WSAEINVAL.0;
    }
    let hostname = match parse_wide_string(pname) {
        Ok(value) => value,
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
    let fake_ip =
        match DnsResolver::new(config.proxy_dns, config.remote_dns_subnet).resolve(&hostname) {
            Ok(ip) => ip,
            Err(_) => return WSAHOST_NOT_FOUND.0,
        };
    let fake_name: Vec<u16> = fake_ip
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let callback = (!completion_routine.is_null())
        .then(|| mem::transmute::<*mut c_void, LookupCompletionRoutine>(completion_routine));
    let key = overlapped as usize;
    let mut contexts = async_dns_w().lock();
    contexts.insert(
        key,
        AsyncDnsWContext {
            fake_name,
            callback,
        },
    );
    let fake_ptr = contexts
        .get(&key)
        .expect("inserted async DNS context")
        .fake_name
        .as_ptr();
    drop(contexts);
    let result = original_getaddrinfoexw(
        fake_ptr,
        pservice,
        namespace,
        pnspid,
        hints,
        ppresult,
        timeout,
        overlapped,
        if callback.is_some() {
            async_dns_w_complete as *mut c_void
        } else {
            std::ptr::null_mut()
        },
        pname_handle,
    );
    if result != 0 && result != WSA_IO_PENDING.0 {
        async_dns_w().lock().remove(&key);
    }
    result
}

#[cfg(windows)]
unsafe fn hook_getaddrinfoexa_async(
    config: &Config,
    pname: *const i8,
    pservice: *const i8,
    namespace: u32,
    pnspid: *mut c_void,
    hints: *const c_void,
    ppresult: *mut *mut c_void,
    timeout: *mut c_void,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
    pname_handle: *mut c_void,
) -> i32 {
    if pname.is_null() {
        return WSAEINVAL.0;
    }
    let hostname = match CStr::from_ptr(pname).to_str() {
        Ok(value) if !value.is_empty() => value,
        _ => return WSAEINVAL.0,
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_getaddrinfoexa(
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
    let fake_ip =
        match DnsResolver::new(config.proxy_dns, config.remote_dns_subnet).resolve(hostname) {
            Ok(ip) => ip,
            Err(_) => return WSAHOST_NOT_FOUND.0,
        };
    let fake_name = match CString::new(fake_ip.to_string()) {
        Ok(value) => value,
        Err(_) => return WSAEINVAL.0,
    };
    let callback = (!completion_routine.is_null())
        .then(|| mem::transmute::<*mut c_void, LookupCompletionRoutine>(completion_routine));
    let key = overlapped as usize;
    let mut contexts = async_dns_a().lock();
    contexts.insert(
        key,
        AsyncDnsAContext {
            fake_name,
            callback,
        },
    );
    let fake_ptr = contexts
        .get(&key)
        .expect("inserted async DNS context")
        .fake_name
        .as_ptr();
    drop(contexts);
    let result = original_getaddrinfoexa(
        fake_ptr,
        pservice,
        namespace,
        pnspid,
        hints,
        ppresult,
        timeout,
        overlapped,
        if callback.is_some() {
            async_dns_a_complete as *mut c_void
        } else {
            std::ptr::null_mut()
        },
        pname_handle,
    );
    if result != 0 && result != WSA_IO_PENDING.0 {
        async_dns_a().lock().remove(&key);
    }
    result
}

/// Release event-based async DNS fake names after the caller observes completion.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getaddrinfoex_overlapped_result_impl(
    overlapped: *mut c_void,
) -> i32 {
    let result = original_getaddrinfoex_overlapped_result(overlapped);
    if result != WSAEINPROGRESS.0 {
        let key = overlapped as usize;
        async_dns_w().lock().remove(&key);
        async_dns_a().lock().remove(&key);
    }
    result
}

/// Windows DnsQueryEx hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_dns_query_ex_impl(
    request: *const c_void,
    results: *mut c_void,
    cancel: *mut c_void,
) -> i32 {
    let Some(state) = get_hook_state() else {
        return original_dns_query_ex(request as *const _ as *const c_void, results, cancel);
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns || request.is_null() || results.is_null() {
        return original_dns_query_ex(request, results, cancel);
    }
    let request = &*(request as *const DNS_QUERY_REQUEST);
    if request.QueryName.0.is_null() {
        return original_dns_query_ex(request as *const _ as *const c_void, results, cancel);
    }
    let hostname = match parse_wide_string(request.QueryName.0) {
        Ok(value) => value,
        Err(_) => {
            return original_dns_query_ex(request as *const _ as *const c_void, results, cancel)
        }
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(&hostname).is_some() {
        return original_dns_query_ex(request as *const _ as *const c_void, results, cancel);
    }
    let fake_ip =
        match DnsResolver::new(config.proxy_dns, config.remote_dns_subnet).resolve(&hostname) {
            Ok(ip) => ip,
            Err(_) => return WSAHOST_NOT_FOUND.0,
        };
    let fake_name: Vec<u16> = fake_ip
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut forwarded = *request;
    forwarded.QueryName = windows::core::PCWSTR(fake_name.as_ptr());
    let Some(callback) = request.pQueryCompletionCallback else {
        return original_dns_query_ex(&forwarded as *const _ as *const c_void, results, cancel);
    };
    let mut token = Box::new(0u8);
    let token_ptr = (&mut *token) as *mut u8 as *const c_void;
    forwarded.pQueryContext = token_ptr as *mut c_void;
    forwarded.pQueryCompletionCallback = Some(async_dns_ex_complete);
    async_dns_ex().lock().insert(
        token_ptr as usize,
        AsyncDnsExContext {
            _token: token,
            _fake_name: fake_name,
            original_context: request.pQueryContext,
            callback,
        },
    );
    let result = original_dns_query_ex(&forwarded as *const _ as *const c_void, results, cancel);
    if result != DNS_REQUEST_PENDING {
        async_dns_ex().lock().remove(&(token_ptr as usize));
    }
    result
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
    // Event-based async calls have no completion callback where we can release
    // the owned fake name. Keep those on the system resolver. Callback-based
    // calls are wrapped below and retain the fake name until completion.
    if !overlapped.is_null() {
        return hook_getaddrinfoexw_async(
            &config,
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
    if !completion_routine.is_null() {
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

/// Windows GetAddrInfoExA hook implementation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_getaddrinfoexa_impl(
    pname: *const i8,
    pservice: *const i8,
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
            return original_getaddrinfoexa(
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
        return original_getaddrinfoexa(
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
    if !overlapped.is_null() {
        return hook_getaddrinfoexa_async(
            &config,
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
    if !completion_routine.is_null() {
        return original_getaddrinfoexa(
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
    if pname.is_null() {
        return WSAEINVAL.0;
    }
    let hostname = match CStr::from_ptr(pname).to_str() {
        Ok(value) if !value.is_empty() => value,
        _ => return WSAEINVAL.0,
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(hostname).is_some() {
        return original_getaddrinfoexa(
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
    let fake_ip = match dns_resolver.resolve(hostname) {
        Ok(ip) => ip,
        Err(_) => return WSAHOST_NOT_FOUND.0,
    };
    let fake = match CString::new(fake_ip.to_string()) {
        Ok(value) => value,
        Err(_) => return WSAEINVAL.0,
    };
    original_getaddrinfoexa(
        fake.as_ptr(),
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
// dnsapi.h: DNS_QUERY_ASYNC requests retain the query name until the callback.
// A stack/temporary fake-IP string cannot safely cross that asynchronous boundary.
const DNS_QUERY_ASYNC: u32 = 0x0000_1000;

/// Windows DnsQuery_A hook implementation.
#[cfg(windows)]
unsafe fn hook_dns_query_ansi_impl(
    name: *const i8,
    query_type: u16,
    options: u32,
    extra: *mut c_void,
    result: *mut *mut c_void,
    reserved: *mut c_void,
    original: unsafe fn(*const i8, u16, u32, *mut c_void, *mut *mut c_void, *mut c_void) -> i32,
) -> i32 {
    let state = match get_hook_state() {
        Some(s) => s,
        None => return original(name, query_type, options, extra, result, reserved),
    };
    maybe_reload_config(state);
    let config = state.config.lock().clone();
    if !config.proxy_dns || name.is_null() || options & DNS_QUERY_ASYNC != 0 {
        return original(name, query_type, options, extra, result, reserved);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return DNS_ERROR_RCODE_NAME_ERROR,
    };
    if hostname.parse::<IpAddr>().is_ok() || crate::dns::lookup_in_hosts(hostname).is_some() {
        return original(name, query_type, options, extra, result, reserved);
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
    original(
        fake_ip_c.as_ptr(),
        query_type,
        options,
        extra,
        result,
        reserved,
    )
}

#[cfg(windows)]
pub unsafe extern "system" fn hook_dns_query_a_impl(
    name: *const i8,
    query_type: u16,
    options: u32,
    extra: *mut c_void,
    result: *mut *mut c_void,
    reserved: *mut c_void,
) -> i32 {
    hook_dns_query_ansi_impl(
        name,
        query_type,
        options,
        extra,
        result,
        reserved,
        original_dns_query_a,
    )
}

#[cfg(windows)]
pub unsafe extern "system" fn hook_dns_query_utf8_impl(
    name: *const i8,
    query_type: u16,
    options: u32,
    extra: *mut c_void,
    result: *mut *mut c_void,
    reserved: *mut c_void,
) -> i32 {
    hook_dns_query_ansi_impl(
        name,
        query_type,
        options,
        extra,
        result,
        reserved,
        original_dns_query_utf8,
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
    if !config.proxy_dns || name.is_null() || options & DNS_QUERY_ASYNC != 0 {
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
            error!(
                "Failed to resolve {} in hook_gethostbyname_impl: {}",
                hostname, e
            );
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

    #[test]
    fn test_wsa_ioctl_exposes_synchronous_recvmsg_pointer() {
        let guid = WSAID_WSARECVMSG;
        let mut replacement: *mut c_void = std::ptr::null_mut();
        let mut returned = 0;
        let result = unsafe {
            hook_wsa_ioctl_impl(
                usize::MAX,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&guid as *const GUID).cast_mut().cast(),
                std::mem::size_of::<GUID>() as u32,
                (&mut replacement as *mut *mut c_void).cast(),
                std::mem::size_of::<*mut c_void>() as u32,
                &mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0);
        assert!(!replacement.is_null());
        assert_eq!(returned as usize, std::mem::size_of::<*mut c_void>());
    }

    #[test]
    fn test_wsa_ioctl_exposes_synchronous_sendmsg_pointer() {
        let guid = WSAID_WSASENDMSG;
        let mut replacement: *mut c_void = std::ptr::null_mut();
        let mut returned = 0;
        let result = unsafe {
            hook_wsa_ioctl_impl(
                usize::MAX,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&guid as *const GUID).cast_mut().cast(),
                std::mem::size_of::<GUID>() as u32,
                (&mut replacement as *mut *mut c_void).cast(),
                std::mem::size_of::<*mut c_void>() as u32,
                &mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0);
        assert!(!replacement.is_null());
        assert_eq!(returned as usize, std::mem::size_of::<*mut c_void>());
    }

    #[cfg(windows)]
    #[test]
    fn test_async_dns_callback_releases_owned_context() {
        static CALLED: AtomicBool = AtomicBool::new(false);
        unsafe extern "system" fn callback(_error: u32, _bytes: u32, _overlapped: *mut c_void) {
            CALLED.store(true, Ordering::Release);
        }
        CALLED.store(false, Ordering::Release);
        let key = usize::MAX - 2;
        async_dns_w().lock().insert(
            key,
            AsyncDnsWContext {
                fake_name: vec![b'1' as u16, 0],
                callback: Some(callback),
            },
        );
        unsafe { async_dns_w_complete(0, 0, key as *mut c_void) };
        assert!(CALLED.load(Ordering::Acquire));
        assert!(!async_dns_w().lock().contains_key(&key));
    }

    #[cfg(windows)]
    #[test]
    fn test_dns_query_ex_callback_restores_context_and_releases_owned_name() {
        static CALLED: AtomicBool = AtomicBool::new(false);
        unsafe extern "system" fn callback(
            context: *const c_void,
            _results: *mut DNS_QUERY_RESULT,
        ) {
            assert_eq!(context as usize, 0x1234);
            CALLED.store(true, Ordering::Release);
        }
        CALLED.store(false, Ordering::Release);
        let mut token = Box::new(0u8);
        let key = (&mut *token) as *mut u8 as usize;
        async_dns_ex().lock().insert(
            key,
            AsyncDnsExContext {
                _token: token,
                _fake_name: vec![b'1' as u16, 0],
                original_context: 0x1234usize as *const c_void,
                callback,
            },
        );
        unsafe { async_dns_ex_complete(key as *const c_void, std::ptr::null_mut()) };
        assert!(CALLED.load(Ordering::Acquire));
        assert!(!async_dns_ex().lock().contains_key(&key));
    }

    #[cfg(windows)]
    #[test]
    fn test_connectex_close_marks_pending_completion_aborted() {
        let mut overlapped = OVERLAPPED::default();
        let key = (
            usize::MAX - 1,
            (&mut overlapped as *mut OVERLAPPED) as usize,
        );
        let pending = Arc::new(ConnectExPending {
            cancelled: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            overlapped: key.1,
            event: HANDLE::default(),
            iocp: None,
        });
        connectex_pending().lock().insert(key, pending.clone());
        cancel_connect_ex(key.0);
        assert!(pending.cancelled.load(Ordering::Acquire));
        assert!(pending.completed.load(Ordering::Acquire));
        assert_eq!(
            overlapped.Internal as u32,
            windows::Win32::Networking::WinSock::WSA_OPERATION_ABORTED.0 as u32
        );
        connectex_pending().lock().remove(&key);
    }
}

/// Capture socket-to-IOCP associations for the asynchronous UDP relay.
/// The association is consumed by the UDP interposer to publish proxied
/// send/receive completions through the caller's IOCP. Cancellation ownership
/// is tracked separately per `(socket, OVERLAPPED)` operation.
#[cfg(windows)]
pub unsafe extern "system" fn hook_create_io_completion_port_impl(
    file_handle: HANDLE,
    existing_port: HANDLE,
    completion_key: usize,
    threads: u32,
) -> HANDLE {
    let port = super::interpose_windows::original_create_io_completion_port(
        file_handle,
        existing_port,
        completion_key,
        threads,
    );
    if !file_handle.is_invalid() && !port.is_invalid() {
        super::udp_windows::register_iocp(file_handle.0 as usize, port, completion_key);
    }
    port
}
