//! Shared UDP interception state. Payload I/O stays on the application's socket
//! so poll/select registrations, binding, nonblocking mode and timeouts survive.
use std::collections::HashMap;
use std::io;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use socket2::{SockAddr, Socket, Type};

use crate::config::{Config, ProxyType, RouteAction, RouteProtocol};
use crate::dns::{get_hostname_from_ip, DnsResolver};
use crate::net::{is_internal_network, InternalNetwork};
use crate::proxy::{decode_udp_datagram, encode_udp_datagram, TargetAddress, UdpControl};

#[cfg(unix)]
pub type Handle = std::os::fd::RawFd;
#[cfg(windows)]
pub type Handle = usize;

static CONFIG: OnceLock<Config> = OnceLock::new();
type Sessions = HashMap<Handle, Arc<Mutex<Session>>>;
static SESSIONS: OnceLock<Mutex<Sessions>> = OnceLock::new();

#[derive(Default)]
struct Session {
    association: Option<Arc<UdpControl>>,
    // The application's logical peer, independent of the kernel relay peer.
    peer: Option<SocketAddr>,
}

fn validate(config: &Config) -> crate::Result<()> {
    if config.proxy_udp
        && (config.proxies.len() != 1 || config.proxies[0].proxy_type != ProxyType::Socks5)
    {
        return Err(crate::Error::Config(
            "proxy_udp requires exactly one SOCKS5 proxy (no UDP proxy chains)".into(),
        ));
    }
    Ok(())
}

pub(crate) fn init(config: &Config) -> crate::Result<()> {
    validate(config)?;
    let _ = CONFIG.set(config.clone());
    Ok(())
}

fn sessions() -> &'static Mutex<Sessions> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Borrow a valid OS handle without taking ownership.
pub(crate) unsafe fn socket(handle: Handle) -> ManuallyDrop<Socket> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        ManuallyDrop::new(Socket::from_raw_fd(handle))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawSocket;
        ManuallyDrop::new(Socket::from_raw_socket(handle as _))
    }
}

pub(crate) unsafe fn enabled(handle: Handle) -> bool {
    // Borrowed OwnedFd/OwnedSocket constructors forbid the invalid sentinel.
    #[cfg(unix)]
    if handle < 0 {
        return false;
    }
    #[cfg(windows)]
    if handle == usize::MAX {
        return false;
    }
    CONFIG.get().is_some_and(|c| c.proxy_udp)
        && !is_internal_network()
        && socket(handle).r#type().is_ok_and(|t| t == Type::DGRAM)
        && socket(handle)
            .local_addr()
            .map_or(true, |a| a.as_socket().is_some())
}

fn error(e: crate::Error) -> io::Error {
    match e {
        crate::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::ConnectionAborted, other),
    }
}

pub(crate) fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "UDP socket operation is not supported in proxy_udp mode",
    )
}

fn association(session: &mut Session) -> io::Result<Arc<UdpControl>> {
    if let Some(association) = &session.association {
        association.check_control().map_err(error)?;
        return Ok(association.clone());
    }
    let config = CONFIG.get().unwrap();
    let association = match UdpControl::connect(
        &config.proxies[0],
        config.tcp_connect_timeout,
        config.tcp_read_timeout,
    ) {
        Ok(association) => {
            crate::trace::record(crate::trace::ConnectionEvent {
                schema_version: "1.0",
                timestamp_ms: crate::trace::now_ms(),
                pid: crate::trace::process_id(),
                process: crate::trace::process_name(),
                session_id: crate::trace::session_id(),
                event: "udp_associate",
                protocol: "udp",
                target: "unknown",
                port: 0,
                stage: "udp_associate",
                ok: true,
                elapsed_ms: None,
                error: None,
            });
            association
        }
        Err(error_value) => {
            let message = error_value.to_string();
            crate::trace::record(crate::trace::ConnectionEvent {
                schema_version: "1.0",
                timestamp_ms: crate::trace::now_ms(),
                pid: crate::trace::process_id(),
                process: crate::trace::process_name(),
                session_id: crate::trace::session_id(),
                event: "udp_associate",
                protocol: "udp",
                target: "unknown",
                port: 0,
                stage: "udp_associate",
                ok: false,
                elapsed_ms: None,
                error: Some(&message),
            });
            return Err(error(error_value));
        }
    };
    let association = Arc::new(association);
    session.association = Some(association.clone());
    Ok(association)
}

fn mapped_relay(socket: &Socket, association: &UdpControl) -> io::Result<SocketAddr> {
    let relay = association.relay_addr();
    if socket.local_addr().is_ok_and(|a| a.is_ipv6()) {
        if let SocketAddr::V4(v4) = relay {
            return Ok(SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()));
        }
    }
    Ok(relay)
}

fn target(address: SocketAddr) -> (TargetAddress, u16) {
    let config = CONFIG.get().unwrap();
    let (ip, port) = config.apply_dnat_ip(&address.ip(), address.port());
    let v4 = match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };
    let domain = v4.and_then(|v4| get_hostname_from_ip(&v4));
    (
        domain
            .map(TargetAddress::from_domain)
            .unwrap_or_else(|| TargetAddress::from_ip(ip)),
        port,
    )
}

pub(crate) unsafe fn connect(handle: Handle, address: SocketAddr) -> Option<io::Result<()>> {
    if !enabled(handle) {
        return None;
    }
    let (route_target, route_port) = target(address);
    let action = CONFIG
        .get()
        .map(|config| config.route_action(RouteProtocol::Udp, route_target.domain(), route_port))
        .unwrap_or(RouteAction::Proxy);
    if action == RouteAction::Direct {
        return None;
    }
    if action == RouteAction::Reject {
        return Some(Err(io::Error::new(io::ErrorKind::PermissionDenied, "UDP route rejected by rule")));
    }
    // Never switch an established association to direct I/O on reconnect.
    if CONFIG.get().unwrap().should_bypass_ip(&address.ip())
        && !sessions().lock().contains_key(&handle)
    {
        return None;
    }
    let _internal = InternalNetwork::enter();
    Some((|| {
        let session = sessions().lock().entry(handle).or_default().clone();
        let mut session = session.lock();
        let association = association(&mut session)?;
        let socket = socket(handle);
        socket.connect(&mapped_relay(&socket, &association)?.into())?;
        session.peer = Some(address);
        Ok(())
    })())
}

pub(crate) unsafe fn send(
    handle: Handle,
    data: &[u8],
    address: Option<SocketAddr>,
    flags: i32,
) -> Option<io::Result<usize>> {
    if !enabled(handle) {
        return None;
    }
    let _internal = InternalNetwork::enter();
    let socket = socket(handle);
    let existing = sessions().lock().get(&handle).cloned();
    let peer = existing.as_ref().and_then(|s| s.lock().peer);
    let address = address
        .or(peer)
        .or_else(|| socket.peer_addr().ok()?.as_socket());
    let Some(address) = address else {
        return Some(Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "UDP destination required",
        )));
    };
    let (route_target, route_port) = target(address);
    let action = CONFIG
        .get()
        .map(|config| config.route_action(RouteProtocol::Udp, route_target.domain(), route_port))
        .unwrap_or(RouteAction::Proxy);
    if action == RouteAction::Direct {
        return None;
    }
    if action == RouteAction::Reject {
        return Some(Err(io::Error::new(io::ErrorKind::PermissionDenied, "UDP route rejected by rule")));
    }
    if existing.is_none()
        && action == RouteAction::Proxy
        && CONFIG.get().unwrap().should_bypass_ip(&address.ip())
    {
        return None;
    }
    let (target_label, target_port) = {
        let (target, port) = target(address);
        (target.host(), port)
    };
    let result = (|| {
        // Only normal datagrams/nonblocking sends: MSG_MORE/OOB must not corrupt framing.
        #[cfg(unix)]
        let allowed = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
        #[cfg(windows)]
        let allowed = 0;
        if flags & !allowed != 0 {
            return Err(unsupported());
        }
        let (target, port) = target(address);
        let packet = encode_udp_datagram(&target, port, data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let session = sessions().lock().entry(handle).or_default().clone();
        let association = association(&mut session.lock())?;
        let relay = mapped_relay(&socket, &association)?;
        let sent = match socket.peer_addr() {
            Ok(peer) if peer.as_socket() == Some(relay) => {
                // BSD/macOS rejects sendto with an address on a connected UDP socket.
                socket.send_with_flags(&packet, flags)?
            }
            Ok(_) => return Err(unsupported()), // A pre-existing direct connection.
            Err(_) => socket.send_to_with_flags(&packet, &relay.into(), flags)?,
        };
        if sent != packet.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "partial UDP send"));
        }
        Ok(data.len())
    })();
    match &result {
        Ok(_) => crate::trace::record(crate::trace::ConnectionEvent {
            schema_version: "1.0", timestamp_ms: crate::trace::now_ms(), pid: crate::trace::process_id(),
            process: crate::trace::process_name(), session_id: crate::trace::session_id(),
            event: "udp_send", protocol: "udp", target: &target_label, port: target_port,
            stage: "data", ok: true, elapsed_ms: None, error: None,
        }),
        Err(error_value) => {
            let message = error_value.to_string();
            crate::trace::record(crate::trace::ConnectionEvent {
                schema_version: "1.0", timestamp_ms: crate::trace::now_ms(), pid: crate::trace::process_id(),
                process: crate::trace::process_name(), session_id: crate::trace::session_id(),
                event: "udp_send", protocol: "udp", target: &target_label, port: target_port,
                stage: "data", ok: false, elapsed_ms: None, error: Some(&message),
            });
        }
    }
    Some(result)
}

pub(crate) struct Received {
    pub payload: Vec<u8>,
    pub source: SocketAddr,
}

pub(crate) unsafe fn receive(handle: Handle, flags: i32) -> Option<io::Result<Received>> {
    if !enabled(handle) {
        return None;
    }
    let session = sessions().lock().get(&handle)?.clone();
    let _internal = InternalNetwork::enter();
    Some((|| {
        #[cfg(unix)]
        let allowed = libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC;
        #[cfg(windows)]
        let allowed = windows::Win32::Networking::WinSock::MSG_PEEK.0;
        if flags & !allowed != 0 {
            return Err(unsupported());
        }
        let (association, peer) = {
            let mut session = session.lock();
            (association(&mut session)?, session.peer)
        };
        let socket = socket(handle);
        let relay = mapped_relay(&socket, &association)?;
        let mut packet = vec![MaybeUninit::<u8>::uninit(); 65535];
        #[cfg(unix)]
        let native_flags = flags & !libc::MSG_TRUNC;
        #[cfg(windows)]
        let native_flags = flags;
        loop {
            association.check_control().map_err(error)?;
            let (n, from) = socket.recv_from_with_flags(&mut packet, native_flags)?;
            association.check_control().map_err(error)?;
            let bytes = std::slice::from_raw_parts(packet.as_ptr().cast::<u8>(), n);
            if from.as_socket() == Some(relay) {
                if let Ok((source, port, data)) = decode_udp_datagram(bytes) {
                    let source_ip = match source {
                        TargetAddress::Ip(ip) => Some(ip),
                        TargetAddress::Domain(name) => {
                            DnsResolver::new(true, CONFIG.get().unwrap().remote_dns_subnet)
                                .resolve(&name)
                                .ok()
                                .map(IpAddr::V4)
                        }
                        _ => None,
                    };
                    if let Some(ip) = source_ip {
                        let mut source = SocketAddr::new(ip, port);
                        if let Some(peer) = peer {
                            let (destination, destination_port) = target(peer);
                            // A connected datagram socket accepts replies only from its peer.
                            if destination_port != port
                                || destination.ip().is_some_and(|expected| *expected != ip)
                            {
                                discard_peek(&socket, native_flags, &mut packet)?;
                                continue;
                            }
                            source = peer;
                        } else if socket.local_addr()?.is_ipv6() {
                            if let IpAddr::V4(ip) = ip {
                                source.set_ip(ip.to_ipv6_mapped().into());
                            }
                        }
                        return Ok(Received {
                            payload: data.to_vec(),
                            source,
                        });
                    }
                }
            }
            // RFC 1928: drop unsupported fragments and malformed/foreign packets.
            discard_peek(&socket, native_flags, &mut packet)?;
        }
    })())
}

fn discard_peek(socket: &Socket, flags: i32, packet: &mut [MaybeUninit<u8>]) -> io::Result<()> {
    #[cfg(unix)]
    let peek = libc::MSG_PEEK;
    #[cfg(windows)]
    let peek = windows::Win32::Networking::WinSock::MSG_PEEK.0;
    if flags & peek != 0 {
        socket.recv_from_with_flags(packet, flags & !peek)?;
    }
    Ok(())
}

pub(crate) fn logical_peer(handle: Handle) -> Option<SocketAddr> {
    CONFIG.get()?;
    if is_internal_network() {
        return None;
    }
    sessions().lock().get(&handle).and_then(|s| s.lock().peer)
}

pub(crate) fn forget(handle: Handle) {
    if CONFIG.get().is_none() {
        return;
    }
    if is_internal_network() {
        return;
    }
    let _internal = InternalNetwork::enter();
    let removed = sessions().lock().remove(&handle);
    drop(removed); // Drop control sockets outside the map lock, with recursion suppressed.
}

/// Copy a socket address without reading beyond the caller's declared buffer.
pub(crate) unsafe fn parse_address(
    address: *const std::ffi::c_void,
    len: usize,
) -> Option<SocketAddr> {
    if address.is_null() || len < 2 {
        return None;
    }
    let (_, address) = SockAddr::try_init(|storage, capacity| {
        if len > *capacity as usize {
            return Err(unsupported());
        }
        std::ptr::copy_nonoverlapping(address.cast::<u8>(), storage.cast::<u8>(), len);
        *capacity = len as _;
        Ok(())
    })
    .ok()?;
    let result = address.as_socket()?;
    let required = SockAddr::from(result).len() as usize;
    (len >= required).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyData;

    #[test]
    fn udp_requires_one_socks5_node_only_when_enabled() {
        let mut config = Config::default();
        assert!(validate(&config).is_ok());
        config.proxy_udp = true;
        assert!(validate(&config).is_err());
        config.proxies.push(ProxyData::default());
        assert!(validate(&config).is_ok());
        config.proxies[0].proxy_type = ProxyType::Http;
        assert!(validate(&config).is_err());
        config.proxies[0].proxy_type = ProxyType::Socks5;
        config.proxies.push(ProxyData::default());
        assert!(validate(&config).is_err());
    }

    #[test]
    fn address_parser_rejects_short_buffers() {
        for ip in ["127.0.0.1:443", "[::1]:443"] {
            let address: SocketAddr = ip.parse().unwrap();
            let native = SockAddr::from(address);
            for len in 0..native.len() as usize {
                assert!(unsafe { parse_address(native.as_ptr().cast(), len) }.is_none());
            }
            assert_eq!(
                unsafe { parse_address(native.as_ptr().cast(), native.len() as usize) },
                Some(address)
            );
        }
    }
}
