//! Winsock datagram interposition. Overlapped datagram calls are explicitly
//! rejected until completion ownership, cancellation and IOCP are implemented.
use super::udp;
use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::OnceLock;
use windows::Win32::Networking::WinSock::*;

macro_rules! original {
    ($name:ident, $ty:ident, ($($arg:ty),*) -> $ret:ty) => {
        type $ty = unsafe extern "system" fn($($arg),*) -> $ret;
        static $name: OnceLock<$ty> = OnceLock::new();
    };
}
original!(SENDTO, SendTo, (usize, *const u8, i32, i32, *const c_void, i32) -> i32);
original!(RECVFROM, RecvFrom, (usize, *mut u8, i32, i32, *mut c_void, *mut i32) -> i32);
original!(SEND, Send, (usize, *const u8, i32, i32) -> i32);
original!(RECV, Recv, (usize, *mut u8, i32, i32) -> i32);
original!(CLOSE, Close, (usize) -> i32);
original!(GETPEER, GetPeer, (usize, *mut c_void, *mut i32) -> i32);
original!(WSASENDTO, WsaSendTo, (usize, *const WSABUF, u32, *mut u32, u32, *const c_void, i32, *mut c_void, *mut c_void) -> i32);
original!(WSARECVFROM, WsaRecvFrom, (usize, *const WSABUF, u32, *mut u32, *mut u32, *mut c_void, *mut i32, *mut c_void, *mut c_void) -> i32);
original!(WSASEND, WsaSend, (usize, *const WSABUF, u32, *mut u32, u32, *mut c_void, *mut c_void) -> i32);
original!(WSARECV, WsaRecv, (usize, *const WSABUF, u32, *mut u32, *mut u32, *mut c_void, *mut c_void) -> i32);
original!(WSASENDMSG, WsaSendMsg, (usize, *const c_void, u32, *mut u32, *mut c_void, *mut c_void) -> i32);

pub(super) unsafe fn install() -> crate::Result<()> {
    macro_rules! install {
        ($symbol:literal, $detour:ident, $store:ident, $ty:ty) => {
            let trampoline = minhook::MinHook::create_hook_api(
                "ws2_32.dll",
                $symbol,
                $detour as *const () as *mut c_void,
            )
            .map_err(|e| crate::Error::WindowsApi(format!("UDP hook {}: {e:?}", $symbol)))?;
            let _ = $store.set(std::mem::transmute::<*mut c_void, $ty>(trampoline));
        };
    }
    install!("sendto", sendto, SENDTO, SendTo);
    install!("recvfrom", recvfrom, RECVFROM, RecvFrom);
    install!("send", send, SEND, Send);
    install!("recv", recv, RECV, Recv);
    install!("closesocket", close, CLOSE, Close);
    install!("getpeername", getpeer, GETPEER, GetPeer);
    install!("WSASendTo", wsa_sendto, WSASENDTO, WsaSendTo);
    install!("WSARecvFrom", wsa_recvfrom, WSARECVFROM, WsaRecvFrom);
    install!("WSASend", wsa_send, WSASEND, WsaSend);
    install!("WSARecv", wsa_recv, WSARECV, WsaRecv);
    install!("WSASendMsg", wsa_sendmsg, WSASENDMSG, WsaSendMsg);
    Ok(())
}

unsafe fn fail(error: io::Error) -> i32 {
    let code = error.raw_os_error().unwrap_or(match error.kind() {
        io::ErrorKind::Unsupported => WSAEOPNOTSUPP.0,
        io::ErrorKind::InvalidInput => WSAEMSGSIZE.0,
        io::ErrorKind::NotConnected => WSAEDESTADDRREQ.0,
        _ => WSAECONNABORTED.0,
    });
    WSASetLastError(code);
    SOCKET_ERROR
}

pub(super) unsafe fn connect(sock: usize, addr: *const c_void, len: i32) -> Option<i32> {
    let address = udp::parse_address(addr, usize::try_from(len).ok()?)?;
    udp::connect(sock, address).map(|result| match result {
        Ok(()) => 0,
        Err(e) => fail(e),
    })
}

unsafe fn bytes<'a>(buf: *const u8, len: i32) -> Option<&'a [u8]> {
    if len < 0 || (buf.is_null() && len != 0) {
        None
    } else if len == 0 {
        Some(&[])
    } else {
        Some(std::slice::from_raw_parts(buf, len as usize))
    }
}

unsafe extern "system" fn sendto(
    s: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
    addr: *const c_void,
    addrlen: i32,
) -> i32 {
    if let Some(data) = bytes(buf, len) {
        let address = if addr.is_null() {
            None
        } else {
            udp::parse_address(addr, addrlen.max(0) as usize)
        };
        if addr.is_null() || address.is_some() {
            if let Some(result) = udp::send(s, data, address, flags) {
                return match result {
                    Ok(n) => n as i32,
                    Err(e) => fail(e),
                };
            }
        }
    }
    SENDTO.get().unwrap()(s, buf, len, flags, addr, addrlen)
}

unsafe extern "system" fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    if let Some(data) = bytes(buf, len) {
        if let Some(result) = udp::send(s, data, None, flags) {
            return match result {
                Ok(n) => n as i32,
                Err(e) => fail(e),
            };
        }
    }
    SEND.get().unwrap()(s, buf, len, flags)
}

unsafe fn store_address(
    source: std::net::SocketAddr,
    addr: *mut c_void,
    len: *mut i32,
) -> io::Result<()> {
    if addr.is_null() {
        return Ok(());
    }
    if len.is_null() || *len < 0 {
        return Err(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    let source = socket2::SockAddr::from(source);
    if (*len as u32) < source.len() as u32 {
        return Err(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    ptr::copy_nonoverlapping(
        source.as_ptr().cast::<u8>(),
        addr.cast(),
        source.len() as usize,
    );
    *len = source.len();
    Ok(())
}

unsafe fn receive(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    addr: *mut c_void,
    addrlen: *mut i32,
) -> Option<i32> {
    if bytes(buf, len).is_none() {
        return None;
    }
    if !addr.is_null() && (addrlen.is_null() || *addrlen < 0) {
        return Some(fail(io::Error::from_raw_os_error(WSAEFAULT.0)));
    }
    udp::receive(s, flags).map(|result| match result {
        Err(e) => fail(e),
        Ok(received) => {
            if let Err(e) = store_address(received.source, addr, addrlen) {
                return fail(e);
            }
            let n = (len as usize).min(received.payload.len());
            if n != 0 {
                ptr::copy_nonoverlapping(received.payload.as_ptr(), buf, n);
            }
            if received.payload.len() > len as usize {
                return fail(io::Error::from_raw_os_error(WSAEMSGSIZE.0));
            }
            n as i32
        }
    })
}

unsafe extern "system" fn recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    addr: *mut c_void,
    addrlen: *mut i32,
) -> i32 {
    receive(s, buf, len, flags, addr, addrlen)
        .unwrap_or_else(|| RECVFROM.get().unwrap()(s, buf, len, flags, addr, addrlen))
}
unsafe extern "system" fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    receive(s, buf, len, flags, ptr::null_mut(), ptr::null_mut())
        .unwrap_or_else(|| RECV.get().unwrap()(s, buf, len, flags))
}
unsafe extern "system" fn close(s: usize) -> i32 {
    // Winsock may refuse to close a nonblocking socket with linger enabled.
    let result = CLOSE.get().unwrap()(s);
    if result == 0 {
        udp::forget(s);
    }
    result
}
unsafe extern "system" fn getpeer(s: usize, addr: *mut c_void, len: *mut i32) -> i32 {
    if let Some(peer) = udp::logical_peer(s) {
        if addr.is_null() {
            return fail(io::Error::from_raw_os_error(WSAEFAULT.0));
        }
        return match store_address(peer, addr, len) {
            Ok(()) => 0,
            Err(e) => fail(e),
        };
    }
    GETPEER.get().unwrap()(s, addr, len)
}

unsafe fn buffers<'a>(bufs: *const WSABUF, count: u32) -> io::Result<&'a [WSABUF]> {
    if bufs.is_null() || count == 0 || count > 1024 {
        return Err(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    let bufs = std::slice::from_raw_parts(bufs, count as usize);
    if bufs.iter().any(|b| b.buf.is_null() && b.len != 0) {
        return Err(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    Ok(bufs)
}

unsafe extern "system" fn wsa_sendto(
    s: usize,
    bufs: *const WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    addr: *const c_void,
    addrlen: i32,
    ov: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !udp::enabled(s) {
        return WSASENDTO.get().unwrap()(
            s, bufs, count, sent, flags, addr, addrlen, ov, completion,
        );
    }
    if !ov.is_null() || !completion.is_null() {
        return fail(udp::unsupported());
    }
    if sent.is_null() {
        return fail(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    let bufs = match buffers(bufs, count) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let total: u64 = bufs.iter().map(|b| b.len as u64).sum();
    if total > 65507 {
        return fail(io::Error::from_raw_os_error(WSAEMSGSIZE.0));
    }
    let mut data = Vec::with_capacity(total as usize);
    for b in bufs {
        if b.len != 0 {
            data.extend_from_slice(std::slice::from_raw_parts(b.buf.0, b.len as usize));
        }
    }
    let result = sendto(
        s,
        data.as_ptr(),
        data.len() as i32,
        flags as i32,
        addr,
        addrlen,
    );
    if result < 0 {
        result
    } else {
        *sent = result as u32;
        0
    }
}
unsafe extern "system" fn wsa_send(
    s: usize,
    bufs: *const WSABUF,
    count: u32,
    sent: *mut u32,
    flags: u32,
    ov: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !udp::enabled(s) {
        return WSASEND.get().unwrap()(s, bufs, count, sent, flags, ov, completion);
    }
    wsa_sendto(s, bufs, count, sent, flags, ptr::null(), 0, ov, completion)
}
unsafe extern "system" fn wsa_recvfrom(
    s: usize,
    bufs: *const WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    addr: *mut c_void,
    addrlen: *mut i32,
    ov: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !udp::enabled(s) {
        return WSARECVFROM.get().unwrap()(
            s, bufs, count, received, flags, addr, addrlen, ov, completion,
        );
    }
    if !ov.is_null() || !completion.is_null() {
        return fail(udp::unsupported());
    }
    if received.is_null() || flags.is_null() {
        return fail(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    let slices = match buffers(bufs, count) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    let result = match udp::receive(s, *flags as i32) {
        Some(Ok(result)) => result,
        Some(Err(e)) => return fail(e),
        None => {
            return WSARECVFROM.get().unwrap()(
                s, bufs, count, received, flags, addr, addrlen, ov, completion,
            )
        }
    };
    if let Err(e) = store_address(result.source, addr, addrlen) {
        return fail(e);
    }
    let mut offset = 0;
    for b in slices {
        let n = (b.len as usize).min(result.payload.len() - offset);
        if n != 0 {
            ptr::copy_nonoverlapping(result.payload.as_ptr().add(offset), b.buf.0, n);
        }
        offset += n;
    }
    *received = offset as u32;
    *flags = 0;
    if offset < result.payload.len() {
        fail(io::Error::from_raw_os_error(WSAEMSGSIZE.0))
    } else {
        0
    }
}
unsafe extern "system" fn wsa_recv(
    s: usize,
    bufs: *const WSABUF,
    count: u32,
    received: *mut u32,
    flags: *mut u32,
    ov: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !udp::enabled(s) {
        return WSARECV.get().unwrap()(s, bufs, count, received, flags, ov, completion);
    }
    wsa_recvfrom(
        s,
        bufs,
        count,
        received,
        flags,
        ptr::null_mut(),
        ptr::null_mut(),
        ov,
        completion,
    )
}

unsafe extern "system" fn wsa_sendmsg(
    s: usize,
    msg: *const c_void,
    flags: u32,
    sent: *mut u32,
    ov: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !udp::enabled(s) {
        return WSASENDMSG.get().unwrap()(s, msg, flags, sent, ov, completion);
    }
    // This hook handles the synchronous WSAMSG form. Overlapped completion
    // ownership stays with the application's IOCP and is intentionally
    // rejected until the full asynchronous relay lifecycle is implemented.
    if msg.is_null() || sent.is_null() || !ov.is_null() || !completion.is_null() {
        return fail(udp::unsupported());
    }
    let message = &*(msg.cast::<WSAMSG>());
    if message.Control.len != 0 {
        return fail(udp::unsupported());
    }
    let count = usize::try_from(message.dwBufferCount).ok();
    let Some(count) = count.filter(|&count| count <= 1024) else {
        return fail(io::Error::from_raw_os_error(WSAEMSGSIZE.0));
    };
    if count != 0 && message.lpBuffers.is_null() {
        return fail(io::Error::from_raw_os_error(WSAEFAULT.0));
    }
    let buffers = std::slice::from_raw_parts(message.lpBuffers, count);
    let mut data = Vec::new();
    for buffer in buffers {
        let length = usize::try_from(buffer.len).unwrap_or(usize::MAX);
        if length > 65507usize.saturating_sub(data.len()) || (length != 0 && buffer.buf.is_null()) {
            return fail(io::Error::from_raw_os_error(WSAEMSGSIZE.0));
        }
        let bytes = std::slice::from_raw_parts(buffer.buf.0.cast_const(), length);
        data.extend_from_slice(bytes);
    }
    let address = if message.name.is_null() {
        None
    } else {
        let length = usize::try_from(message.namelen).ok();
        let Some(length) = length else {
            return fail(io::Error::from_raw_os_error(WSAEFAULT.0));
        };
        udp::parse_address(message.name.cast(), length)
    };
    let native_flags = match i32::try_from(flags) {
        Ok(flags) => flags,
        Err(_) => return fail(udp::unsupported()),
    };
    match udp::send(s, &data, address, native_flags) {
        Some(Ok(length)) => {
            *sent = length as u32;
            0
        }
        Some(Err(error)) => fail(error),
        None => WSASENDMSG.get().unwrap()(s, msg, flags, sent, ov, completion),
    }
}
