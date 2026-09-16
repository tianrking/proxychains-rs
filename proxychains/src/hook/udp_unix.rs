//! libc datagram wrappers. All fallbacks resolve RTLD_NEXT, never our own exports.
use super::udp;
use libc::{c_int, c_void, size_t, sockaddr, socklen_t, ssize_t};
use std::{io, ptr};

macro_rules! original {
    ($name:literal, ($($arg:ty),*) -> $ret:ty) => {{
        type Function = unsafe extern "C" fn($($arg),*) -> $ret;
        static ORIGINAL: std::sync::OnceLock<Function> = std::sync::OnceLock::new();
        *ORIGINAL.get_or_init(|| super::interpose::load_symbol($name).expect(concat!("libc symbol ", $name)))
    }};
}

unsafe fn fail(error: io::Error) -> ssize_t {
    let errno = error.raw_os_error().unwrap_or(match error.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::InvalidInput => libc::EMSGSIZE,
        io::ErrorKind::NotConnected => libc::EDESTADDRREQ,
        _ => libc::ECONNABORTED,
    });
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location() = errno;
    }
    #[cfg(not(target_os = "linux"))]
    {
        *libc::__error() = errno;
    }
    -1
}

pub(super) unsafe fn connect(s: c_int, addr: *const sockaddr, len: socklen_t) -> Option<c_int> {
    if udp::enabled(s)
        && !addr.is_null()
        && len as usize >= std::mem::size_of::<libc::sa_family_t>()
        && (*addr).sa_family as c_int == libc::AF_UNSPEC
    {
        // Keep the association on disconnect; subsequent send() still needs a destination.
        // Reconnecting to another destination is supported; AF_UNSPEC is explicit for now.
        return Some(fail(udp::unsupported()) as c_int);
    }
    let addr = udp::parse_address(addr.cast(), len as usize)?;
    udp::connect(s, addr).map(|result| match result {
        Ok(()) => 0,
        Err(e) => fail(e) as c_int,
    })
}

unsafe fn bytes<'a>(buf: *const c_void, len: usize) -> Option<&'a [u8]> {
    if len > isize::MAX as usize || (buf.is_null() && len != 0) {
        None
    } else if len == 0 {
        Some(&[])
    } else {
        Some(std::slice::from_raw_parts(buf.cast(), len))
    }
}

pub unsafe fn sendto(
    s: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> ssize_t {
    if let Some(data) = bytes(buf, len) {
        let address = udp::parse_address(addr.cast(), addrlen as usize);
        if addr.is_null() || address.is_some() {
            if let Some(result) = udp::send(s, data, address, flags) {
                return match result {
                    Ok(n) => n as ssize_t,
                    Err(e) => fail(e),
                };
            }
        }
    }
    original!("sendto", (c_int, *const c_void, size_t, c_int, *const sockaddr, socklen_t) -> ssize_t)(
        s, buf, len, flags, addr, addrlen,
    )
}

pub unsafe fn send(s: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    if let Some(data) = bytes(buf, len) {
        if let Some(result) = udp::send(s, data, None, flags) {
            return match result {
                Ok(n) => n as ssize_t,
                Err(e) => fail(e),
            };
        }
    }
    original!("send", (c_int, *const c_void, size_t, c_int) -> ssize_t)(s, buf, len, flags)
}

unsafe fn store_address(source: std::net::SocketAddr, addr: *mut sockaddr, len: *mut socklen_t) {
    if addr.is_null() {
        return;
    }
    let source = socket2::SockAddr::from(source);
    ptr::copy_nonoverlapping(
        source.as_ptr().cast::<u8>(),
        addr.cast(),
        (*len).min(source.len()) as usize,
    );
    *len = source.len();
}

unsafe fn receive(
    s: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> Option<ssize_t> {
    if bytes(buf, len).is_none() {
        return None;
    }
    if !addr.is_null() && addrlen.is_null() {
        return Some(fail(io::Error::from_raw_os_error(libc::EFAULT)));
    }
    udp::receive(s, flags).map(|result| match result {
        Err(e) => fail(e),
        Ok(received) => {
            store_address(received.source, addr, addrlen);
            let n = len.min(received.payload.len());
            if n != 0 {
                ptr::copy_nonoverlapping(received.payload.as_ptr(), buf.cast(), n);
            }
            if flags & libc::MSG_TRUNC != 0 {
                received.payload.len() as ssize_t
            } else {
                n as ssize_t
            }
        }
    })
}

pub unsafe fn recvfrom(
    s: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> ssize_t {
    receive(s, buf, len, flags, addr, addrlen).unwrap_or_else(|| original!("recvfrom", (c_int, *mut c_void, size_t, c_int, *mut sockaddr, *mut socklen_t) -> ssize_t)(s, buf, len, flags, addr, addrlen))
}
pub unsafe fn recv(s: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    receive(s, buf, len, flags, ptr::null_mut(), ptr::null_mut()).unwrap_or_else(|| {
        original!("recv", (c_int, *mut c_void, size_t, c_int) -> ssize_t)(s, buf, len, flags)
    })
}
pub unsafe fn read(s: c_int, buf: *mut c_void, len: size_t) -> ssize_t {
    receive(s, buf, len, 0, ptr::null_mut(), ptr::null_mut())
        .unwrap_or_else(|| original!("read", (c_int, *mut c_void, size_t) -> ssize_t)(s, buf, len))
}
pub unsafe fn write(s: c_int, buf: *const c_void, len: size_t) -> ssize_t {
    if udp::enabled(s) {
        return send(s, buf, len, 0);
    }
    original!("write", (c_int, *const c_void, size_t) -> ssize_t)(s, buf, len)
}
pub unsafe fn close(s: c_int) -> c_int {
    // Remove before close so immediate descriptor reuse cannot see stale state.
    udp::forget(s);
    original!("close", (c_int) -> c_int)(s)
}

fn copy_session(oldfd: c_int, newfd: c_int) {
    udp::duplicate_session(oldfd, newfd);
}

pub unsafe fn dup(oldfd: c_int) -> c_int {
    let newfd = original!("dup", (c_int) -> c_int)(oldfd);
    if newfd >= 0 {
        copy_session(oldfd, newfd);
    }
    newfd
}

pub unsafe fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    if oldfd != newfd {
        udp::remove_session(newfd);
    }
    let result = original!("dup2", (c_int, c_int) -> c_int)(oldfd, newfd);
    if result >= 0 && oldfd != newfd {
        copy_session(oldfd, result);
    }
    result
}

#[cfg(target_os = "linux")]
pub unsafe fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
    if oldfd != newfd {
        udp::remove_session(newfd);
    }
    let result = original!("dup3", (c_int, c_int, c_int) -> c_int)(oldfd, newfd, flags);
    if result >= 0 && oldfd != newfd {
        copy_session(oldfd, result);
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub unsafe fn fcntl(s: c_int, command: c_int, argument: *mut c_void) -> c_int {
    let result = original!("fcntl", (c_int, c_int, *mut c_void) -> c_int)(s, command, argument);
    if result >= 0
        && (command == libc::F_DUPFD || command == libc::F_DUPFD_CLOEXEC)
    {
        copy_session(s, result);
    }
    result
}

pub unsafe fn getpeername(s: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    if let Some(peer) = udp::logical_peer(s) {
        if addr.is_null() || len.is_null() {
            return fail(io::Error::from_raw_os_error(libc::EFAULT)) as c_int;
        }
        store_address(peer, addr, len);
        return 0;
    }
    original!("getpeername", (c_int, *mut sockaddr, *mut socklen_t) -> c_int)(s, addr, len)
}

unsafe fn iovecs<'a>(iov: *const libc::iovec, len: usize) -> io::Result<&'a [libc::iovec]> {
    if len > 1024 || (iov.is_null() && len != 0) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if len == 0 {
        return Ok(&[]);
    }
    let iov = std::slice::from_raw_parts(iov, len);
    if iov.iter().any(|v| bytes(v.iov_base, v.iov_len).is_none()) {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    Ok(iov)
}

pub unsafe fn sendmsg(s: c_int, msg: *const libc::msghdr, flags: c_int) -> ssize_t {
    if !udp::enabled(s) || msg.is_null() {
        return original!("sendmsg", (c_int, *const libc::msghdr, c_int) -> ssize_t)(s, msg, flags);
    }
    let msg = &*msg;
    // Ancillary destination/interface/GSO data cannot be forwarded unchanged to the relay.
    if msg.msg_controllen != 0 {
        return fail(udp::unsupported());
    }
    let iov = match iovecs(msg.msg_iov, msg.msg_iovlen as usize) {
        Ok(iov) => iov,
        Err(e) => return fail(e),
    };
    let total = iov
        .iter()
        .try_fold(0usize, |sum, v| sum.checked_add(v.iov_len));
    let Some(total) = total.filter(|&n| n <= 65507) else {
        return fail(io::Error::from_raw_os_error(libc::EMSGSIZE));
    };
    let mut data = Vec::with_capacity(total);
    for v in iov {
        data.extend_from_slice(bytes(v.iov_base, v.iov_len).unwrap());
    }
    sendto(
        s,
        data.as_ptr().cast(),
        data.len(),
        flags,
        msg.msg_name.cast(),
        msg.msg_namelen,
    )
}
pub unsafe fn recvmsg(s: c_int, msg: *mut libc::msghdr, flags: c_int) -> ssize_t {
    if !udp::enabled(s) || msg.is_null() {
        return original!("recvmsg", (c_int, *mut libc::msghdr, c_int) -> ssize_t)(s, msg, flags);
    }
    let header = &mut *msg;
    let iov = match iovecs(header.msg_iov, header.msg_iovlen as usize) {
        Ok(iov) => iov,
        Err(e) => return fail(e),
    };
    let result = match udp::receive(s, flags) {
        Some(Ok(result)) => result,
        Some(Err(e)) => return fail(e),
        None => {
            return original!("recvmsg", (c_int, *mut libc::msghdr, c_int) -> ssize_t)(
                s, msg, flags,
            )
        }
    };
    store_address(
        result.source,
        header.msg_name.cast(),
        &mut header.msg_namelen,
    );
    let mut offset = 0;
    for v in iov {
        let n = v.iov_len.min(result.payload.len() - offset);
        if n != 0 {
            ptr::copy_nonoverlapping(result.payload.as_ptr().add(offset), v.iov_base.cast(), n);
        }
        offset += n;
    }
    header.msg_flags = if offset < result.payload.len() {
        libc::MSG_TRUNC
    } else {
        0
    };
    // Relay packet metadata describes the relay, not the original sender.
    if header.msg_controllen != 0 {
        header.msg_flags |= libc::MSG_CTRUNC;
    }
    header.msg_controllen = 0;
    if flags & libc::MSG_TRUNC != 0 {
        result.payload.len() as ssize_t
    } else {
        offset as ssize_t
    }
}
pub unsafe fn writev(s: c_int, iov: *const libc::iovec, len: c_int) -> ssize_t {
    if !udp::enabled(s) || len < 0 {
        return original!("writev", (c_int, *const libc::iovec, c_int) -> ssize_t)(s, iov, len);
    }
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = iov.cast_mut();
    msg.msg_iovlen = len as _;
    sendmsg(s, &msg, 0)
}
pub unsafe fn readv(s: c_int, iov: *const libc::iovec, len: c_int) -> ssize_t {
    if !udp::enabled(s) || len < 0 {
        return original!("readv", (c_int, *const libc::iovec, c_int) -> ssize_t)(s, iov, len);
    }
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = iov.cast_mut();
    msg.msg_iovlen = len as _;
    recvmsg(s, &mut msg, 0)
}

#[cfg(target_os = "linux")]
pub unsafe fn sendmmsg(
    s: c_int,
    msgs: *mut libc::mmsghdr,
    count: libc::c_uint,
    flags: c_int,
) -> c_int {
    if !udp::enabled(s) {
        return original!("sendmmsg", (c_int, *mut libc::mmsghdr, libc::c_uint, c_int) -> c_int)(
            s, msgs, count, flags,
        );
    }
    if msgs.is_null() || count > 1024 {
        return fail(io::Error::from_raw_os_error(libc::EINVAL)) as c_int;
    }
    for i in 0..count as usize {
        let msg = &mut *msgs.add(i);
        let n = sendmsg(s, &msg.msg_hdr, flags);
        if n < 0 {
            return if i == 0 { -1 } else { i as c_int };
        }
        msg.msg_len = n as _;
    }
    count as c_int
}
#[cfg(target_os = "linux")]
pub unsafe fn recvmmsg(
    s: c_int,
    msgs: *mut libc::mmsghdr,
    count: libc::c_uint,
    flags: c_int,
    timeout: *mut libc::timespec,
) -> c_int {
    if !udp::enabled(s) {
        return original!("recvmmsg", (c_int, *mut libc::mmsghdr, libc::c_uint, c_int, *mut libc::timespec) -> c_int)(
            s, msgs, count, flags, timeout,
        );
    }
    // Timed batches need a shared deadline; do not silently change timeout semantics.
    if !timeout.is_null() || msgs.is_null() || count > 1024 {
        return fail(udp::unsupported()) as c_int;
    }
    for i in 0..count as usize {
        let msg = &mut *msgs.add(i);
        let mut receive_flags = flags & !libc::MSG_WAITFORONE;
        if i > 0 && flags & libc::MSG_WAITFORONE != 0 {
            receive_flags |= libc::MSG_DONTWAIT;
        }
        let n = recvmsg(s, &mut msg.msg_hdr, receive_flags);
        if n < 0 {
            return if i == 0 { -1 } else { i as c_int };
        }
        msg.msg_len = n as _;
    }
    count as c_int
}
