//! Export libc names from the preload library, forwarding to the core wrappers.
use libc::{c_int, c_void, size_t, sockaddr, socklen_t, ssize_t};
macro_rules! export {
    ($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
            proxychains::hook::udp_unix::$name($($arg),*)
        }
    };
}
export!(sendto(s: c_int, buf: *const c_void, len: size_t, flags: c_int, addr: *const sockaddr, addrlen: socklen_t) -> ssize_t);
export!(recvfrom(s: c_int, buf: *mut c_void, len: size_t, flags: c_int, addr: *mut sockaddr, addrlen: *mut socklen_t) -> ssize_t);
export!(send(s: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t);
export!(recv(s: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t);
export!(read(s: c_int, buf: *mut c_void, len: size_t) -> ssize_t);
export!(write(s: c_int, buf: *const c_void, len: size_t) -> ssize_t);
export!(close(s: c_int) -> c_int);
export!(getpeername(s: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int);
export!(sendmsg(s: c_int, msg: *const libc::msghdr, flags: c_int) -> ssize_t);
export!(recvmsg(s: c_int, msg: *mut libc::msghdr, flags: c_int) -> ssize_t);
export!(readv(s: c_int, iov: *const libc::iovec, len: c_int) -> ssize_t);
export!(writev(s: c_int, iov: *const libc::iovec, len: c_int) -> ssize_t);
#[cfg(target_os = "linux")]
export!(sendmmsg(s: c_int, msgs: *mut libc::mmsghdr, count: libc::c_uint, flags: c_int) -> c_int);
#[cfg(target_os = "linux")]
export!(recvmmsg(s: c_int, msgs: *mut libc::mmsghdr, count: libc::c_uint, flags: c_int, timeout: *mut libc::timespec) -> c_int);
