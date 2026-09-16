//! dyld binds two-level namespace imports using explicit interpose tuples.
//! Keep replacement symbols distinct from libc to avoid replacing ourselves.
//! Layout follows Apple's mach-o/dyld-interposing.h.
use std::ffi::c_void;

extern "C" {
    fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent;
    fn proxychains_fcntl(fd: libc::c_int, command: libc::c_int, ...) -> libc::c_int;
}

#[repr(C)]
struct Interpose {
    replacement: *const c_void,
    original: *const c_void,
}
// These immutable pointers refer to functions retained for the image lifetime.
unsafe impl Sync for Interpose {}

macro_rules! interpose {
    ($module:ident, $name:ident) => {
        Interpose {
            replacement: crate::$module::$name as *const () as *const c_void,
            original: libc::$name as *const () as *const c_void,
        }
    };
}

#[used]
#[link_section = "__DATA,__interpose,interposing"]
static INTERPOSE: [Interpose; 18] = [
    interpose!(unix_impl, connect),
    interpose!(unix_impl, getaddrinfo),
    interpose!(unix_impl, freeaddrinfo),
    Interpose {
        replacement: crate::unix_impl::gethostbyname as *const () as *const c_void,
        original: gethostbyname as *const () as *const c_void,
    },
    interpose!(unix_impl, getnameinfo),
    interpose!(udp_exports, sendto),
    interpose!(udp_exports, recvfrom),
    interpose!(udp_exports, send),
    interpose!(udp_exports, recv),
    interpose!(udp_exports, read),
    interpose!(udp_exports, write),
    interpose!(udp_exports, close),
    Interpose {
        replacement: proxychains_fcntl as *const () as *const c_void,
        original: libc::fcntl as *const () as *const c_void,
    },
    interpose!(udp_exports, getpeername),
    interpose!(udp_exports, sendmsg),
    interpose!(udp_exports, recvmsg),
    interpose!(udp_exports, readv),
    interpose!(udp_exports, writev),
];
