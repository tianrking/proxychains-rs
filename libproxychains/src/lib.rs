//! LD_PRELOAD library for proxychains
//!
//! This library is loaded via LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS)
//! to intercept network system calls and redirect them through proxy chains.

use std::ffi::{c_char, c_int};
use std::os::unix::io::AsRawFd;

use ctor::ctor;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

use proxychains::{
    hook::{
        hook_connect, hook_getaddrinfo, hook_gethostbyname, hook_getnameinfo,
        init_hooks,
    },
    ConfigParser,
};

/// Library initialization
#[ctor]
fn init() {
    // Initialize logging
    let log_level = if std::env::var("PROXYCHAINS_QUIET_MODE").is_ok() {
        Level::ERROR
    } else if std::env::var("PROXYCHAINS_DEBUG").is_ok() {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .compact()
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("libproxychains initializing...");

    // Parse configuration
    let config = match ConfigParser::new().parse() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse configuration: {}", e);
            return;
        }
    };

    debug!(
        "Configuration loaded: {} proxies, chain type: {:?}",
        config.proxies.len(),
        config.chain_type
    );

    // Initialize hooks
    if let Err(e) = init_hooks(config) {
        error!("Failed to initialize hooks: {}", e);
    } else {
        info!("libproxychains initialized successfully");
    }
}

/// Hook for connect() system call
///
/// # Safety
/// This is a C FFI function that makes unsafe operations
#[no_mangle]
pub unsafe extern "C" fn connect(
    sock: c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> c_int {
    proxychains::hook::hook_connect(sock, addr, len)
}

/// Hook for getaddrinfo() system call
///
/// # Safety
/// This is a C FFI function that makes unsafe operations
#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    proxychains::hook::hook_getaddrinfo(node, service, hints, res)
}

/// Hook for freeaddrinfo() system call
///
/// # Safety
/// This is a C FFI function that makes unsafe operations
#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(res: *mut libc::addrinfo) {
    proxychains::hook::hook_freeaddrinfo(res)
}

/// Hook for gethostbyname() system call
///
/// # Safety
/// This is a C FFI function that makes unsafe operations
#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut libc::hostent {
    proxychains::hook::hook_gethostbyname(name)
}

/// Hook for getnameinfo() system call
///
/// # Safety
/// This is a C FFI function that makes unsafe operations
#[no_mangle]
pub unsafe extern "C" fn getnameinfo(
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    host: *mut c_char,
    hostlen: libc::socklen_t,
    serv: *mut c_char,
    servlen: libc::socklen_t,
    flags: c_int,
) -> c_int {
    proxychains::hook::hook_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert!(true);
    }
}
