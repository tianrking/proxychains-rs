//! LD_PRELOAD/DLL injection library for proxychains
//!
//! This library is loaded via:
//! - Linux: LD_PRELOAD environment variable
//! - macOS: DYLD_INSERT_LIBRARIES environment variable
//! - Windows: DLL injection using dll-syringe
//!
//! It intercepts network system calls and redirects them through proxy chains.

use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

use proxychains::{ConfigParser, hook::init_hooks};

/// Initialize the library (common code for all platforms)
fn init_library() {
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

// ============================================================================
// Unix Implementation (LD_PRELOAD/DYLD_INSERT_LIBRARIES)
// ============================================================================

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use ctor::ctor;
    use std::ffi::{c_char, c_int};

    /// Library initialization using #[ctor] attribute
    #[ctor]
    fn init() {
        init_library();
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
}

// ============================================================================
// Windows Implementation (DLL Injection)
// ============================================================================

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;
    use windows::Win32::Foundation::*;

    /// Windows DLL entry point
    ///
    /// This is called when the DLL is loaded/unloaded.
    ///
    /// # Safety
    /// This is a Windows API callback
    #[no_mangle]
    pub extern "system" fn DllMain(
        _hinst: HINSTANCE,
        reason: u32,
        _reserved: *mut c_void,
    ) -> BOOL {
        const DLL_PROCESS_ATTACH: u32 = 1;
        const DLL_PROCESS_DETACH: u32 = 0;

        match reason {
            DLL_PROCESS_ATTACH => {
                // Initialize the library when loaded into a process
                init_library();
                BOOL(1)
            }
            DLL_PROCESS_DETACH => {
                // Keep DllMain minimal: avoid TLS/logging work during detach.
                BOOL(1)
            }
            _ => BOOL(1),
        }
    }

    // Note: On Windows, we don't export individual functions like connect, getaddrinfo, etc.
    // Instead, we use API Hooking (via retour-rs) to intercept calls to ws2_32.dll functions.
    // The hooks are installed during init_library() -> init_hooks().
    //
    // The hooking mechanism works by:
    // 1. Loading the original functions from ws2_32.dll
    // 2. Creating detours that redirect to our hook functions
    // 3. Enabling the detours so all calls go through our hooks first
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert!(true);
    }
}
