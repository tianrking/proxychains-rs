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

#[cfg(unix)]
mod udp_exports;

/// Initialize the library (common code for all platforms)
fn init_library() -> bool {
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
            return false;
        }
    };

    debug!(
        "Configuration loaded: {} proxies, chain type: {:?}",
        config.proxies.len(),
        config.chain_type
    );

    // Initialize hooks
    if !config.has_proxies() {
        error!("No proxies configured");
        return false;
    }
    if let Err(e) = init_hooks(config) {
        error!("Failed to initialize hooks: {}", e);
        false
    } else {
        info!("libproxychains initialized successfully");
        true
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
        if !init_library() { unsafe { libc::_exit(127); } }
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

    /// Called by the launcher after LoadLibrary completes, outside the loader lock.
    /// The argument contains two NUL-terminated UTF-16 strings: config and group.
    #[no_mangle]
    pub unsafe extern "system" fn proxychains_initialize_v1(argument: *mut c_void) -> u32 {
        use std::os::windows::ffi::OsStringExt;
        static INITIALIZED: std::sync::OnceLock<(Vec<u16>, u32)> = std::sync::OnceLock::new();
        if argument.is_null() { return 1; }
        let ptr = argument as *const u16;
        let mut payload = Vec::new();
        let mut separators = Vec::new();
        for i in 0..32768 {
            let ch = *ptr.add(i); payload.push(ch);
            if ch == 0 { separators.push(i); if separators.len() == 2 { break; } }
        }
        if separators.len() != 2 { return 2; }
        // Configuration failures before installing hooks are retryable for attachment.
        // Once hook installation begins, retain failure state rather than retrying a
        // potentially partial installation.
        if INITIALIZED.get().is_none() {
            let config = std::ffi::OsString::from_wide(&payload[..separators[0]]);
            let group = std::ffi::OsString::from_wide(&payload[separators[0]+1..separators[1]]);
            let mut parser = ConfigParser::new();
            if !config.is_empty() { parser = parser.with_path(std::path::PathBuf::from(config)); }
            if !group.is_empty() { parser = parser.with_group(group.to_string_lossy()); }
            if !matches!(parser.parse(), Ok(config) if config.has_proxies()) { return 3; }
        }
        let (saved, status) = INITIALIZED.get_or_init(|| {
            let result = std::panic::catch_unwind(|| {
                let config = std::ffi::OsString::from_wide(&payload[..separators[0]]);
                let group = std::ffi::OsString::from_wide(&payload[separators[0]+1..separators[1]]);
                if !config.is_empty() { std::env::set_var("PROXYCHAINS_CONF_FILE", config); }
                if group.is_empty() { std::env::remove_var("PROXYCHAINS_PROXY_GROUP"); }
                else { std::env::set_var("PROXYCHAINS_PROXY_GROUP", group); }
                init_library()
            });
            (payload.clone(), if matches!(result, Ok(true)) { 0x50435231 } else { 3 })
        });
        if saved != &payload { return 4; }
        *status
    }

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
                // Initialization is explicitly acknowledged by proxychains_initialize_v1.
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
