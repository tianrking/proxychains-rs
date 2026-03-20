//! Windows API hooking via MinHook.
//!
//! This module installs hooks for Winsock APIs and exposes trampoline-backed
//! `original_*` wrappers that call the underlying system implementations.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use minhook::MinHook;
use tracing::debug;
use windows::Win32::Networking::WinSock::{WSAECONNREFUSED, WSAHOST_NOT_FOUND, WSASetLastError};

use crate::error::{Error, Result};

use super::hooks_windows::{
    hook_connect_impl, hook_freeaddrinfo_impl, hook_getaddrinfo_impl, hook_getaddrinfow_impl,
    hook_gethostbyname_impl, hook_getnameinfo_impl, hook_wsa_connect_impl, hook_wsa_ioctl_impl,
};

type ConnectFn = unsafe extern "system" fn(usize, *const c_void, i32) -> i32;
type WsaConnectFn = unsafe extern "system" fn(
    usize,
    *const c_void,
    i32,
    *const c_void,
    *const c_void,
    *const c_void,
    *const c_void,
) -> i32;
type GetAddrInfoFn =
    unsafe extern "system" fn(*const i8, *const i8, *const c_void, *mut *mut c_void) -> i32;
type GetAddrInfoWFn =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void, *mut *mut c_void) -> i32;
type FreeAddrInfoFn = unsafe extern "system" fn(*mut c_void);
type GetHostByNameFn = unsafe extern "system" fn(*const i8) -> *mut c_void;
type GetNameInfoFn =
    unsafe extern "system" fn(*const c_void, i32, *mut i8, u32, *mut i8, u32, i32) -> i32;
type WsaIoctlFn = unsafe extern "system" fn(
    usize,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
    *mut c_void,
) -> i32;

static ORIGINAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
static ORIGINAL_WSA_CONNECT: OnceLock<WsaConnectFn> = OnceLock::new();
static ORIGINAL_GETADDRINFO: OnceLock<GetAddrInfoFn> = OnceLock::new();
static ORIGINAL_GETADDRINFOW: OnceLock<GetAddrInfoWFn> = OnceLock::new();
static ORIGINAL_FREEADDRINFO: OnceLock<FreeAddrInfoFn> = OnceLock::new();
static ORIGINAL_GETHOSTBYNAME: OnceLock<GetHostByNameFn> = OnceLock::new();
static ORIGINAL_GETNAMEINFO: OnceLock<GetNameInfoFn> = OnceLock::new();
static ORIGINAL_WSA_IOCTL: OnceLock<WsaIoctlFn> = OnceLock::new();

static HOOKS_READY: AtomicBool = AtomicBool::new(false);

fn mh_to_error(op: &str, status: minhook::MH_STATUS) -> Error {
    Error::WindowsApi(format!("MinHook {} failed: {:?}", op, status))
}

unsafe fn install_api_hook<F>(proc_name: &str, detour: *mut c_void) -> Result<F> {
    let trampoline = MinHook::create_hook_api("ws2_32.dll", proc_name, detour)
        .map_err(|s| mh_to_error("create_hook_api", s))?;
    Ok(std::mem::transmute_copy::<*mut c_void, F>(&trampoline))
}

/// Store for original function pointers.
pub struct OriginalFunctions;

impl OriginalFunctions {
    pub fn new() -> Self {
        Self
    }

    pub fn load_and_hook(&mut self) -> Result<()> {
        unsafe {
            let connect_fn: ConnectFn =
                install_api_hook("connect", hook_connect_impl as *const () as *mut c_void)?;
            let wsa_connect_fn: WsaConnectFn =
                install_api_hook("WSAConnect", hook_wsa_connect_impl as *const () as *mut c_void)?;
            let wsa_ioctl_fn: WsaIoctlFn =
                install_api_hook("WSAIoctl", hook_wsa_ioctl_impl as *const () as *mut c_void)?;
            let getaddrinfo_fn: GetAddrInfoFn = install_api_hook(
                "getaddrinfo",
                hook_getaddrinfo_impl as *const () as *mut c_void,
            )?;
            let getaddrinfow_fn: GetAddrInfoWFn = install_api_hook(
                "GetAddrInfoW",
                hook_getaddrinfow_impl as *const () as *mut c_void,
            )?;
            let freeaddrinfo_fn: FreeAddrInfoFn = install_api_hook(
                "freeaddrinfo",
                hook_freeaddrinfo_impl as *const () as *mut c_void,
            )?;
            let gethostbyname_fn: GetHostByNameFn = install_api_hook(
                "gethostbyname",
                hook_gethostbyname_impl as *const () as *mut c_void,
            )?;
            let getnameinfo_fn: GetNameInfoFn = install_api_hook(
                "getnameinfo",
                hook_getnameinfo_impl as *const () as *mut c_void,
            )?;

            let _ = ORIGINAL_CONNECT.set(connect_fn);
            let _ = ORIGINAL_WSA_CONNECT.set(wsa_connect_fn);
            let _ = ORIGINAL_WSA_IOCTL.set(wsa_ioctl_fn);
            let _ = ORIGINAL_GETADDRINFO.set(getaddrinfo_fn);
            let _ = ORIGINAL_GETADDRINFOW.set(getaddrinfow_fn);
            let _ = ORIGINAL_FREEADDRINFO.set(freeaddrinfo_fn);
            let _ = ORIGINAL_GETHOSTBYNAME.set(gethostbyname_fn);
            let _ = ORIGINAL_GETNAMEINFO.set(getnameinfo_fn);

            MinHook::enable_all_hooks().map_err(|s| mh_to_error("enable_all_hooks", s))?;
        }

        Ok(())
    }
}

impl Default for OriginalFunctions {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize original functions and install hooks.
pub fn init_original_functions() -> Result<()> {
    if HOOKS_READY.load(Ordering::Acquire) {
        return Ok(());
    }

    let mut funcs = OriginalFunctions::new();
    funcs.load_and_hook()?;
    HOOKS_READY.store(true, Ordering::Release);
    debug!("Windows Winsock hooks installed");
    Ok(())
}

/// Call the original connect function.
pub unsafe fn original_connect(sock: usize, addr: *const c_void, len: i32) -> i32 {
    if let Some(f) = ORIGINAL_CONNECT.get() {
        f(sock, addr, len)
    } else {
        WSASetLastError(WSAECONNREFUSED.0);
        -1
    }
}

/// Call the original WSAConnect function.
pub unsafe fn original_wsa_connect(
    sock: usize,
    name: *const c_void,
    namelen: i32,
    caller_data: *const c_void,
    callee_data: *const c_void,
    sqos: *const c_void,
    gqos: *const c_void,
) -> i32 {
    if let Some(f) = ORIGINAL_WSA_CONNECT.get() {
        f(
            sock,
            name,
            namelen,
            caller_data,
            callee_data,
            sqos,
            gqos,
        )
    } else {
        WSASetLastError(WSAECONNREFUSED.0);
        -1
    }
}

/// Call the original WSAIoctl function.
pub unsafe fn original_wsa_ioctl(
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
    if let Some(f) = ORIGINAL_WSA_IOCTL.get() {
        f(
            sock,
            io_control_code,
            in_buffer,
            in_buffer_len,
            out_buffer,
            out_buffer_len,
            bytes_returned,
            overlapped,
            completion_routine,
        )
    } else {
        WSASetLastError(WSAECONNREFUSED.0);
        -1
    }
}

/// Call the original getaddrinfo function.
pub unsafe fn original_getaddrinfo(
    node: *const i8,
    service: *const i8,
    hints: *const c_void,
    res: *mut *mut c_void,
) -> i32 {
    if let Some(f) = ORIGINAL_GETADDRINFO.get() {
        f(node, service, hints, res)
    } else {
        WSASetLastError(WSAHOST_NOT_FOUND.0);
        WSAHOST_NOT_FOUND.0
    }
}

/// Call the original GetAddrInfoW function.
pub unsafe fn original_getaddrinfow(
    node: *const u16,
    service: *const u16,
    hints: *const c_void,
    res: *mut *mut c_void,
) -> i32 {
    if let Some(f) = ORIGINAL_GETADDRINFOW.get() {
        f(node, service, hints, res)
    } else {
        WSASetLastError(WSAHOST_NOT_FOUND.0);
        WSAHOST_NOT_FOUND.0
    }
}

/// Call the original freeaddrinfo function.
pub unsafe fn original_freeaddrinfo(res: *mut c_void) {
    if let Some(f) = ORIGINAL_FREEADDRINFO.get() {
        f(res);
    }
}

/// Call the original gethostbyname function.
pub unsafe fn original_gethostbyname(name: *const i8) -> *mut c_void {
    if let Some(f) = ORIGINAL_GETHOSTBYNAME.get() {
        f(name)
    } else {
        std::ptr::null_mut()
    }
}

/// Call the original getnameinfo function.
pub unsafe fn original_getnameinfo(
    sa: *const c_void,
    salen: i32,
    host: *mut i8,
    hostlen: u32,
    serv: *mut i8,
    servlen: u32,
    flags: i32,
) -> i32 {
    if let Some(f) = ORIGINAL_GETNAMEINFO.get() {
        f(sa, salen, host, hostlen, serv, servlen, flags)
    } else {
        WSAHOST_NOT_FOUND.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_original_functions_creation() {
        let funcs = OriginalFunctions::new();
        let _ = funcs;
    }
}
