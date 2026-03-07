//! LD_PRELOAD interposition utilities
//!
//! This module provides utilities for loading original libc symbols
//! and managing the hook mechanism.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use libc::{c_int, c_void, dlsym, RTLD_NEXT};

use crate::error::{Error, Result};

/// Load a symbol from the next library in the loading chain
///
/// This uses `dlsym(RTLD_NEXT, ...)` to get the original function
/// before our LD_PRELOAD library intercepted it.
pub fn load_symbol<T>(name: &str) -> Result<T> {
    let cname = CString::new(name).map_err(|_| {
        Error::Config(format!("Invalid symbol name: {}", name))
    })?;

    let sym = unsafe { dlsym(RTLD_NEXT, cname.as_ptr()) };

    if sym.is_null() {
        return Err(Error::Config(format!(
            "Failed to load symbol: {}",
            name
        )));
    }

    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&sym) })
}

/// Store for original function pointers
pub struct OriginalFunctions {
    pub connect: Option<unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int>,
    pub getaddrinfo: Option<unsafe extern "C" fn(*const c_char, *const c_char, *const libc::addrinfo, *mut *mut libc::addrinfo) -> c_int>,
    pub freeaddrinfo: Option<unsafe extern "C" fn(*mut libc::addrinfo)>,
    pub gethostbyname: Option<unsafe extern "C" fn(*const c_char) -> *mut libc::hostent>,
    pub getnameinfo: Option<unsafe extern "C" fn(*const libc::sockaddr, libc::socklen_t, *mut c_char, libc::socklen_t, *mut c_char, libc::socklen_t, c_int) -> c_int>,
    pub gethostbyaddr: Option<unsafe extern "C" fn(*const c_void, libc::socklen_t, c_int) -> *mut libc::hostent>,
}

impl OriginalFunctions {
    /// Create a new OriginalFunctions struct
    pub fn new() -> Self {
        Self {
            connect: None,
            getaddrinfo: None,
            freeaddrinfo: None,
            gethostbyname: None,
            getnameinfo: None,
            gethostbyaddr: None,
        }
    }

    /// Load all original functions
    pub fn load_all(&mut self) -> Result<()> {
        self.connect = Some(load_symbol("connect")?);
        self.getaddrinfo = Some(load_symbol("getaddrinfo")?);
        self.freeaddrinfo = Some(load_symbol("freeaddrinfo")?);
        self.gethostbyname = Some(load_symbol("gethostbyname")?);
        self.getnameinfo = Some(load_symbol("getnameinfo")?);
        self.gethostbyaddr = Some(load_symbol("gethostbyaddr")?);
        Ok(())
    }
}

impl Default for OriginalFunctions {
    fn default() -> Self {
        Self::new()
    }
}

/// Global storage for original function pointers
static mut ORIGINAL_FUNCS: Option<OriginalFunctions> = None;

/// Initialize original functions
///
/// This should be called once during library initialization
pub fn init_original_functions() -> Result<()> {
    unsafe {
        if ORIGINAL_FUNCS.is_none() {
            let mut funcs = OriginalFunctions::new();
            funcs.load_all()?;
            ORIGINAL_FUNCS = Some(funcs);
        }
    }
    Ok(())
}

/// Get the original functions
///
/// # Safety
/// This function should only be called after initialization
pub unsafe fn get_original_functions() -> &'static OriginalFunctions {
    ORIGINAL_FUNCS.as_ref().expect("Original functions not initialized")
}

/// Call the original connect function
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn original_connect(
    sock: c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> c_int {
    let funcs = get_original_functions();
    if let Some(connect_fn) = funcs.connect {
        connect_fn(sock, addr, len)
    } else {
        -1
    }
}

/// Call the original getaddrinfo function
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn original_getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    let funcs = get_original_functions();
    if let Some(getaddrinfo_fn) = funcs.getaddrinfo {
        getaddrinfo_fn(node, service, hints, res)
    } else {
        libc::EAI_FAIL
    }
}

/// Call the original freeaddrinfo function
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn original_freeaddrinfo(res: *mut libc::addrinfo) {
    let funcs = get_original_functions();
    if let Some(freeaddrinfo_fn) = funcs.freeaddrinfo {
        freeaddrinfo_fn(res);
    }
}

/// Call the original gethostbyname function
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn original_gethostbyname(name: *const c_char) -> *mut libc::hostent {
    let funcs = get_original_functions();
    if let Some(gethostbyname_fn) = funcs.gethostbyname {
        gethostbyname_fn(name)
    } else {
        ptr::null_mut()
    }
}

/// Call the original getnameinfo function
///
/// # Safety
/// This function makes unsafe FFI calls
pub unsafe fn original_getnameinfo(
    sa: *const libc::sockaddr,
    salen: libc::socklen_t,
    host: *mut c_char,
    hostlen: libc::socklen_t,
    serv: *mut c_char,
    servlen: libc::socklen_t,
    flags: c_int,
) -> c_int {
    let funcs = get_original_functions();
    if let Some(getnameinfo_fn) = funcs.getnameinfo {
        getnameinfo_fn(sa, salen, host, hostlen, serv, servlen, flags)
    } else {
        libc::EAI_FAIL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_original_functions_creation() {
        let funcs = OriginalFunctions::new();
        assert!(funcs.connect.is_none());
        assert!(funcs.getaddrinfo.is_none());
    }
}
