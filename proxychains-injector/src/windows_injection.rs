//! Same-architecture injection with an explicit initialization acknowledgement.
use crate::{InjectorError, Result};
use std::{
    ffi::c_void,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::Path,
};
use windows::core::{s, PCWSTR};
use windows::Win32::{
    Foundation::*,
    System::{
        Diagnostics::{Debug::WriteProcessMemory, ToolHelp::*},
        LibraryLoader::*,
        Memory::*,
        Threading::*,
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}
fn error(message: impl Into<String>) -> InjectorError {
    InjectorError::InjectionFailed(message.into())
}

unsafe fn remote_module(pid: u32, path: &Path) -> Result<usize> {
    let snapshot = Handle(
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).map_err(|e| {
            error(format!(
                "Cannot enumerate target modules (architecture/permissions): {e}"
            ))
        })?,
    );
    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    Module32FirstW(snapshot.0, &mut entry).map_err(|e| error(e.to_string()))?;
    loop {
        let n = entry
            .szExePath
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExePath.len());
        let found = std::path::PathBuf::from(std::ffi::OsString::from_wide(&entry.szExePath[..n]));
        if found.canonicalize().ok().as_deref() == Some(path) {
            return Ok(entry.modBaseAddr as usize);
        }
        if Module32NextW(snapshot.0, &mut entry).is_err() {
            break;
        }
    }
    Err(error("DLL was not loaded in the target process"))
}

unsafe fn call_remote(process: HANDLE, address: usize, data: &[u16]) -> Result<u32> {
    let bytes = std::mem::size_of_val(data);
    let allocation = VirtualAllocEx(
        process,
        None,
        bytes,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if allocation.is_null() {
        return Err(error("Cannot allocate initialization argument"));
    }
    let mut written = 0;
    if WriteProcessMemory(
        process,
        allocation,
        data.as_ptr().cast(),
        bytes,
        Some(&mut written),
    )
    .is_err()
        || written != bytes
    {
        let _ = VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
        return Err(error("Cannot write initialization argument"));
    }
    let start: LPTHREAD_START_ROUTINE = Some(std::mem::transmute::<
        usize,
        unsafe extern "system" fn(*mut c_void) -> u32,
    >(address));
    let thread = match CreateRemoteThread(process, None, 0, start, Some(allocation), 0, None) {
        Ok(h) => Handle(h),
        Err(e) => {
            let _ = VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
            return Err(error(e.to_string()));
        }
    };
    if WaitForSingleObject(thread.0, 15000) != WAIT_OBJECT_0 {
        // The remote thread can still reference its argument. For attached targets,
        // leave this small allocation until process exit rather than freeing live memory.
        return Err(error(
            "Remote initialization timed out or wait failed; readiness is unknown",
        ));
    }
    let _ = VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
    let mut code = 0;
    GetExitCodeThread(thread.0, &mut code).map_err(|e| error(e.to_string()))?;
    Ok(code)
}

pub(crate) unsafe fn inject(process: HANDLE, path: &Path) -> Result<()> {
    let mut local_wow64 = BOOL(0);
    let mut target_wow64 = BOOL(0);
    IsWow64Process(GetCurrentProcess(), &mut local_wow64).map_err(|e| error(e.to_string()))?;
    IsWow64Process(process, &mut target_wow64).map_err(|e| error(e.to_string()))?;
    if local_wow64 != target_wow64 {
        return Err(error(
            "Launcher and target architectures differ; use a matching launcher/DLL",
        ));
    }
    let path = path.canonicalize()?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // Map without executing DllMain; validates the DLL and native architecture.
    let local = Module(
        LoadLibraryExW(
            PCWSTR(wide.as_ptr()),
            HANDLE::default(),
            DONT_RESOLVE_DLL_REFERENCES,
        )
        .map_err(|e| error(format!("Invalid DLL or incompatible architecture: {e}")))?,
    );
    let init = GetProcAddress(local.0, s!("proxychains_initialize_v1")).ok_or_else(|| {
        error("DLL does not export proxychains_initialize_v1; use matching launcher and DLL")
    })?;
    let offset = init as usize - local.0 .0 as usize;
    let loader = GetProcAddress(
        GetModuleHandleA(s!("kernel32.dll")).map_err(|e| error(e.to_string()))?,
        s!("LoadLibraryW"),
    )
    .ok_or_else(|| error("LoadLibraryW unavailable"))?;
    // Do not interpret the DWORD result as a 64-bit module address.
    call_remote(process, loader as usize, &wide)?;
    let base = remote_module(GetProcessId(process), &path)?;
    let config = match std::env::var_os("PROXYCHAINS_CONF_FILE") {
        Some(path) => std::path::PathBuf::from(path)
            .canonicalize()?
            .into_os_string(),
        None => std::ffi::OsString::new(),
    };
    let group = std::env::var_os("PROXYCHAINS_PROXY_GROUP").unwrap_or_default();
    let payload: Vec<u16> = config
        .encode_wide()
        .chain(Some(0))
        .chain(group.encode_wide())
        .chain(Some(0))
        .collect();
    if payload.len() > 32768 {
        return Err(error("Initialization configuration is too long"));
    }
    let status = call_remote(process, base + offset, &payload)?;
    if status != 0x50435231 {
        return Err(error(format!(
            "Proxy hooks did not become ready (status {status:#x})"
        )));
    }
    Ok(())
}
