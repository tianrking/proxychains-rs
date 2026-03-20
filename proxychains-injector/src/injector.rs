//! Injector implementation
//!
//! Platform-specific DLL/process injection functionality.

use std::path::Path;

use thiserror::Error;
use tracing::{debug, info};

/// Injection errors
#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    #[error("Failed to inject DLL: {0}")]
    InjectionFailed(String),

    #[error("Failed to create process: {0}")]
    ProcessCreationFailed(String),

    #[error("DLL not found: {0}")]
    DllNotFound(String),

    #[error("Unsupported platform")]
    UnsupportedPlatform,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Windows API error: {0}")]
    WindowsApi(String),
}

pub type Result<T> = std::result::Result<T, InjectorError>;

/// Process information for injection
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub command: String,
    pub args: Vec<String>,
}

/// DLL injector for proxychains
pub struct ProxychainsInjector {
    dll_path: std::path::PathBuf,
}

impl ProxychainsInjector {
    /// Create a new injector with the specified DLL path
    pub fn new(dll_path: &Path) -> Result<Self> {
        if !dll_path.exists() {
            return Err(InjectorError::DllNotFound(dll_path.display().to_string()));
        }

        Ok(Self {
            dll_path: dll_path.to_path_buf(),
        })
    }

    /// Get the DLL path
    pub fn dll_path(&self) -> &Path {
        &self.dll_path
    }

    /// Inject into an existing process by PID (Windows)
    #[cfg(windows)]
    pub fn inject_by_pid(&self, pid: u32) -> Result<()> {
        use windows::Win32::System::Threading::*;

        debug!("Injecting into process with PID: {}", pid);

        unsafe {
            // Open the target process
            let access_rights = PROCESS_CREATE_THREAD.0
                | PROCESS_QUERY_INFORMATION.0
                | PROCESS_VM_OPERATION.0
                | PROCESS_VM_WRITE.0
                | PROCESS_VM_READ.0;

            let process = OpenProcess(PROCESS_ACCESS_RIGHTS(access_rights), false, pid)
                .map_err(|e| InjectorError::WindowsApi(format!("OpenProcess failed: {:?}", e)))?;

            if process.is_invalid() {
                return Err(InjectorError::ProcessNotFound(format!("PID {}", pid)));
            }

            // Inject DLL
            self.inject_dll(process)?;

            info!("Successfully injected DLL into process {}", pid);
        }

        Ok(())
    }

    /// Inject into an existing process by name (Windows)
    #[cfg(windows)]
    pub fn inject_by_name(&self, name: &str) -> Result<()> {
        debug!("Injecting into process with name: {}", name);
        Err(InjectorError::UnsupportedPlatform)
    }

    /// Create a new process and inject DLL (Windows)
    #[cfg(windows)]
    pub fn spawn_and_inject(&self, process_info: &ProcessInfo) -> Result<std::process::Child> {
        debug!(
            "Spawning process: {} {:?}",
            process_info.command, process_info.args
        );

        // Create the process
        let mut cmd = std::process::Command::new(&process_info.command);
        cmd.args(&process_info.args);

        let mut child = cmd
            .spawn()
            .map_err(|e| InjectorError::ProcessCreationFailed(e.to_string()))?;

        let pid = child.id();
        debug!("Process created with PID: {}", pid);

        // Inject DLL using the PID
        self.inject_by_pid(pid).map_err(|e| {
            let _ = child.kill();
            e
        })?;

        info!("Successfully spawned and injected into process {}", pid);

        Ok(child)
    }

    /// Internal DLL injection method (Windows)
    #[cfg(windows)]
    unsafe fn inject_dll(&self, process: windows::Win32::Foundation::HANDLE) -> Result<()> {
        use windows::Win32::Foundation::*;
        use windows::Win32::System::Memory::*;
        use windows::Win32::System::LibraryLoader::*;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Threading::CreateRemoteThread;
        use windows::Win32::System::Threading::WaitForSingleObject;
        use windows::Win32::System::Threading::LPTHREAD_START_ROUTINE;

        let dll_path = self.dll_path.to_string_lossy();
        let dll_path_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();

        // Get the address of LoadLibraryW
        let load_library = GetProcAddress(
            GetModuleHandleA(windows::core::s!("kernel32.dll"))
                .map_err(|e| InjectorError::WindowsApi(format!("GetModuleHandle failed: {:?}", e)))?,
            windows::core::s!("LoadLibraryW"),
        )
        .ok_or_else(|| InjectorError::WindowsApi("GetProcAddress failed".into()))?;

        // Allocate memory in the target process for the DLL path
        let path_size = dll_path_wide.len() * std::mem::size_of::<u16>();
        let remote_memory = VirtualAllocEx(
            process,
            None,
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_memory.is_null() {
            return Err(InjectorError::WindowsApi("VirtualAllocEx returned null".into()));
        }

        // Write the DLL path to the allocated memory
        let mut bytes_written: usize = 0;
        let write_result = WriteProcessMemory(
            process,
            remote_memory,
            dll_path_wide.as_ptr() as *const _,
            path_size,
            Some(&mut bytes_written),
        );

        if write_result.is_err() || bytes_written != path_size {
            let _ = VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return Err(InjectorError::WindowsApi("WriteProcessMemory failed".into()));
        }

        // Create a remote thread that calls LoadLibraryW with the DLL path
        let start_routine: LPTHREAD_START_ROUTINE = std::mem::transmute(load_library);

        let thread = CreateRemoteThread(
            process,
            None,
            0,
            start_routine,
            Some(remote_memory),
            0,
            None,
        )
        .map_err(|e| InjectorError::WindowsApi(format!("CreateRemoteThread failed: {:?}", e)))?;

        if thread.is_invalid() {
            let _ = VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
            return Err(InjectorError::WindowsApi(
                "CreateRemoteThread returned invalid handle".into(),
            ));
        }

        // Wait for the thread to complete
        let _ = WaitForSingleObject(thread, 5000);

        // Clean up
        let _ = VirtualFreeEx(process, remote_memory, 0, MEM_RELEASE);
        let _ = CloseHandle(thread);

        Ok(())
    }

    /// Unix stub - not implemented (uses LD_PRELOAD instead)
    #[cfg(unix)]
    pub fn inject_by_pid(&self, _pid: u32) -> Result<()> {
        Err(InjectorError::UnsupportedPlatform)
    }

    /// Unix stub - not implemented
    #[cfg(unix)]
    pub fn inject_by_name(&self, _name: &str) -> Result<()> {
        Err(InjectorError::UnsupportedPlatform)
    }

    /// Unix stub - not implemented
    #[cfg(unix)]
    pub fn spawn_and_inject(&self, _process_info: &ProcessInfo) -> Result<std::process::Child> {
        Err(InjectorError::UnsupportedPlatform)
    }
}

/// Find the proxychains DLL/library path
pub fn find_library_path() -> Result<std::path::PathBuf> {
    // Try to find the library relative to the executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Check for library in the same directory
            #[cfg(windows)]
            {
                let dll_path = exe_dir.join("proxychains.dll");
                if dll_path.exists() {
                    return Ok(dll_path);
                }
            }

            #[cfg(target_os = "linux")]
            {
                let so_path = exe_dir.join("libproxychains.so");
                if so_path.exists() {
                    return Ok(so_path);
                }
            }

            #[cfg(target_os = "macos")]
            {
                let dylib_path = exe_dir.join("libproxychains.dylib");
                if dylib_path.exists() {
                    return Ok(dylib_path);
                }
            }
        }
    }

    // Check standard locations
    #[cfg(windows)]
    {
        let paths = [
            "proxychains.dll",
            "./proxychains.dll",
            "./lib/proxychains.dll",
        ];
        for path in &paths {
            let p = std::path::PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let paths = [
            "./libproxychains.so",
            "./lib/libproxychains.so",
            "/usr/lib/libproxychains.so",
            "/usr/local/lib/libproxychains.so",
        ];
        for path in &paths {
            let p = std::path::PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let paths = [
            "./libproxychains.dylib",
            "./lib/libproxychains.dylib",
            "/usr/lib/libproxychains.dylib",
            "/usr/local/lib/libproxychains.dylib",
        ];
        for path in &paths {
            let p = std::path::PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    Err(InjectorError::DllNotFound(
        "Could not find proxychains library".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_creation() {
        let info = ProcessInfo {
            pid: Some(1234),
            name: Some("test.exe".to_string()),
            command: "test.exe".to_string(),
            args: vec!["--arg1".to_string()],
        };
        assert_eq!(info.pid, Some(1234));
    }

    #[test]
    fn test_find_library_path() {
        let result = find_library_path();
        match result {
            Ok(path) => println!("Found library at: {:?}", path),
            Err(e) => println!("Expected error (library not built): {}", e),
        }
    }
}
