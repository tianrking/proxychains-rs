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

    /// Create a suspended process, inject DLL, resume, and wait for completion (Windows).
    #[cfg(windows)]
    pub fn spawn_inject_wait(&self, process_info: &ProcessInfo) -> Result<i32> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
            CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
        };

        fn quote_arg(arg: &str) -> String {
            if arg.is_empty()
                || arg.contains(' ')
                || arg.contains('\t')
                || arg.contains('"')
                || arg.contains('\\')
            {
                let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{}\"", escaped)
            } else {
                arg.to_string()
            }
        }

        let mut command_line = quote_arg(&process_info.command);
        for arg in &process_info.args {
            command_line.push(' ');
            command_line.push_str(&quote_arg(arg));
        }

        debug!("Spawning suspended process: {}", command_line);

        let mut cmd_wide: Vec<u16> = std::ffi::OsStr::new(&command_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info = STARTUPINFOW::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info_win = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_info_win,
            )
            .map_err(|e| InjectorError::ProcessCreationFailed(format!("{:?}", e)))?;

            let process_handle: HANDLE = process_info_win.hProcess;
            let thread_handle: HANDLE = process_info_win.hThread;
            let pid = process_info_win.dwProcessId;
            debug!("Suspended process created with PID: {}", pid);

            if let Err(e) = self.inject_dll(process_handle) {
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(e);
            }
            info!("Successfully injected DLL into suspended process {}", pid);

            let resume_ret = ResumeThread(thread_handle);
            if resume_ret == u32::MAX {
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(InjectorError::WindowsApi("ResumeThread failed".into()));
            }

            let _ = WaitForSingleObject(process_handle, INFINITE);
            let mut exit_code = 1u32;
            GetExitCodeProcess(process_handle, &mut exit_code)
                .map_err(|e| InjectorError::WindowsApi(format!("GetExitCodeProcess failed: {:?}", e)))?;

            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);

            Ok(exit_code as i32)
        }
    }

    /// Create a suspended process, inject DLL, resume, and keep injecting descendants
    /// (child/grandchild processes) until the root process exits.
    #[cfg(windows)]
    pub fn spawn_inject_tree_wait(&self, process_info: &ProcessInfo) -> Result<i32> {
        use std::collections::HashSet;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject,
            CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
        };

        fn quote_arg(arg: &str) -> String {
            if arg.is_empty()
                || arg.contains(' ')
                || arg.contains('\t')
                || arg.contains('"')
                || arg.contains('\\')
            {
                let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{}\"", escaped)
            } else {
                arg.to_string()
            }
        }

        let mut command_line = quote_arg(&process_info.command);
        for arg in &process_info.args {
            command_line.push(' ');
            command_line.push_str(&quote_arg(arg));
        }

        debug!("Spawning suspended process (tree mode): {}", command_line);

        let mut cmd_wide: Vec<u16> = std::ffi::OsStr::new(&command_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info = STARTUPINFOW::default();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info_win = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_info_win,
            )
            .map_err(|e| InjectorError::ProcessCreationFailed(format!("{:?}", e)))?;

            let process_handle: HANDLE = process_info_win.hProcess;
            let thread_handle: HANDLE = process_info_win.hThread;
            let root_pid = process_info_win.dwProcessId;
            debug!("Suspended root process created with PID: {}", root_pid);

            if let Err(e) = self.inject_dll(process_handle) {
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(e);
            }
            info!("Successfully injected DLL into suspended root process {}", root_pid);

            let resume_ret = ResumeThread(thread_handle);
            if resume_ret == u32::MAX {
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(InjectorError::WindowsApi("ResumeThread failed".into()));
            }

            let mut injected_pids: HashSet<u32> = HashSet::new();
            injected_pids.insert(root_pid);

            loop {
                let descendants = enumerate_descendant_pids(root_pid)?;
                for pid in descendants {
                    if injected_pids.contains(&pid) {
                        continue;
                    }
                    match self.inject_by_pid(pid) {
                        Ok(_) => {
                            injected_pids.insert(pid);
                        }
                        Err(e) => {
                            debug!("Tree-mode injection skipped for PID {}: {}", pid, e);
                        }
                    }
                }

                let wait_ret = WaitForSingleObject(process_handle, 150);
                if wait_ret == WAIT_OBJECT_0 {
                    break;
                }
            }

            let mut exit_code = 1u32;
            GetExitCodeProcess(process_handle, &mut exit_code).map_err(|e| {
                InjectorError::WindowsApi(format!("GetExitCodeProcess failed: {:?}", e))
            })?;

            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);

            Ok(exit_code as i32)
        }
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

#[cfg(windows)]
fn enumerate_descendant_pids(root_pid: u32) -> Result<Vec<u32>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| InjectorError::WindowsApi(format!("CreateToolhelp32Snapshot failed: {:?}", e)))?;

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut parent_by_pid: HashMap<u32, u32> = HashMap::new();
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                parent_by_pid.insert(entry.th32ProcessID, entry.th32ParentProcessID);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        let mut seen: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        let mut descendants = Vec::new();

        queue.push_back(root_pid);
        seen.insert(root_pid);

        while let Some(parent) = queue.pop_front() {
            for (&pid, &ppid) in parent_by_pid.iter() {
                if ppid == parent && seen.insert(pid) {
                    descendants.push(pid);
                    queue.push_back(pid);
                }
            }
        }

        Ok(descendants)
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
