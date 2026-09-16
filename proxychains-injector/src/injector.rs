//! Injector implementation
//!
//! Platform-specific DLL/process injection functionality.

use std::path::Path;

use thiserror::Error;
use tracing::{debug, info, warn};

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

#[cfg(windows)]
fn enumerate_descendant_pids(root_pid: u32) -> Result<Vec<u32>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| {
            InjectorError::WindowsApi(format!("CreateToolhelp32Snapshot failed: {e:?}"))
        })?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut parent_by_pid = HashMap::new();
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                parent_by_pid.insert(entry.th32ProcessID, entry.th32ParentProcessID);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);

        let mut seen = HashSet::from([root_pid]);
        let mut queue = VecDeque::from([root_pid]);
        let mut descendants = Vec::new();
        while let Some(parent) = queue.pop_front() {
            for (&pid, &ppid) in &parent_by_pid {
                if ppid == parent && seen.insert(pid) {
                    descendants.push(pid);
                    queue.push_back(pid);
                }
            }
        }
        Ok(descendants)
    }
}

pub type Result<T> = std::result::Result<T, InjectorError>;

#[cfg(windows)]
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_owned();
    }
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            result.extend(std::iter::repeat('\\').take(slashes * 2 + 1));
        } else {
            result.extend(std::iter::repeat('\\').take(slashes));
        }
        slashes = 0;
        result.push(ch);
    }
    result.extend(std::iter::repeat('\\').take(slashes * 2));
    result.push('"');
    result
}

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
            dll_path: dll_path.canonicalize()?,
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
            let result = self.inject_dll(process);
            let _ = windows::Win32::Foundation::CloseHandle(process);
            result?;

            info!("Successfully injected DLL into process {}", pid);
        }

        Ok(())
    }

    /// Inject into an existing process by name (Windows)
    #[cfg(windows)]
    pub fn inject_by_name(&self, name: &str) -> Result<()> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        let mut matches = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| InjectorError::WindowsApi(e.to_string()))?;
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of_val(&entry) as u32;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let n = entry
                        .szExeFile
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    if String::from_utf16_lossy(&entry.szExeFile[..n]).eq_ignore_ascii_case(name) {
                        matches.push(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        match matches.as_slice() {
            [pid] => self.inject_by_pid(*pid),
            [] => Err(InjectorError::ProcessNotFound(name.into())),
            _ => Err(InjectorError::InjectionFailed(format!(
                "Multiple processes named {name}; select an explicit PID: {matches:?}"
            ))),
        }
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
                let _ = windows::Win32::System::Threading::TerminateProcess(process_handle, 1);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(e);
            }
            info!("Successfully injected DLL into suspended process {}", pid);

            let resume_ret = ResumeThread(thread_handle);
            if resume_ret == u32::MAX {
                let _ = windows::Win32::System::Threading::TerminateProcess(process_handle, 1);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(InjectorError::WindowsApi("ResumeThread failed".into()));
            }

            let _ = WaitForSingleObject(process_handle, INFINITE);
            let mut exit_code = 1u32;
            GetExitCodeProcess(process_handle, &mut exit_code).map_err(|e| {
                InjectorError::WindowsApi(format!("GetExitCodeProcess failed: {:?}", e))
            })?;

            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);

            Ok(exit_code as i32)
        }
    }

    /// Create a suspended process, inject DLL, resume, and keep injecting descendants
    /// (child/grandchild processes) until the root process exits.
    #[cfg(windows)]
    pub fn spawn_inject_tree_wait(&self, process_info: &ProcessInfo) -> Result<i32> {
        match self.spawn_inject_tree_debug_wait(process_info) {
            Ok(exit_code) => Ok(exit_code),
            Err(error) => {
                warn!(
                    "Creation-time tree injection failed; retrying with suspended-process polling fallback: {}",
                    error
                );
                self.spawn_inject_tree_polling_wait(process_info)
            }
        }
    }

    /// Create the root under the Windows debugger, inject every process at its
    /// creation event, and continue each event only after hook initialization.
    /// This closes the polling window where a short-lived child could execute
    /// networking code before the 150 ms process-table scan noticed it.
    #[cfg(windows)]
    fn spawn_inject_tree_debug_wait(&self, process_info: &ProcessInfo) -> Result<i32> {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{
            CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE,
        };
        use windows::Win32::System::Diagnostics::Debug::{
            ContinueDebugEvent, WaitForDebugEvent, CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT,
            EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
        };
        use windows::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, TerminateProcess, DEBUG_PROCESS,
            PROCESS_INFORMATION, STARTUPINFOW,
        };

        let mut command_line = quote_arg(&process_info.command);
        for arg in &process_info.args {
            command_line.push(' ');
            command_line.push_str(&quote_arg(arg));
        }
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
                DEBUG_PROCESS,
                None,
                PCWSTR::null(),
                &startup_info,
                &mut process_info_win,
            )
            .map_err(|e| InjectorError::ProcessCreationFailed(format!("{e:?}")))?;

            let root_pid = process_info_win.dwProcessId;
            let root_handle: HANDLE = process_info_win.hProcess;
            let mut root_exit = None;
            let mut fatal_error: Option<InjectorError> = None;
            loop {
                let mut event = DEBUG_EVENT::default();
                WaitForDebugEvent(&mut event, 30_000).map_err(|e| {
                    InjectorError::WindowsApi(format!("WaitForDebugEvent failed: {e:?}"))
                })?;
                let code = event.dwDebugEventCode;
                let mut continue_status = DBG_CONTINUE;

                if code == CREATE_PROCESS_DEBUG_EVENT {
                    let info = event.u.CreateProcessInfo;
                    let is_root = event.dwProcessId == root_pid;
                    if fatal_error.is_none() {
                        debug!(
                            "Injecting DLL at process creation event: pid={} root={}",
                            event.dwProcessId, is_root
                        );
                        if let Err(error) = self.inject_dll(info.hProcess) {
                            fatal_error = Some(InjectorError::InjectionFailed(format!(
                                "PID {} (root={}): {error}",
                                event.dwProcessId, is_root
                            )));
                            if is_root {
                                let _ = TerminateProcess(root_handle, 1);
                            }
                        } else {
                            info!(
                                "Injected DLL at process creation event for PID {}",
                                event.dwProcessId
                            );
                        }
                    }
                    if !is_root {
                        let _ = CloseHandle(info.hProcess);
                    }
                    let _ = CloseHandle(info.hThread);
                    if !info.hFile.is_invalid() {
                        let _ = CloseHandle(info.hFile);
                    }
                } else if code == EXIT_PROCESS_DEBUG_EVENT {
                    let info = event.u.ExitProcess;
                    if event.dwProcessId == root_pid {
                        root_exit = Some(info.dwExitCode);
                    }
                } else if code == EXCEPTION_DEBUG_EVENT {
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }

                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status).map_err(
                    |e| InjectorError::WindowsApi(format!("ContinueDebugEvent failed: {e:?}")),
                )?;
                if root_exit.is_some() {
                    break;
                }
            }

            let mut exit_code = root_exit.unwrap_or(1);
            GetExitCodeProcess(root_handle, &mut exit_code).map_err(|e| {
                InjectorError::WindowsApi(format!("GetExitCodeProcess failed: {e:?}"))
            })?;
            let _ = CloseHandle(process_info_win.hThread);
            let _ = CloseHandle(root_handle);
            if let Some(error) = fatal_error {
                return Err(error);
            }
            Ok(exit_code as i32)
        }
    }

    /// Compatibility fallback for applications that cannot be created under a
    /// debugger (for example browser launchers with debugger-sensitive startup
    /// behavior). The root is still injected before resume; descendants are
    /// discovered by process-table polling, so a short race window remains.
    #[cfg(windows)]
    fn spawn_inject_tree_polling_wait(&self, process_info: &ProcessInfo) -> Result<i32> {
        use std::collections::HashSet;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess,
            WaitForSingleObject, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
        };

        let mut command_line = quote_arg(&process_info.command);
        for arg in &process_info.args {
            command_line.push(' ');
            command_line.push_str(&quote_arg(arg));
        }
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
            .map_err(|e| InjectorError::ProcessCreationFailed(format!("{e:?}")))?;

            let process_handle: HANDLE = process_info_win.hProcess;
            let thread_handle: HANDLE = process_info_win.hThread;
            let root_pid = process_info_win.dwProcessId;
            if let Err(error) = self.inject_dll(process_handle) {
                let _ = TerminateProcess(process_handle, 1);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(error);
            }
            info!(
                "Injected DLL into suspended fallback root process {}",
                root_pid
            );

            if ResumeThread(thread_handle) == u32::MAX {
                let _ = TerminateProcess(process_handle, 1);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
                return Err(InjectorError::WindowsApi("ResumeThread failed".into()));
            }

            let mut injected_pids = HashSet::from([root_pid]);
            loop {
                for pid in enumerate_descendant_pids(root_pid)? {
                    if injected_pids.contains(&pid) {
                        continue;
                    }
                    match self.inject_by_pid(pid) {
                        Ok(()) => {
                            injected_pids.insert(pid);
                            debug!("Injected DLL into fallback tree PID {}", pid);
                        }
                        Err(error) => {
                            debug!("Fallback tree injection skipped for PID {}: {}", pid, error);
                        }
                    }
                }
                if WaitForSingleObject(process_handle, 150) == WAIT_OBJECT_0 {
                    break;
                }
            }

            let mut exit_code = 1u32;
            GetExitCodeProcess(process_handle, &mut exit_code).map_err(|e| {
                InjectorError::WindowsApi(format!("GetExitCodeProcess failed: {e:?}"))
            })?;
            let _ = CloseHandle(thread_handle);
            let _ = CloseHandle(process_handle);
            Ok(exit_code as i32)
        }
    }

    /// Internal DLL injection method (Windows)
    #[cfg(windows)]
    unsafe fn inject_dll(&self, process: windows::Win32::Foundation::HANDLE) -> Result<()> {
        super::windows_injection::inject(process, &self.dll_path)
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
