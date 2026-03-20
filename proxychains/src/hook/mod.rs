//! Hook module for LD_PRELOAD interposition
//!
//! This module provides the infrastructure for intercepting
//! network system calls and redirecting them through proxy chains.
//!
//! Platform support:
//! - Unix (Linux/macOS): Uses LD_PRELOAD/DYLD_INSERT_LIBRARIES with dlsym
//! - Windows: Uses API Hooking (MinHook)

// Unix-specific modules
#[cfg(unix)]
mod hooks;
#[cfg(unix)]
mod interpose;

// Windows-specific modules
#[cfg(windows)]
mod hooks_windows;
#[cfg(windows)]
mod interpose_windows;

// Re-export based on platform
#[cfg(unix)]
pub use hooks::*;
#[cfg(unix)]
pub use interpose::*;

#[cfg(windows)]
pub use hooks_windows::*;
#[cfg(windows)]
pub use interpose_windows::*;
