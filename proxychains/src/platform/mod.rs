//! Platform abstraction module
//!
//! This module provides platform-specific implementations for:
//! - Hosts file path resolution
//! - Configuration file paths
//! - Socket operations
//! - Error handling

use std::path::PathBuf;

/// Platform-specific constants and operations
pub trait Platform: Send + Sync {
    /// Get the hosts file path
    fn hosts_path() -> PathBuf;

    /// Get the default configuration file path
    fn config_path() -> PathBuf;

    /// Get the library file extension
    fn library_extension() -> &'static str;
}

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::UnixPlatform as CurrentPlatform;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::WindowsPlatform as CurrentPlatform;

/// Get the hosts file path for the current platform
pub fn hosts_path() -> PathBuf {
    CurrentPlatform::hosts_path()
}

/// Get the default config path for the current platform
pub fn config_path() -> PathBuf {
    CurrentPlatform::config_path()
}

/// Get the library extension for the current platform
pub fn library_extension() -> &'static str {
    CurrentPlatform::library_extension()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_path_exists() {
        let path = hosts_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_library_extension() {
        let ext = library_extension();
        #[cfg(unix)]
        assert!(ext == "so" || ext == "dylib");
        #[cfg(windows)]
        assert_eq!(ext, "dll");
    }
}
