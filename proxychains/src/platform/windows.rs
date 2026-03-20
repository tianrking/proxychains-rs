//! Windows platform implementation

use std::path::PathBuf;

use super::Platform;

/// Windows platform implementation
pub struct WindowsPlatform;

impl Platform for WindowsPlatform {
    fn hosts_path() -> PathBuf {
        // Windows hosts file: %WINDIR%\System32\drivers\etc\hosts
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
        PathBuf::from(windir).join("System32\\drivers\\etc\\hosts")
    }

    fn config_path() -> PathBuf {
        // Check for config in order:
        // 1. %APPDATA%\proxychains\proxychains.conf
        // 2. %PROGRAMDATA%\proxychains\proxychains.conf
        // 3. Same directory as executable

        // Try APPDATA first
        if let Ok(appdata) = std::env::var("APPDATA") {
            let user_config = PathBuf::from(appdata).join("proxychains\\proxychains.conf");
            if user_config.exists() {
                return user_config;
            }
        }

        // Try PROGRAMDATA
        if let Ok(programdata) = std::env::var("PROGRAMDATA") {
            let system_config = PathBuf::from(programdata).join("proxychains\\proxychains.conf");
            if system_config.exists() {
                return system_config;
            }
        }

        // Try same directory as executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let local_config = exe_dir.join("proxychains.conf");
                if local_config.exists() {
                    return local_config;
                }
            }
        }

        // Default to APPDATA location (even if doesn't exist)
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata).join("proxychains\\proxychains.conf")
    }

    fn library_extension() -> &'static str {
        "dll"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_path() {
        let path = WindowsPlatform::hosts_path();
        assert!(path.ends_with("drivers\\etc\\hosts") || path.ends_with("drivers/etc/hosts"));
    }

    #[test]
    fn test_library_extension() {
        assert_eq!(WindowsPlatform::library_extension(), "dll");
    }
}
