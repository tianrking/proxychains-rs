//! Unix platform implementation

use std::path::PathBuf;

use super::Platform;

/// Unix platform implementation
pub struct UnixPlatform;

impl Platform for UnixPlatform {
    fn hosts_path() -> PathBuf {
        PathBuf::from("/etc/hosts")
    }

    fn config_path() -> PathBuf {
        // Check for user config first, then system config
        if let Ok(home) = std::env::var("HOME") {
            let user_config = PathBuf::from(home).join(".proxychains/proxychains.conf");
            if user_config.exists() {
                return user_config;
            }
        }

        // Default system config locations
        let system_paths = [
            "/etc/proxychains.conf",
            "/usr/local/etc/proxychains.conf",
        ];

        for path in &system_paths {
            let p = PathBuf::from(path);
            if p.exists() {
                return p;
            }
        }

        // Return default if none exists
        PathBuf::from("/etc/proxychains.conf")
    }

    fn library_extension() -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "dylib"
        }
        #[cfg(not(target_os = "macos"))]
        {
            "so"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_path() {
        let path = UnixPlatform::hosts_path();
        assert_eq!(path.to_str(), Some("/etc/hosts"));
    }

    #[test]
    fn test_library_extension() {
        let ext = UnixPlatform::library_extension();
        assert!(!ext.is_empty());
    }
}
