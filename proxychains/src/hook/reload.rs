//! Shared helpers for hook runtime reload behavior.

use std::time::Duration;

/// Environment variable to tune hook config reload interval.
pub const ENV_RELOAD_INTERVAL_MS: &str = "PROXYCHAINS_CONFIG_RELOAD_INTERVAL_MS";

/// Default reload interval used when env var is absent/invalid.
const DEFAULT_RELOAD_INTERVAL_MS: u64 = 2000;

/// Returns config reload interval for hook runtime.
///
/// Values <= 0 are ignored and default is used.
pub fn config_reload_interval() -> Duration {
    let value = std::env::var(ENV_RELOAD_INTERVAL_MS)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_RELOAD_INTERVAL_MS);
    Duration::from_millis(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_reload_interval() {
        std::env::remove_var(ENV_RELOAD_INTERVAL_MS);
        assert_eq!(config_reload_interval(), Duration::from_millis(2000));
    }
}
