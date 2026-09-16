//! Shared proxy health state used by independent connection attempts.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::config::ProxyData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProxyKey {
    protocol: HealthProtocol,
    proxy_type: crate::config::ProxyType,
    host: String,
    port: u16,
    user: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct HealthEntry {
    failures: u32,
    down_until: Instant,
}

static HEALTH: Lazy<Mutex<HashMap<ProxyKey, HealthEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn key(proxy: &ProxyData, protocol: HealthProtocol) -> ProxyKey {
    ProxyKey {
        protocol,
        proxy_type: proxy.proxy_type,
        host: proxy.host.trim().to_ascii_lowercase(),
        port: proxy.port,
        user: proxy.user.clone(),
    }
}

/// Return whether a proxy is currently eligible for a new connection.
pub fn is_available(proxy: &ProxyData, protocol: HealthProtocol) -> bool {
    let now = Instant::now();
    let mut health = HEALTH.lock();
    let proxy_key = key(proxy, protocol);
    match health.get(&proxy_key).copied() {
        Some(entry) if entry.down_until > now => false,
        Some(_) => {
            // Expired entries are removed so the next failure starts a fresh
            // bounded backoff window.
            health.remove(&proxy_key);
            true
        }
        None => true,
    }
}

/// Record a failed connection and suppress new attempts for `cooldown`.
pub fn mark_failure(proxy: &ProxyData, protocol: HealthProtocol, cooldown: Duration) {
    if cooldown.is_zero() {
        return;
    }
    let now = Instant::now();
    let mut health = HEALTH.lock();
    let proxy_key = key(proxy, protocol);
    let previous = health.get(&proxy_key).copied();
    let failures = previous.map_or(1, |entry| entry.failures.saturating_add(1));
    // Exponential backoff is capped so a long-lived process can recover from
    // a transient outage without requiring a restart.
    let multiplier = 1u32 << failures.saturating_sub(1).min(3);
    let effective = cooldown.checked_mul(multiplier).unwrap_or(cooldown);
    health.insert(
        proxy_key,
        HealthEntry {
            failures,
            down_until: now + effective,
        },
    );
}

/// Record a successful connection and clear any prior failure backoff.
pub fn mark_success(proxy: &ProxyData, protocol: HealthProtocol) {
    HEALTH.lock().remove(&key(proxy, protocol));
}

/// Clear all shared health state. Primarily useful for explicit state resets
/// and deterministic tests.
pub fn clear() {
    HEALTH.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyData, ProxyType};
    use std::net::Ipv4Addr;
    use std::thread;

    fn proxy() -> ProxyData {
        ProxyData::new(Ipv4Addr::LOCALHOST, 1080, ProxyType::Socks5)
    }

    #[test]
    fn failure_is_shared_until_cooldown_expires() {
        let proxy = proxy();
        assert!(is_available(&proxy, HealthProtocol::Tcp));
        mark_failure(&proxy, HealthProtocol::Tcp, Duration::from_millis(100));
        assert!(!is_available(&proxy, HealthProtocol::Tcp));
        assert!(is_available(&proxy, HealthProtocol::Udp));
        thread::sleep(Duration::from_millis(150));
        assert!(is_available(&proxy, HealthProtocol::Tcp));
    }

    #[test]
    fn success_clears_failure() {
        let proxy = ProxyData::new(Ipv4Addr::LOCALHOST, 1081, ProxyType::Socks5);
        mark_failure(&proxy, HealthProtocol::Udp, Duration::from_secs(60));
        assert!(!is_available(&proxy, HealthProtocol::Udp));
        mark_success(&proxy, HealthProtocol::Udp);
        assert!(is_available(&proxy, HealthProtocol::Udp));
    }
}
