//! Configuration file parser

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::types::*;
use crate::error::{Error, Result};
use crate::platform;

/// Environment variable names
pub const ENV_CONF_FILE: &str = "PROXYCHAINS_CONF_FILE";
pub const ENV_QUIET_MODE: &str = "PROXYCHAINS_QUIET_MODE";
pub const ENV_SOCKS5_HOST: &str = "PROXYCHAINS_SOCKS5_HOST";
pub const ENV_SOCKS5_PORT: &str = "PROXYCHAINS_SOCKS5_PORT";
pub const ENV_DNS: &str = "PROXYCHAINS_DNS";
pub const ENV_PROXY_GROUP: &str = "PROXYCHAINS_PROXY_GROUP";

/// Configuration parser
pub struct ConfigParser {
    config_path: Option<PathBuf>,
    proxy_group: Option<String>,
}

impl ConfigParser {
    /// Create a new configuration parser
    pub fn new() -> Self {
        Self {
            config_path: None,
            proxy_group: None,
        }
    }

    /// Set the configuration file path
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Set proxy group name. Matches sections like [ProxyList:<group>].
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.proxy_group = Some(group.into());
        self
    }

    fn selected_group(&self) -> Option<String> {
        self.proxy_group
            .clone()
            .or_else(|| env::var(ENV_PROXY_GROUP).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Find the configuration file
    pub fn find_config_file(&self) -> Option<PathBuf> {
        // If path was explicitly set, use it
        if let Some(ref path) = self.config_path {
            if path.exists() {
                return Some(path.clone());
            }
        }

        // Check environment variable
        if let Ok(path) = env::var(ENV_CONF_FILE) {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        // Check standard locations
        let search_paths = vec![
            PathBuf::from("./proxychains.conf"),
            platform::config_path(),
            dirs::home_dir()
                .map(|h| h.join(".proxychains/proxychains.conf"))
                .unwrap_or_default(),
            PathBuf::from("/usr/local/etc/proxychains.conf"),
            PathBuf::from("/etc/proxychains.conf"),
        ];

        for path in search_paths {
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    /// Parse the configuration
    pub fn parse(&self) -> Result<Config> {
        // First check for simple SOCKS5 environment variables
        if let (Ok(host), Ok(port)) = (env::var(ENV_SOCKS5_HOST), env::var(ENV_SOCKS5_PORT)) {
            if let Ok(port) = port.parse::<u16>() {
                return self.parse_socks5_env(&host, port);
            }
        }

        // Find and parse config file
        if let Some(path) = self.find_config_file() {
            self.parse_file(&path)
        } else {
            // Return default config with no proxies
            let mut config = Config::default();
            self.apply_env_overrides(&mut config)?;
            Ok(config)
        }
    }

    /// Parse SOCKS5 from environment variables
    fn parse_socks5_env(&self, host: &str, port: u16) -> Result<Config> {
        let ip: Ipv4Addr = host.parse().map_err(|_| {
            Error::Config(format!("Invalid SOCKS5 host: {}", host))
        })?;

        let mut config = Config::default();
        config.proxy_dns = env::var(ENV_DNS).is_ok();
        config.quiet_mode = env::var(ENV_QUIET_MODE).is_ok();

        config.proxies.push(ProxyData::new(ip, port, ProxyType::Socks5));

        Ok(config)
    }

    /// Parse configuration from file
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<Config> {
        let path = path.as_ref();
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);

        let mut config = Config::default();
        let mut in_proxy_list = false;
        let selected_group = self.selected_group().map(|s| s.to_lowercase());
        let mut matched_selected_group = selected_group.is_none();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for section markers
            if trimmed.starts_with('[') {
                let section = trimmed
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .trim();
                let section_lower = section.to_lowercase();

                if section_lower.starts_with("proxylist") {
                    let group_name = section
                        .split_once(':')
                        .map(|(_, g)| g.trim().to_lowercase())
                        .filter(|g| !g.is_empty())
                        .unwrap_or_else(|| "default".to_string());

                    in_proxy_list = if let Some(ref selected) = selected_group {
                        let is_match = &group_name == selected;
                        if is_match {
                            matched_selected_group = true;
                        }
                        is_match
                    } else {
                        true
                    };
                } else {
                    in_proxy_list = false;
                }
                continue;
            }

            if in_proxy_list {
                self.parse_proxy_line(trimmed, &mut config)?;
            } else {
                self.parse_config_line(trimmed, &mut config)?;
            }
        }

        // Apply environment variable overrides
        self.apply_env_overrides(&mut config)?;

        if let Some(group) = selected_group {
            if !matched_selected_group {
                return Err(Error::Config(format!(
                    "Proxy group not found: {}",
                    group
                )));
            }
        }

        Ok(config)
    }

    /// List available proxy groups in the configuration file.
    ///
    /// Returns group names found in `[ProxyList]` and `[ProxyList:<name>]`
    /// sections. The unnamed default section is represented as `default`.
    pub fn list_proxy_groups(&self) -> Result<Vec<String>> {
        let path = self
            .find_config_file()
            .ok_or_else(|| Error::Config("Could not find configuration file".to_string()))?;
        self.list_proxy_groups_from_file(path)
    }

    /// List available proxy groups from a specific file.
    pub fn list_proxy_groups_from_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<String>> {
        let path = path.as_ref();
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut groups: Vec<String> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
                continue;
            }

            let section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim();
            if !section.to_lowercase().starts_with("proxylist") {
                continue;
            }

            let group_name = section
                .split_once(':')
                .map(|(_, g)| g.trim().to_lowercase())
                .filter(|g| !g.is_empty())
                .unwrap_or_else(|| "default".to_string());

            if !groups.iter().any(|g| g == &group_name) {
                groups.push(group_name);
            }
        }

        Ok(groups)
    }

    /// Parse a configuration line
    fn parse_config_line(&self, line: &str, config: &mut Config) -> Result<()> {
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.is_empty() {
            return Ok(());
        }

        let key = parts[0].to_lowercase();
        let value = parts.get(1).map(|s| s.trim()).unwrap_or("");

        match key.as_str() {
            "dynamic_chain" => config.chain_type = ChainType::Dynamic,
            "strict_chain" => config.chain_type = ChainType::Strict,
            "random_chain" => config.chain_type = ChainType::Random,
            "round_robin_chain" => config.chain_type = ChainType::LoadBalance,
            "load_balance" => config.chain_type = ChainType::LoadBalance,
            "failover" => config.chain_type = ChainType::Failover,
            "chain_len" => {
                config.chain_len = value.parse().ok();
            }
            "quiet_mode" => config.quiet_mode = true,
            "proxy_dns" => config.proxy_dns = true,
            // Compatibility aliases from proxychains-ng.
            "proxy_dns_old" => config.proxy_dns = true,
            "proxy_dns_daemon" => config.proxy_dns = true,
            "remote_dns_subnet" => {
                if let Ok(subnet) = value.parse() {
                    config.remote_dns_subnet = subnet;
                }
            }
            "tcp_read_time_out" => {
                if let Ok(timeout) = value.parse::<u64>() {
                    config.tcp_read_timeout = Duration::from_millis(timeout);
                }
            }
            "tcp_connect_time_out" => {
                if let Ok(timeout) = value.parse::<u64>() {
                    config.tcp_connect_timeout = Duration::from_millis(timeout);
                }
            }
            "max_chain_retries" => {
                if let Ok(retries) = value.parse::<usize>() {
                    // Keep a sensible floor to avoid accidental zero/retry-less configs.
                    config.max_chain_retries = retries.max(1);
                }
            }
            "localnet" => {
                self.parse_localnet(value, config)?;
            }
            "dnat" => {
                self.parse_dnat(value, config)?;
            }
            _ => {} // Ignore unknown options
        }

        Ok(())
    }

    /// Parse a localnet line
    fn parse_localnet(&self, value: &str, config: &mut Config) -> Result<()> {
        // Format: address/mask or address mask
        let parts: Vec<&str> = value.split(|c| c == '/' || c == ' ').collect();
        if parts.len() != 2 {
            return Err(Error::Config(format!("Invalid localnet format: {}", value)));
        }

        let address: Ipv4Addr = parts[0].parse().map_err(|_| {
            Error::Config(format!("Invalid localnet address: {}", parts[0]))
        })?;

        let netmask: Ipv4Addr = parts[1].parse().map_err(|_| {
            Error::Config(format!("Invalid localnet netmask: {}", parts[1]))
        })?;

        config.localnets.push(LocalNet::new(address, netmask));
        Ok(())
    }

    /// Parse a DNAT line
    fn parse_dnat(&self, value: &str, config: &mut Config) -> Result<()> {
        // Format: orig_addr:orig_port new_addr:new_port
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(Error::Config(format!("Invalid DNAT format: {}", value)));
        }

        let parse_addr_port = |s: &str| -> Result<(Ipv4Addr, u16)> {
            let ap: Vec<&str> = s.split(':').collect();
            if ap.len() != 2 {
                return Err(Error::Config(format!("Invalid address:port: {}", s)));
            }
            let addr: Ipv4Addr = ap[0].parse().map_err(|_| {
                Error::Config(format!("Invalid address: {}", ap[0]))
            })?;
            let port: u16 = ap[1].parse().map_err(|_| {
                Error::Config(format!("Invalid port: {}", ap[1]))
            })?;
            Ok((addr, port))
        };

        let (orig_addr, orig_port) = parse_addr_port(parts[0])?;
        let (new_addr, new_port) = parse_addr_port(parts[1])?;

        config.dnats.push(DnatRule::new(orig_addr, orig_port, new_addr, new_port));
        Ok(())
    }

    /// Parse a proxy line
    fn parse_proxy_line(&self, line: &str, config: &mut Config) -> Result<()> {
        // Format: type host port [user pass]
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::Config(format!("Invalid proxy line: {}", line)));
        }

        let proxy_type: ProxyType = parts[0].parse().map_err(|e| {
            Error::Config(e)
        })?;

        let ip: Ipv4Addr = parts[1].parse().map_err(|_| {
            Error::Config(format!("Invalid proxy host: {}", parts[1]))
        })?;

        let port: u16 = parts[2].parse().map_err(|_| {
            Error::Config(format!("Invalid proxy port: {}", parts[2]))
        })?;

        let mut proxy = ProxyData::new(ip, port, proxy_type);

        // Parse optional credentials
        if parts.len() >= 5 {
            proxy.user = Some(parts[3].to_string());
            proxy.pass = Some(parts[4].to_string());
        }

        config.proxies.push(proxy);
        Ok(())
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&self, config: &mut Config) -> Result<()> {
        if env::var(ENV_QUIET_MODE).is_ok() {
            config.quiet_mode = true;
        }

        if env::var(ENV_DNS).is_ok() {
            config.proxy_dns = true;
        }

        Ok(())
    }
}

impl Default for ConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple module to get home directory
mod dirs {
    use std::env;
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_parse_proxy_type() {
        assert_eq!(ProxyType::from_str("socks5").unwrap(), ProxyType::Socks5);
        assert_eq!(ProxyType::from_str("socks5h").unwrap(), ProxyType::Socks5);
        assert_eq!(ProxyType::from_str("SOCKS5").unwrap(), ProxyType::Socks5);
        assert_eq!(ProxyType::from_str("socks4").unwrap(), ProxyType::Socks4);
        assert_eq!(ProxyType::from_str("socks4a").unwrap(), ProxyType::Socks4);
        assert_eq!(ProxyType::from_str("http").unwrap(), ProxyType::Http);
        assert!(ProxyType::from_str("invalid").is_err());
    }

    #[test]
    fn test_localnet_contains() {
        let localnet = LocalNet::new(
            Ipv4Addr::new(192, 168, 0, 0),
            Ipv4Addr::new(255, 255, 0, 0),
        );

        assert!(localnet.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(localnet.contains(&Ipv4Addr::new(192, 168, 255, 255)));
        assert!(!localnet.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_proxy_group() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("proxychains_group_{}.conf", ts));
        let content = r#"
dynamic_chain
[ProxyList]
socks5 127.0.0.1 1080
[ProxyList:jp]
socks5 127.0.0.2 1080
"#;
        fs::write(&path, content).unwrap();

        let config = ConfigParser::new()
            .with_path(path.clone())
            .with_group("jp")
            .parse()
            .unwrap();
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].ip, Ipv4Addr::new(127, 0, 0, 2));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_missing_proxy_group_returns_error() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("proxychains_group_missing_{}.conf", ts));
        let content = r#"
[ProxyList]
socks5 127.0.0.1 1080
"#;
        fs::write(&path, content).unwrap();

        let err = ConfigParser::new()
            .with_path(path.clone())
            .with_group("us")
            .parse()
            .unwrap_err();
        assert!(format!("{}", err).contains("Proxy group not found"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_list_proxy_groups() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("proxychains_groups_{}.conf", ts));
        let content = r#"
[ProxyList]
socks5 127.0.0.1 1080
[ProxyList:JP]
socks5 127.0.0.2 1080
[ProxyList:us]
socks5 127.0.0.3 1080
"#;
        fs::write(&path, content).unwrap();

        let mut groups = ConfigParser::new()
            .list_proxy_groups_from_file(path.clone())
            .unwrap();
        groups.sort();
        assert_eq!(groups, vec!["default", "jp", "us"]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_proxychains_ng_compat_aliases() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("proxychains_compat_{}.conf", ts));
        let content = r#"
round_robin_chain
proxy_dns_old
[ProxyList]
socks5 127.0.0.1 1080
"#;
        fs::write(&path, content).unwrap();

        let config = ConfigParser::new().with_path(path.clone()).parse().unwrap();
        assert_eq!(config.chain_type, ChainType::LoadBalance);
        assert!(config.proxy_dns);

        let _ = fs::remove_file(path);
    }
}
