//! SOCKS4 and SOCKS4a protocol implementation

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::ProxyData;
use crate::error::{Error, Result};
use crate::net::{read_bytes_timeout, write_bytes_timeout};

/// SOCKS4 version
const SOCKS4_VERSION: u8 = 0x04;

/// SOCKS4 commands
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
}

/// SOCKS4 reply codes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum ReplyCode {
    Granted = 0x5A,
    Rejected = 0x5B,
    IdentFailed = 0x5C,
    UserIdInvalid = 0x5D,
}

impl ReplyCode {
    fn from_u8(value: u8) -> Self {
        match value {
            0x5A => ReplyCode::Granted,
            0x5B => ReplyCode::Rejected,
            0x5C => ReplyCode::IdentFailed,
            0x5D => ReplyCode::UserIdInvalid,
            _ => ReplyCode::Rejected,
        }
    }

    fn is_success(&self) -> bool {
        matches!(self, ReplyCode::Granted)
    }

    fn to_error(&self) -> Error {
        match self {
            ReplyCode::Granted => Error::Protocol("Unexpected success".to_string()),
            ReplyCode::Rejected => Error::ProxyConnection("Request rejected or failed".to_string()),
            ReplyCode::IdentFailed => {
                Error::ProxyConnection("Request failed because identd unreachable".to_string())
            }
            ReplyCode::UserIdInvalid => {
                Error::ProxyConnection("Request rejected due to invalid user ID".to_string())
            }
        }
    }
}

/// SOCKS4 connector
pub struct Socks4Connector<'a> {
    proxy: &'a ProxyData,
    timeout: Duration,
}

impl<'a> Socks4Connector<'a> {
    /// Create a new SOCKS4 connector
    pub fn new(proxy: &'a ProxyData, timeout: Duration) -> Self {
        Self { proxy, timeout }
    }

    /// Connect to target through SOCKS4/4a proxy
    ///
    /// # Arguments
    /// * `stream` - Connected stream to proxy
    /// * `target_ip` - Target IP address (for SOCKS4)
    /// * `target_domain` - Target domain name (for SOCKS4a)
    /// * `target_port` - Target port
    ///
    /// If target_domain is Some, SOCKS4a protocol is used.
    /// Otherwise, SOCKS4 protocol is used with target_ip.
    pub fn connect<T: Read + Write>(
        &self,
        stream: &mut T,
        target_ip: &Ipv4Addr,
        target_domain: Option<&str>,
        target_port: u16,
    ) -> Result<()> {
        // Build request
        let mut request = Vec::new();

        // Version and command
        request.push(SOCKS4_VERSION);
        request.push(Command::Connect as u8);

        // Port (big-endian)
        request.extend_from_slice(&target_port.to_be_bytes());

        // IP address or SOCKS4a marker
        if let Some(domain) = target_domain {
            // SOCKS4a: use invalid IP 0.0.0.x where x != 0
            // Convention is to use 0.0.0.1 to 0.0.0.255
            request.extend_from_slice(&[0, 0, 0, 1]);
            // Null-terminated user ID
            if let Some(ref user) = self.proxy.user {
                request.extend_from_slice(user.as_bytes());
            }
            request.push(0); // Null terminator for user ID
            // Null-terminated domain name
            request.extend_from_slice(domain.as_bytes());
            request.push(0); // Null terminator for domain
        } else {
            // SOCKS4: use actual IP
            request.extend_from_slice(&target_ip.octets());
            // Null-terminated user ID
            if let Some(ref user) = self.proxy.user {
                request.extend_from_slice(user.as_bytes());
            }
            request.push(0); // Null terminator
        }

        // Send request
        write_bytes_timeout(stream, &request, self.timeout)?;

        // Read response (8 bytes)
        let response = read_bytes_timeout(stream, 8, self.timeout)?;

        // Check response
        if response[0] != 0x00 {
            return Err(Error::Protocol(format!(
                "Invalid SOCKS4 response null byte: {}",
                response[0]
            )));
        }

        let reply = ReplyCode::from_u8(response[1]);
        if !reply.is_success() {
            return Err(reply.to_error());
        }

        // Response bytes 2-7 contain port and IP (we don't need them)
        Ok(())
    }
}

/// Connect to target through SOCKS4 proxy
pub fn socks4_connect<T: Read + Write>(
    stream: &mut T,
    proxy: &ProxyData,
    target_ip: &Ipv4Addr,
    target_port: u16,
    timeout: Duration,
) -> Result<()> {
    let connector = Socks4Connector::new(proxy, timeout);
    connector.connect(stream, target_ip, None, target_port)
}

/// Connect to target through SOCKS4a proxy (with domain name)
pub fn socks4a_connect<T: Read + Write>(
    stream: &mut T,
    proxy: &ProxyData,
    target_ip: &Ipv4Addr,
    target_domain: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<()> {
    let connector = Socks4Connector::new(proxy, timeout);
    connector.connect(stream, target_ip, Some(target_domain), target_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_code() {
        assert!(ReplyCode::Granted.is_success());
        assert!(!ReplyCode::Rejected.is_success());
    }
}
