//! SOCKS5 protocol implementation
//!
//! Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Authentication)

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::config::ProxyData;
use crate::error::{Error, Result};
use crate::net::{read_bytes_timeout, write_bytes_timeout};

/// SOCKS5 version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMethod {
    /// No authentication required
    NoAuth = 0x00,
    /// GSSAPI
    GssApi = 0x01,
    /// Username/Password authentication
    UserPass = 0x02,
    /// No acceptable methods
    NoAcceptable = 0xFF,
}

/// SOCKS5 commands
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

/// SOCKS5 address types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

/// SOCKS5 reply codes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl ReplyCode {
    fn from_u8(value: u8) -> Self {
        match value {
            0x00 => ReplyCode::Succeeded,
            0x01 => ReplyCode::GeneralFailure,
            0x02 => ReplyCode::ConnectionNotAllowed,
            0x03 => ReplyCode::NetworkUnreachable,
            0x04 => ReplyCode::HostUnreachable,
            0x05 => ReplyCode::ConnectionRefused,
            0x06 => ReplyCode::TtlExpired,
            0x07 => ReplyCode::CommandNotSupported,
            0x08 => ReplyCode::AddressTypeNotSupported,
            _ => ReplyCode::GeneralFailure,
        }
    }

    fn is_success(&self) -> bool {
        matches!(self, ReplyCode::Succeeded)
    }

    fn to_error(&self) -> Error {
        match self {
            ReplyCode::Succeeded => Error::Protocol("Unexpected success".to_string()),
            ReplyCode::GeneralFailure => Error::ProxyConnection("General SOCKS server failure".to_string()),
            ReplyCode::ConnectionNotAllowed => Error::Blocked,
            ReplyCode::NetworkUnreachable => Error::ProxyConnection("Network unreachable".to_string()),
            ReplyCode::HostUnreachable => Error::ProxyConnection("Host unreachable".to_string()),
            ReplyCode::ConnectionRefused => Error::ProxyConnection("Connection refused".to_string()),
            ReplyCode::TtlExpired => Error::ProxyConnection("TTL expired".to_string()),
            ReplyCode::CommandNotSupported => Error::Protocol("Command not supported".to_string()),
            ReplyCode::AddressTypeNotSupported => Error::Protocol("Address type not supported".to_string()),
        }
    }
}

/// Target address for SOCKS5 connection
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// IPv4 address
    Ip(Ipv4Addr),
    /// Domain name
    Domain(String),
}

impl TargetAddr {
    /// Create from IP address
    pub fn from_ip(ip: Ipv4Addr) -> Self {
        TargetAddr::Ip(ip)
    }

    /// Create from domain name
    pub fn from_domain(domain: &str) -> Self {
        TargetAddr::Domain(domain.to_string())
    }
}

/// SOCKS5 connector
pub struct Socks5Connector<'a> {
    proxy: &'a ProxyData,
    timeout: Duration,
}

impl<'a> Socks5Connector<'a> {
    /// Create a new SOCKS5 connector
    pub fn new(proxy: &'a ProxyData, timeout: Duration) -> Self {
        Self { proxy, timeout }
    }

    /// Connect to target through SOCKS5 proxy
    pub fn connect<T: Read + Write>(
        &self,
        stream: &mut T,
        target_addr: &TargetAddr,
        target_port: u16,
    ) -> Result<()> {
        // Step 1: Negotiate authentication method
        self.negotiate_auth(stream)?;

        // Step 2: Authenticate if required
        if self.proxy.user.is_some() {
            self.authenticate(stream)?;
        }

        // Step 3: Send CONNECT request
        self.send_connect_request(stream, target_addr, target_port)?;

        // Step 4: Read response
        self.read_connect_response(stream)?;

        Ok(())
    }

    /// Negotiate authentication method
    fn negotiate_auth<T: Read + Write>(&self, stream: &mut T) -> Result<()> {
        // Build greeting message
        let mut greeting = vec![SOCKS5_VERSION];

        if self.proxy.user.is_some() {
            // Offer both no-auth and user/pass methods
            greeting.push(2);
            greeting.push(AuthMethod::NoAuth as u8);
            greeting.push(AuthMethod::UserPass as u8);
        } else {
            // Only offer no-auth
            greeting.push(1);
            greeting.push(AuthMethod::NoAuth as u8);
        }

        // Send greeting
        write_bytes_timeout(stream, &greeting, self.timeout)?;

        // Read server's method selection
        let response = read_bytes_timeout(stream, 2, self.timeout)?;

        if response[0] != SOCKS5_VERSION {
            return Err(Error::Protocol(format!(
                "Invalid SOCKS version: {}",
                response[0]
            )));
        }

        let method = response[1];
        if method == AuthMethod::NoAcceptable as u8 {
            return Err(Error::AuthFailed(
                "No acceptable authentication method".to_string(),
            ));
        }

        // Check if the server selected a method we offered
        if method == AuthMethod::NoAuth as u8 {
            // No authentication required, we're done
            Ok(())
        } else if method == AuthMethod::UserPass as u8 {
            if self.proxy.user.is_none() {
                return Err(Error::AuthFailed(
                    "Server requires authentication but no credentials provided".to_string(),
                ));
            }
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "Server selected unsupported auth method: {}",
                method
            )))
        }
    }

    /// Perform username/password authentication (RFC 1929)
    fn authenticate<T: Read + Write>(&self, stream: &mut T) -> Result<()> {
        let user = self.proxy.user.as_ref().unwrap();
        let pass = self.proxy.pass.as_ref().unwrap();

        // Validate lengths
        if user.len() > 255 || pass.len() > 255 {
            return Err(Error::AuthFailed("Username or password too long".to_string()));
        }

        // Build auth request: [version][ulen][username][plen][password]
        let mut auth_request = Vec::with_capacity(3 + user.len() + pass.len());
        auth_request.push(0x01); // Sub-negotiation version
        auth_request.push(user.len() as u8);
        auth_request.extend_from_slice(user.as_bytes());
        auth_request.push(pass.len() as u8);
        auth_request.extend_from_slice(pass.as_bytes());

        // Send auth request
        write_bytes_timeout(stream, &auth_request, self.timeout)?;

        // Read auth response
        let response = read_bytes_timeout(stream, 2, self.timeout)?;

        if response[1] != 0x00 {
            return Err(Error::AuthFailed("Authentication failed".to_string()));
        }

        Ok(())
    }

    /// Send CONNECT request
    fn send_connect_request<T: Read + Write>(
        &self,
        stream: &mut T,
        target_addr: &TargetAddr,
        target_port: u16,
    ) -> Result<()> {
        let mut request = vec![
            SOCKS5_VERSION,
            Command::Connect as u8,
            0x00, // Reserved
        ];

        // Add address
        match target_addr {
            TargetAddr::Ip(ip) => {
                request.push(AddressType::Ipv4 as u8);
                request.extend_from_slice(&ip.octets());
            }
            TargetAddr::Domain(domain) => {
                if domain.len() > 255 {
                    return Err(Error::Protocol("Domain name too long".to_string()));
                }
                request.push(AddressType::DomainName as u8);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
            }
        }

        // Add port (big-endian)
        request.extend_from_slice(&target_port.to_be_bytes());

        // Send request
        write_bytes_timeout(stream, &request, self.timeout)?;

        Ok(())
    }

    /// Read CONNECT response
    fn read_connect_response<T: Read + Write>(&self, stream: &mut T) -> Result<()> {
        // Read header: [version][reply][reserved][atype]
        let header = read_bytes_timeout(stream, 4, self.timeout)?;

        if header[0] != SOCKS5_VERSION {
            return Err(Error::Protocol(format!(
                "Invalid SOCKS version in response: {}",
                header[0]
            )));
        }

        let reply = ReplyCode::from_u8(header[1]);
        if !reply.is_success() {
            return Err(reply.to_error());
        }

        // Read bound address based on address type
        let atyp = header[3];
        match atyp {
            0x01 => {
                // IPv4 - read 4 bytes + 2 bytes port
                let _ = read_bytes_timeout(stream, 6, self.timeout)?;
            }
            0x03 => {
                // Domain name - read length first
                let len_byte = read_bytes_timeout(stream, 1, self.timeout)?;
                let len = len_byte[0] as usize;

                // Read domain + port
                let _ = read_bytes_timeout(stream, len + 2, self.timeout)?;
            }
            0x04 => {
                // IPv6 - read 16 bytes + 2 bytes port
                let _ = read_bytes_timeout(stream, 18, self.timeout)?;
            }
            _ => {
                return Err(Error::Protocol(format!(
                    "Unknown address type in response: {}",
                    atyp
                )));
            }
        }

        Ok(())
    }
}

/// Connect to target through SOCKS5 proxy
pub fn socks5_connect<T: Read + Write>(
    stream: &mut T,
    proxy: &ProxyData,
    target_addr: &TargetAddr,
    target_port: u16,
    timeout: Duration,
) -> Result<()> {
    let connector = Socks5Connector::new(proxy, timeout);
    connector.connect(stream, target_addr, target_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_code_is_success() {
        assert!(ReplyCode::Succeeded.is_success());
        assert!(!ReplyCode::GeneralFailure.is_success());
    }

    #[test]
    fn test_target_addr() {
        let ip = TargetAddr::from_ip(Ipv4Addr::new(192, 168, 1, 1));
        assert!(matches!(ip, TargetAddr::Ip(_)));

        let domain = TargetAddr::from_domain("example.com");
        assert!(matches!(domain, TargetAddr::Domain(_)));
    }
}
