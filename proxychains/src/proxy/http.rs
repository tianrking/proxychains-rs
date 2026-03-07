//! HTTP CONNECT protocol implementation

use std::io::{BufRead, BufReader, Read, Write};
use std::time::Duration;

use crate::config::ProxyData;
use crate::error::{Error, Result};
use crate::net::write_bytes_timeout;

/// HTTP CONNECT connector
pub struct HttpConnector<'a> {
    proxy: &'a ProxyData,
    timeout: Duration,
}

impl<'a> HttpConnector<'a> {
    /// Create a new HTTP CONNECT connector
    pub fn new(proxy: &'a ProxyData, timeout: Duration) -> Self {
        Self { proxy, timeout }
    }

    /// Connect to target through HTTP CONNECT proxy
    ///
    /// # Arguments
    /// * `stream` - Connected stream to proxy
    /// * `target_host` - Target hostname or IP
    /// * `target_port` - Target port
    pub fn connect<T: Read + Write>(
        &self,
        stream: &mut T,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        // Build CONNECT request
        let mut request = format!(
            "CONNECT {}:{} HTTP/1.0\r\n",
            target_host, target_port
        );

        // Add authentication if credentials are provided
        if let (Some(user), Some(pass)) = (&self.proxy.user, &self.proxy.pass) {
            let credentials = format!("{}:{}", user, pass);
            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                credentials,
            );
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        // End headers
        request.push_str("\r\n");

        // Send request
        write_bytes_timeout(stream, request.as_bytes(), self.timeout)?;

        // Read response
        let response = self.read_response(stream)?;

        // Parse and validate response
        self.validate_response(&response)?;

        Ok(())
    }

    /// Read HTTP response from stream
    fn read_response<T: Read>(&self, stream: &mut T) -> Result<String> {
        let mut reader = BufReader::new(stream);
        let mut response = String::new();

        // Read until we get \r\n\r\n (end of headers)
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break; // EOF
            }

            response.push_str(&line);

            // Check for end of headers (empty line)
            if line == "\r\n" || line == "\n" {
                break;
            }

            // Safety check for response size
            if response.len() > 65536 {
                return Err(Error::Protocol("HTTP response too large".to_string()));
            }
        }

        Ok(response)
    }

    /// Validate HTTP response
    fn validate_response(&self, response: &str) -> Result<()> {
        // Parse status line
        let status_line = response
            .lines()
            .next()
            .ok_or_else(|| Error::Protocol("Empty HTTP response".to_string()))?;

        // Parse status code
        // Format: HTTP/1.x <status_code> <reason>
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::Protocol(format!(
                "Invalid HTTP response: {}",
                status_line
            )));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| Error::Protocol(format!("Invalid status code: {}", parts[1])))?;

        // Check for success (2xx)
        if !(200..300).contains(&status_code) {
            return Err(Error::ProxyConnection(format!(
                "HTTP proxy returned status {}",
                status_code
            )));
        }

        Ok(())
    }
}

/// Connect to target through HTTP CONNECT proxy
pub fn http_connect<T: Read + Write>(
    stream: &mut T,
    proxy: &ProxyData,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<()> {
    let connector = HttpConnector::new(proxy, timeout);
    connector.connect(stream, target_host, target_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_proxy() -> ProxyData {
        ProxyData::new(Ipv4Addr::new(192, 168, 1, 1), 8080, crate::config::ProxyType::Http)
    }

    #[test]
    fn test_response_validation() {
        let proxy = create_test_proxy();
        let connector = HttpConnector::new(&proxy, Duration::from_secs(5));

        // Valid 200 response
        assert!(connector.validate_response("HTTP/1.0 200 OK\r\n\r\n").is_ok());

        // Valid 2xx response
        assert!(connector.validate_response("HTTP/1.1 204 No Content\r\n\r\n").is_ok());

        // Invalid response (403)
        assert!(connector.validate_response("HTTP/1.0 403 Forbidden\r\n\r\n").is_err());
    }
}
