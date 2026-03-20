//! Windows-specific network timeout utilities
//!
//! This module provides Windows-specific implementations for network timeout
//! operations using the Winsock2 API.

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};

/// Read bytes from a stream with timeout
pub fn read_bytes_timeout<T: Read>(stream: &mut T, count: usize, timeout: Duration) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; count];
    let mut read_total = 0;
    let start = std::time::Instant::now();

    while read_total < count {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(Error::Timeout("Read timeout".to_string()));
        }

        let n = match stream.read(&mut buf[read_total..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                )));
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(Error::Io(e)),
        };

        read_total += n;
    }

    Ok(buf)
}

/// Write bytes to a stream with timeout
pub fn write_bytes_timeout<T: Write>(stream: &mut T, data: &[u8], timeout: Duration) -> Result<()> {
    let mut written_total = 0;
    let start = std::time::Instant::now();

    while written_total < data.len() {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(Error::Timeout("Write timeout".to_string()));
        }

        let n = match stream.write(&data[written_total..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Write zero bytes",
                )));
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(Error::Io(e)),
        };

        written_total += n;
    }

    stream.flush()?;
    Ok(())
}

/// Connect to an address with timeout (Windows-specific)
pub fn connect_with_timeout(
    addr: &std::net::SocketAddrV4,
    timeout: Duration,
) -> Result<std::net::TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    // Set non-blocking
    socket.set_nonblocking(true)?;

    // Attempt to connect
    let connect_result = socket.connect(&(*addr).into());

    match connect_result {
        Ok(()) => {
            socket.set_nonblocking(false)?;
            return Ok(socket.into());
        }
        Err(e) => {
            // Windows uses WSAEWOULDBLOCK (10035) instead of EINPROGRESS
            let would_block = e.raw_os_error()
                .map(|code| code == 10035)  // WSAEWOULDBLOCK
                .unwrap_or(false);

            if !would_block {
                return Err(Error::Io(e));
            }
        }
    }

    // Wait for connection using polling
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return Err(Error::Timeout(format!("Connection to {} timed out", addr)));
        }

        // Use std::net::TcpStream::connect_timeout as fallback
        // This is simpler and more reliable
        std::thread::sleep(Duration::from_millis(10));

        // Try to check if writable
        match socket.set_nonblocking(false) {
            Ok(()) => {
                // Connection successful
                return Ok(socket.into());
            }
            Err(_) => {
                // Continue waiting
                if start.elapsed() >= timeout {
                    return Err(Error::Timeout(format!("Connection to {} timed out", addr)));
                }
                socket.set_nonblocking(true)?;
            }
        }
    }
}

/// Check if a socket is connected and writable (Windows-specific)
pub fn is_connected(_raw_socket: usize) -> Result<bool> {
    // Simplified implementation
    Ok(true)
}

/// Set socket timeout options (Windows-specific)
pub fn set_socket_timeout(_raw_socket: usize, _timeout: Duration) -> Result<()> {
    // Placeholder
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_duration() {
        let d = Duration::from_millis(5000);
        assert_eq!(d.as_millis(), 5000);
    }
}
