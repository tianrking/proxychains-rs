//! Windows-specific network timeout utilities
//!
//! This module provides Windows-specific implementations for network timeout
//! operations using the Winsock2 API.

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};

/// Read bytes from a stream with timeout
pub fn read_bytes_timeout<T: Read>(
    stream: &mut T,
    count: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
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
    addr: &std::net::SocketAddr,
    timeout: Duration,
) -> Result<std::net::TcpStream> {
    Ok(std::net::TcpStream::connect_timeout(addr, timeout)?)
}

/// Check if a socket is connected and writable (Windows-specific)
pub fn is_connected(raw_socket: usize) -> Result<bool> {
    let socket = unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(raw_socket as _) };
    let socket = socket2::SockRef::from(&socket);
    Ok(socket.take_error()?.is_none() && socket.peer_addr().is_ok())
}

/// Set socket timeout options (Windows-specific)
pub fn set_socket_timeout(raw_socket: usize, timeout: Duration) -> Result<()> {
    let socket = unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(raw_socket as _) };
    let socket = socket2::SockRef::from(&socket);
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
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
