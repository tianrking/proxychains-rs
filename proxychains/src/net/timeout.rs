//! Network timeout utilities

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
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

        // Set read timeout on the stream
        let n = match stream.read(&mut buf[read_total..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF",
                )));
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Wait for data
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

/// Connect to an address with timeout
pub fn connect_with_timeout(addr: &std::net::SocketAddr, timeout: Duration) -> Result<std::net::TcpStream> {
    Ok(std::net::TcpStream::connect_timeout(addr, timeout)?)
}

/// Check if a socket is connected and writable
pub fn is_connected<F: AsRawFd>(fd: &F) -> Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };

    let result = unsafe { libc::poll(&mut poll_fd, 1, 0) };

    if result > 0 {
        // Check socket error
        let mut err: libc::c_int = 0;
        let mut err_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut libc::c_int as *mut libc::c_void,
                &mut err_len,
            )
        };

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        Ok(err == 0)
    } else {
        Ok(false)
    }
}

/// Set socket timeout options
pub fn set_socket_timeout<F: AsRawFd>(fd: &F, timeout: Duration) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: (timeout.subsec_micros() as libc::suseconds_t),
    };

    unsafe {
        let ret = libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        let ret = libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

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
