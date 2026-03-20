//! Windows-specific socket utilities
//!
//! This module provides Windows-specific implementations for socket operations
//! using the Winsock2 API.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Get the port from a SOCKADDR structure (Windows-specific)
#[cfg(windows)]
pub fn get_port_from_sockaddr(addr: *const core::ffi::c_void) -> u16 {
    unsafe {
        // SOCKADDR has sa_family at offset 0, followed by data
        let sa_family = *(addr as *const u16);
        // AF_INET = 2
        if sa_family == 2 {
            // SOCKADDR_IN structure:
            // sin_family: u16 (2 bytes)
            // sin_port: u16 (2 bytes) - network byte order
            let port_ptr = (addr as *const u8).add(2) as *const u16;
            u16::from_be(*port_ptr)
        } else if sa_family == 23 {
            // SOCKADDR_IN6 has the same port offset.
            let port_ptr = (addr as *const u8).add(2) as *const u16;
            u16::from_be(*port_ptr)
        } else {
            0
        }
    }
}

/// Get the IP address from a SOCKADDR structure (Windows-specific)
#[cfg(windows)]
pub fn get_ip_from_sockaddr(addr: *const core::ffi::c_void) -> Option<Ipv4Addr> {
    unsafe {
        let sa_family = *(addr as *const u16);
        // AF_INET = 2
        if sa_family == 2 {
            // SOCKADDR_IN structure:
            // sin_family: u16 (2 bytes)
            // sin_port: u16 (2 bytes)
            // sin_addr: in_addr (4 bytes)
            let ip_ptr = (addr as *const u8).add(4);
            let ip_bytes = [
                *ip_ptr,
                *ip_ptr.add(1),
                *ip_ptr.add(2),
                *ip_ptr.add(3),
            ];
            Some(Ipv4Addr::from(ip_bytes))
        } else if sa_family == 23 {
            // Handle IPv4-mapped IPv6 (::ffff:a.b.c.d) so reverse fake-DNS lookup works.
            let ip_ptr = (addr as *const u8).add(8);
            let mut octets = [0u8; 16];
            std::ptr::copy_nonoverlapping(ip_ptr, octets.as_mut_ptr(), 16);
            let v6 = Ipv6Addr::from(octets);
            v6.to_ipv4_mapped()
        } else {
            None
        }
    }
}

/// Get the IP address (IPv4/IPv6) from a SOCKADDR structure.
#[cfg(windows)]
pub fn get_ipaddr_from_sockaddr(addr: *const core::ffi::c_void) -> Option<IpAddr> {
    unsafe {
        let sa_family = *(addr as *const u16);
        if sa_family == 2 {
            let ip_ptr = (addr as *const u8).add(4);
            let ip_bytes = [*ip_ptr, *ip_ptr.add(1), *ip_ptr.add(2), *ip_ptr.add(3)];
            Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
        } else if sa_family == 23 {
            // SOCKADDR_IN6 layout:
            // sin6_family (2), sin6_port (2), sin6_flowinfo (4), sin6_addr (16), sin6_scope_id (4)
            let ip_ptr = (addr as *const u8).add(8);
            let mut octets = [0u8; 16];
            std::ptr::copy_nonoverlapping(ip_ptr, octets.as_mut_ptr(), 16);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }
}

/// Create a TCP socket (Windows-specific)
pub fn create_tcp_socket() -> std::io::Result<std::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nodelay(true)?;

    Ok(socket.into())
}

/// Create a non-blocking TCP socket (Windows-specific)
pub fn create_nonblocking_tcp_socket() -> std::io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}

/// Check if an IP is a private/local address
pub fn is_private_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    false
}

/// Check if an IP is localhost
pub fn is_localhost(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()
}

/// Check if an IP is the "any" address (0.0.0.0)
pub fn is_any_addr(ip: &Ipv4Addr) -> bool {
    ip.is_unspecified()
}

/// Check if an IP is a broadcast address
pub fn is_broadcast(ip: &Ipv4Addr) -> bool {
    ip.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_ip(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_localhost(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_ipv6_sockaddr_layout() {
        // Build a minimal SOCKADDR_IN6 byte layout.
        let mut raw = [0u8; 28];
        raw[0] = 23; // AF_INET6 low byte
        raw[1] = 0;
        raw[2] = 0x13; // port 4919 in network byte order
        raw[3] = 0x37;
        raw[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);

        let addr_ptr = raw.as_ptr() as *const core::ffi::c_void;
        assert_eq!(get_port_from_sockaddr(addr_ptr), 4919);
        assert_eq!(
            get_ipaddr_from_sockaddr(addr_ptr),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            )))
        );
    }

    #[test]
    fn test_get_ip_from_sockaddr_ipv6_mapped() {
        let mut raw = [0u8; 28];
        raw[0] = 23; // AF_INET6
        raw[1] = 0;
        raw[8..24].copy_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4,
        ]);
        let addr_ptr = raw.as_ptr() as *const core::ffi::c_void;
        assert_eq!(get_ip_from_sockaddr(addr_ptr), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }
}
