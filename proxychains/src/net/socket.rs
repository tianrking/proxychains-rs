//! Socket utilities

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP address type union (compatible with C version)
#[repr(C)]
pub union IpType {
    pub octet: [u8; 4],
    pub as_int: u32,
}

impl IpType {
    pub fn new(octets: [u8; 4]) -> Self {
        Self { octet: octets }
    }

    pub fn from_int(val: u32) -> Self {
        Self { as_int: val.to_be() }
    }

    pub fn to_ipv4(&self) -> Ipv4Addr {
        // SAFETY: Both variants are [u8; 4] equivalent
        unsafe { Ipv4Addr::from(self.octet) }
    }

    pub fn from_ipv4(addr: &Ipv4Addr) -> Self {
        Self {
            octet: addr.octets(),
        }
    }
}

impl Default for IpType {
    fn default() -> Self {
        Self { octet: [0; 4] }
    }
}

impl Clone for IpType {
    fn clone(&self) -> Self {
        Self {
            octet: unsafe { self.octet },
        }
    }
}

impl Copy for IpType {}

impl std::fmt::Debug for IpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpType")
            .field("octet", unsafe { &self.octet })
            .finish()
    }
}

impl From<Ipv4Addr> for IpType {
    fn from(addr: Ipv4Addr) -> Self {
        Self::from_ipv4(&addr)
    }
}

impl From<u32> for IpType {
    fn from(val: u32) -> Self {
        Self::from_int(val)
    }
}

/// Create a TCP socket
pub fn create_tcp_socket() -> std::io::Result<std::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nodelay(true)?;

    Ok(socket.into())
}

/// Create a non-blocking TCP socket
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

/// Get the port from a sockaddr structure (platform-specific)
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_port_from_sockaddr(addr: *const libc::sockaddr) -> u16 {
    unsafe {
        let sa_family = (*addr).sa_family;
        if sa_family == libc::AF_INET as libc::sa_family_t {
            let addr_in = addr as *const libc::sockaddr_in;
            u16::from_be((*addr_in).sin_port)
        } else if sa_family == libc::AF_INET6 as libc::sa_family_t {
            let addr_in6 = addr as *const libc::sockaddr_in6;
            u16::from_be((*addr_in6).sin6_port)
        } else {
            0
        }
    }
}

/// Get the IP address from a sockaddr structure (platform-specific)
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_ip_from_sockaddr(addr: *const libc::sockaddr) -> Option<Ipv4Addr> {
    unsafe {
        let sa_family = (*addr).sa_family;
        if sa_family == libc::AF_INET as libc::sa_family_t {
            let addr_in = addr as *const libc::sockaddr_in;
            let ip_bytes = (*addr_in).sin_addr.s_addr.to_ne_bytes();
            Some(Ipv4Addr::from(ip_bytes))
        } else if sa_family == libc::AF_INET6 as libc::sa_family_t {
            let addr_in6 = addr as *const libc::sockaddr_in6;
            let v6 = Ipv6Addr::from((*addr_in6).sin6_addr.s6_addr);
            v6.to_ipv4_mapped()
        } else {
            None
        }
    }
}

/// Get IPv4/IPv6 address from sockaddr structure.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_ipaddr_from_sockaddr(addr: *const libc::sockaddr) -> Option<IpAddr> {
    unsafe {
        let sa_family = (*addr).sa_family;
        if sa_family == libc::AF_INET as libc::sa_family_t {
            let addr_in = addr as *const libc::sockaddr_in;
            let ip_bytes = (*addr_in).sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
        } else if sa_family == libc::AF_INET6 as libc::sa_family_t {
            let addr_in6 = addr as *const libc::sockaddr_in6;
            let octets = (*addr_in6).sin6_addr.s6_addr;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_type() {
        let ip = IpType::new([192, 168, 1, 1]);
        let ipv4 = ip.to_ipv4();
        assert_eq!(ipv4, Ipv4Addr::new(192, 168, 1, 1));
    }

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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_get_ip_from_sockaddr_ipv6_mapped() {
        let sockaddr = libc::sockaddr_in6 {
            #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
            sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 6, 7, 8],
            },
            sin6_scope_id: 0,
        };
        let ptr = &sockaddr as *const libc::sockaddr_in6 as *const libc::sockaddr;
        assert_eq!(get_ip_from_sockaddr(ptr), Some(Ipv4Addr::new(5, 6, 7, 8)));
    }
}
