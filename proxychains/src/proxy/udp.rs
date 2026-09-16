//! RFC 1928 UDP association transport. This does not intercept application sockets.
use super::{connect_to_proxy, AuthMethod, Socks5Connector, TargetAddress};
use crate::config::{ProxyData, ProxyType};
use crate::error::{Error, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}

fn encode_address(target: &TargetAddress, port: u16, out: &mut Vec<u8>) -> Result<()> {
    if let Some(domain) = target.domain() {
        if domain.is_empty() || domain.len() > 255 || domain.bytes().any(|b| b == 0) {
            return Err(Error::InvalidAddress);
        }
        out.extend([3, domain.len() as u8]);
        out.extend_from_slice(domain.as_bytes());
    } else {
        match target.ip().ok_or(Error::InvalidAddress)? {
            IpAddr::V4(ip) => {
                out.push(1);
                out.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(4);
                out.extend(ip.octets());
            }
        }
    }
    out.extend(port.to_be_bytes());
    Ok(())
}

fn read_address(input: &mut impl Read) -> Result<(TargetAddress, u16)> {
    let mut kind = [0];
    input.read_exact(&mut kind)?;
    let target = match kind[0] {
        1 => {
            let mut b = [0; 4];
            input.read_exact(&mut b)?;
            TargetAddress::from_ip(Ipv4Addr::from(b).into())
        }
        4 => {
            let mut b = [0; 16];
            input.read_exact(&mut b)?;
            TargetAddress::from_ip(Ipv6Addr::from(b).into())
        }
        3 => {
            let mut n = [0];
            input.read_exact(&mut n)?;
            if n[0] == 0 {
                return Err(Error::InvalidAddress);
            }
            let mut b = vec![0; n[0] as usize];
            input.read_exact(&mut b)?;
            let name = String::from_utf8(b).map_err(|_| Error::InvalidAddress)?;
            if name.bytes().any(|b| b == 0) {
                return Err(Error::InvalidAddress);
            }
            TargetAddress::from_domain(name)
        }
        _ => return Err(invalid("Unsupported UDP address type")),
    };
    let mut port = [0; 2];
    input.read_exact(&mut port)?;
    Ok((target, u16::from_be_bytes(port)))
}

/// Encode one unfragmented SOCKS5 UDP datagram.
pub fn encode_udp_datagram(target: &TargetAddress, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_address(target, port, &mut packet)?;
    if packet.len() + payload.len() > 65507 {
        return Err(invalid("UDP datagram exceeds transport limit"));
    }
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Decode a complete SOCKS5 datagram. Fragmentation is explicitly unsupported.
pub fn decode_udp_datagram(packet: &[u8]) -> Result<(TargetAddress, u16, &[u8])> {
    if packet.len() < 4 || packet[..2] != [0, 0] {
        return Err(invalid("Invalid UDP reserved header"));
    }
    if packet[2] != 0 {
        return Err(invalid("Fragmented SOCKS5 UDP datagrams are unsupported"));
    }
    let mut rest = &packet[3..];
    let (target, port) = read_address(&mut rest)?;
    Ok((target, port, rest))
}

/// A single SOCKS5 UDP association. Dropping it closes its TCP control channel.
pub struct UdpAssociation {
    control: UdpControl,
    socket: UdpSocket,
}

/// TCP lifetime and relay endpoint, also used by hooks with an application-owned socket.
pub(crate) struct UdpControl {
    control: TcpStream,
    relay: SocketAddr,
}
impl UdpAssociation {
    /// Adjust relay receive timeout after the control handshake completes.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket.set_read_timeout(timeout)?;
        Ok(())
    }
    pub fn connect(
        proxy: &ProxyData,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self> {
        let control = UdpControl::connect(proxy, connect_timeout, io_timeout)?;
        let relay = control.relay_addr();
        let bind = if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(relay)?;
        socket.set_read_timeout(Some(io_timeout))?;
        socket.set_write_timeout(Some(io_timeout))?;
        Ok(Self { control, socket })
    }
    pub fn send_to(&self, target: &TargetAddress, port: u16, payload: &[u8]) -> Result<usize> {
        self.control.check_control()?;
        let packet = encode_udp_datagram(target, port, payload)?;
        let sent = self.socket.send(&packet)?;
        if sent != packet.len() {
            return Err(invalid("Incomplete UDP datagram send"));
        }
        Ok(payload.len())
    }
    pub fn recv_from(&self) -> Result<(TargetAddress, u16, Vec<u8>)> {
        self.control.check_control()?;
        let mut packet = vec![0; 65535];
        let len = self.socket.recv(&mut packet)?;
        self.control.check_control()?;
        let (target, port, data) = decode_udp_datagram(&packet[..len])?;
        Ok((target, port, data.to_vec()))
    }
}

impl UdpControl {
    pub(crate) fn connect(
        proxy: &ProxyData,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self> {
        if proxy.proxy_type != ProxyType::Socks5 {
            return Err(invalid("UDP requires a SOCKS5 proxy"));
        }
        let mut control = connect_to_proxy(proxy, connect_timeout)?;
        control.set_read_timeout(Some(io_timeout))?;
        control.set_write_timeout(Some(io_timeout))?;
        let connector = Socks5Connector::new(proxy, io_timeout);
        if matches!(
            connector.negotiate_auth(&mut control)?,
            AuthMethod::UserPass
        ) {
            connector.authenticate(&mut control)?;
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
        let mut response = [0; 3];
        control.read_exact(&mut response)?;
        if response != [5, 0, 0] {
            return Err(invalid("SOCKS5 UDP ASSOCIATE rejected"));
        }
        let (relay, port) = read_address(&mut control)?;
        if port == 0 {
            return Err(invalid("SOCKS5 returned an invalid relay port"));
        }
        let peer = control.peer_addr()?;
        let relay = match relay {
            TargetAddress::Ip(ip) => {
                SocketAddr::new(if ip.is_unspecified() { peer.ip() } else { ip }, port)
            }
            TargetAddress::Domain(name) => (name.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or(Error::InvalidAddress)?,
            _ => return Err(Error::InvalidAddress),
        };
        control.set_nonblocking(true)?;
        Ok(Self { control, relay })
    }
    pub(crate) fn relay_addr(&self) -> SocketAddr {
        self.relay
    }
    pub(crate) fn check_control(&self) -> Result<()> {
        match self.control.peek(&mut [0]) {
            Ok(0) => Err(invalid("SOCKS5 UDP control connection closed")),
            Ok(_) => Err(invalid("Unexpected data on UDP control connection")),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn datagram_roundtrip_and_rejections() {
        for target in [
            TargetAddress::from_domain("dns.invalid"),
            TargetAddress::from_ip(Ipv4Addr::LOCALHOST.into()),
            TargetAddress::from_ip(Ipv6Addr::LOCALHOST.into()),
        ] {
            let packet = encode_udp_datagram(&target, 53, b"\x00\xffquery").unwrap();
            let (decoded, port, payload) = decode_udp_datagram(&packet).unwrap();
            assert_eq!(decoded.host(), target.host());
            assert_eq!(port, 53);
            assert_eq!(payload, b"\x00\xffquery");
            for len in 0..packet.len() - 7 {
                assert!(decode_udp_datagram(&packet[..len]).is_err());
            }
            let mut fragmented = packet.clone();
            fragmented[2] = 1;
            assert!(decode_udp_datagram(&fragmented).is_err());
        }
        assert!(
            encode_udp_datagram(&TargetAddress::from_domain("x".repeat(256)), 53, b"").is_err()
        );
        assert!(
            encode_udp_datagram(&TargetAddress::from_domain("x"), 53, &vec![0; 65507]).is_err()
        );
    }
    #[test]
    fn real_local_udp_association_roundtrip() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy = ProxyData::new(
            Ipv4Addr::LOCALHOST,
            tcp.local_addr().unwrap().port(),
            ProxyType::Socks5,
        );
        let server = std::thread::spawn(move || {
            let (mut control, _) = tcp.accept().unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut greeting = [0; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).unwrap();
            let mut request = [0; 10];
            control.read_exact(&mut request).unwrap();
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
            response.extend(udp.local_addr().unwrap().port().to_be_bytes());
            control.write_all(&response).unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut buf = [0; 1024];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            udp.send_to(&buf[..n], peer).unwrap();
            assert_eq!(control.read(&mut [0]).unwrap(), 0);
        });
        let association =
            UdpAssociation::connect(&proxy, Duration::from_secs(2), Duration::from_secs(2))
                .unwrap();
        association
            .send_to(&TargetAddress::from_domain("dns.invalid"), 53, b"query")
            .unwrap();
        let (target, port, data) = association.recv_from().unwrap();
        assert_eq!(target.host(), "dns.invalid");
        assert_eq!(port, 53);
        assert_eq!(data, b"query");
        drop(association);
        server.join().unwrap();
    }
}
