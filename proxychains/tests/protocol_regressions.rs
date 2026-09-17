use proxychains::config::{ProxyData, ProxyType};
use proxychains::proxy::{
    establish_proxy_chain, http_connect, socks5_connect, TargetAddr, TargetAddress,
};
use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

struct Duplex {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Duplex {
    fn new(input: &[u8]) -> Self {
        Self {
            input: Cursor::new(input.to_vec()),
            output: vec![],
        }
    }
}
impl Read for Duplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}
impl Write for Duplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
const TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn socks_obeys_selected_authentication() {
    let mut proxy = ProxyData::new(Ipv4Addr::LOCALHOST, 1080, ProxyType::Socks5);
    proxy.user = Some("user".into());
    proxy.pass = Some("pass".into());
    for (reply, next_version) in [
        (vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0], 5),
        (vec![5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0], 1),
    ] {
        let mut io = Duplex::new(&reply);
        socks5_connect(
            &mut io,
            &proxy,
            &TargetAddr::from_domain("example.invalid"),
            443,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(io.output[4], next_version);
    }
    proxy.pass = None;
    assert!(socks5_connect(
        &mut Duplex::new(&[5, 2]),
        &proxy,
        &TargetAddr::from_domain("example.invalid"),
        443,
        TIMEOUT
    )
    .is_err());
}

#[test]
fn http_preserves_payload_and_formats_ipv6() {
    let proxy = ProxyData::new(Ipv4Addr::LOCALHOST, 8080, ProxyType::Http);
    let mut io = Duplex::new(b"HTTP/1.0 200 OK\r\n\r\nSSH-2.0-test\r\n");
    http_connect(&mut io, &proxy, "::1", 22, TIMEOUT).unwrap();
    assert!(io.output.starts_with(b"CONNECT [::1]:22 HTTP/1.0\r\n"));
    let mut payload = String::new();
    io.read_to_string(&mut payload).unwrap();
    assert_eq!(payload, "SSH-2.0-test\r\n");
    for reply in [
        b"HTTP/1.0 200 OK\r\n".as_slice(),
        b"BOGUS 200 OK\r\n\r\n",
        b"HTTP/1.1 407 Auth\r\n\r\n",
    ] {
        assert!(http_connect(
            &mut Duplex::new(reply),
            &proxy,
            "example.invalid",
            443,
            TIMEOUT
        )
        .is_err());
    }
    assert!(http_connect(
        &mut Duplex::new(b""),
        &proxy,
        "a\r\nInjected: x",
        443,
        TIMEOUT
    )
    .is_err());
}

#[test]
fn two_and_three_hop_chains_visit_every_node() {
    for hops in [2, 3] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut requests = vec![];
            for _ in 0..hops {
                let mut request = vec![];
                while !request.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    request.push(b[0]);
                }
                requests.push(String::from_utf8(request).unwrap());
                stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
            }
            requests
        });
        let mut proxies = vec![ProxyData::new(
            Ipv4Addr::LOCALHOST,
            first_port,
            ProxyType::Http,
        )];
        for i in 1..hops {
            proxies.push(ProxyData::new(
                Ipv4Addr::LOCALHOST,
                8000 + i as u16,
                ProxyType::Http,
            ));
        }
        let stream = establish_proxy_chain(
            &proxies,
            &TargetAddress::from_domain("target.invalid"),
            443,
            TIMEOUT,
            TIMEOUT,
        )
        .unwrap();
        assert_eq!(stream.read_timeout().unwrap(), None);
        let requests = server.join().unwrap();
        for i in 0..hops - 1 {
            assert!(requests[i].starts_with(&format!("CONNECT 127.0.0.1:{} ", 8001 + i)));
        }
        assert!(requests[hops - 1].starts_with("CONNECT target.invalid:443 "));
    }
}
