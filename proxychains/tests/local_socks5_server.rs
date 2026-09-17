use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxychains::{Config, LocalSocks5Credentials, LocalSocks5Server, ProxyData, ProxyType};

fn config(port: u16) -> Config {
    Config {
        proxies: vec![ProxyData::new(Ipv4Addr::LOCALHOST, port, ProxyType::Socks5)],
        ..Config::default()
    }
}

fn start_server(
    config: Config,
    credentials: Option<LocalSocks5Credentials>,
) -> (u16, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = shutdown.clone();
    let server = LocalSocks5Server::new(config, credentials, 4).unwrap();
    let handle = std::thread::spawn(move || server.serve(listener, stop).unwrap());
    (port, shutdown, handle)
}

#[test]
fn local_socks5_forwards_domain_connect_through_upstream_chain() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream = std::thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, [5, 1, 0, 3]);
        let mut length = [0; 1];
        stream.read_exact(&mut length).unwrap();
        let mut domain = vec![0; length[0] as usize];
        stream.read_exact(&mut domain).unwrap();
        assert_eq!(domain, b"agent.test");
        let mut port = [0; 2];
        stream.read_exact(&mut port).unwrap();
        assert_eq!(u16::from_be_bytes(port), 443);
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut payload = [0; 13];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"agent-request");
        stream.write_all(b"agent-response").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let (port, stop, server) = start_server(config(upstream_port), None);
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    client.write_all(&[5, 1, 0, 3, 10]).unwrap();
    client.write_all(b"agent.test").unwrap();
    client.write_all(&443u16.to_be_bytes()).unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0);
    client.write_all(b"agent-request").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = [0; 14];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"agent-response");
    upstream.join().unwrap();
    stop.store(true, Ordering::Release);
    server.join().unwrap();
}

#[test]
fn local_socks5_requires_configured_credentials() {
    let credentials = LocalSocks5Credentials::new("agent", "secret").unwrap();
    let (port, stop, server) = start_server(config(1), Some(credentials));

    let mut anonymous = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    anonymous.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    anonymous.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0xff]);

    let mut authenticated = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    authenticated.write_all(&[5, 1, 2]).unwrap();
    authenticated.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 2]);
    authenticated.write_all(b"\x01\x05agent\x06secret").unwrap();
    authenticated.read_exact(&mut method).unwrap();
    assert_eq!(method, [1, 0]);
    authenticated.shutdown(Shutdown::Both).unwrap();

    stop.store(true, Ordering::Release);
    server.join().unwrap();
}
