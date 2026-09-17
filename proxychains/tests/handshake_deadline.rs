use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use proxychains::{ProxyData, ProxyType};
use proxychains::proxy::{tunnel_through_tcp_proxy, TargetAddress};

#[test]
fn slow_socks_stages_share_deadline_and_restore_timeouts() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        socket.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        socket.read_exact(&mut request).unwrap();
        // The second blocking read must use only the remaining budget.
        std::thread::sleep(Duration::from_millis(600));
        let _ = socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
    let proxy = ProxyData::new(Ipv4Addr::LOCALHOST, address.port(), ProxyType::Socks5);
    let start = Instant::now();
    let result = tunnel_through_tcp_proxy(&mut stream, &proxy,
        &TargetAddress::from_ip("192.0.2.1".parse().unwrap()), 443, Duration::from_millis(400));
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_millis(700), "deadline was restarted between stages");
    assert_eq!(stream.read_timeout().unwrap(), Some(Duration::from_secs(3)));
    assert_eq!(stream.write_timeout().unwrap(), Some(Duration::from_secs(4)));
    server.join().unwrap();
}
