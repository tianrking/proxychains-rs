use std::net::{TcpListener, Ipv4Addr};
use std::time::Duration;
use proxychains::{config::{ProxyData,ProxyType}, proxy::connect_to_proxy};

#[test]
fn ipv6_proxy_transport_and_refused_connections() {
    let listener=TcpListener::bind("[::1]:0").expect("IPv6 loopback required for transport test");
    let proxy=ProxyData::new_host("::1",listener.local_addr().unwrap().port(),ProxyType::Socks5);
    let stream=connect_to_proxy(&proxy,Duration::from_secs(1)).unwrap();
    assert!(stream.peer_addr().unwrap().is_ipv6());
    drop(stream); drop(listener);
    assert!(connect_to_proxy(&proxy,Duration::from_millis(200)).is_err());
    let ipv4=TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy=ProxyData::new(Ipv4Addr::LOCALHOST,ipv4.local_addr().unwrap().port(),ProxyType::Socks5);
    let stream=connect_to_proxy(&proxy,Duration::from_secs(1)).unwrap();
    #[cfg(windows)] {
        use std::os::windows::io::AsRawSocket;
        proxychains::net::set_socket_timeout(stream.as_raw_socket() as usize,Duration::from_secs(2)).unwrap();
        assert_eq!(stream.read_timeout().unwrap(),Some(Duration::from_secs(2)));
        assert!(proxychains::net::is_connected(stream.as_raw_socket() as usize).unwrap());
    }
    drop(stream);
}
