use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use proxychains::config::{ProxyData, ProxyType};
use proxychains::proxy::{
    http_connect, socks5_connect, establish_proxy_chain, TargetAddr, TargetAddress,
};

fn proxy_from_env(var: &str, proxy_type: ProxyType) -> Option<ProxyData> {
    let raw = std::env::var(var).ok()?;
    let addr: SocketAddr = raw.parse().ok()?;
    let ip = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };
    Some(ProxyData::new(ip, addr.port(), proxy_type))
}

#[test]
fn socks5_backend_handshake_works() {
    let Some(proxy) = proxy_from_env("PROXYCHAINS_TEST_SOCKS5_ADDR", ProxyType::Socks5) else {
        eprintln!("skip: PROXYCHAINS_TEST_SOCKS5_ADDR not set");
        return;
    };

    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(proxy.ip), proxy.port),
        Duration::from_secs(2),
    )
    .expect("connect socks5 proxy");

    let target = TargetAddr::from_domain("example.com");
    socks5_connect(&mut stream, &proxy, &target, 80, Duration::from_secs(8))
        .expect("socks5 connect to target");
}

#[test]
fn http_connect_backend_handshake_works() {
    let Some(proxy) = proxy_from_env("PROXYCHAINS_TEST_HTTP_ADDR", ProxyType::Http) else {
        eprintln!("skip: PROXYCHAINS_TEST_HTTP_ADDR not set");
        return;
    };

    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(proxy.ip), proxy.port),
        Duration::from_secs(2),
    )
    .expect("connect http proxy");

    http_connect(
        &mut stream,
        &proxy,
        "example.com",
        443,
        Duration::from_secs(8),
    )
    .expect("http CONNECT to target");
}

#[test]
fn establish_chain_with_real_socks5_works() {
    let Some(proxy) = proxy_from_env("PROXYCHAINS_TEST_SOCKS5_ADDR", ProxyType::Socks5) else {
        eprintln!("skip: PROXYCHAINS_TEST_SOCKS5_ADDR not set");
        return;
    };

    let target = TargetAddress::from_domain("example.com");
    let stream = establish_proxy_chain(
        &[proxy],
        &target,
        80,
        Duration::from_secs(3),
        Duration::from_secs(8),
    )
    .expect("establish chain to target via real socks5");

    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[test]
fn supports_group_probe_demo_shape() {
    // Sanity regression around types expected by CLI probe json output.
    let proxy = ProxyData::new(Ipv4Addr::new(127, 0, 0, 1), 1080, ProxyType::Socks5);
    assert_eq!(proxy.proxy_type.to_string(), "socks5");
}
