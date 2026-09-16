//! Native interception regression: the fixture knows only a normal UDP target.
//! The test proxy records SOCKS framing and the actual application source port.
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::time::{Duration, Instant};
#[cfg(unix)]
#[path = "support/process.rs"]
mod process;

#[test]
#[ignore = "requires built library and fixture via PROXYCHAINS_TEST_DLL / PROXYCHAINS_TEST_FIXTURE"]
fn native_udp_routing_and_lifecycle() {
    let library = std::env::var("PROXYCHAINS_TEST_DLL").expect("library required");
    let fixture = std::env::var("PROXYCHAINS_TEST_FIXTURE").expect("fixture required");
    let dir = std::env::temp_dir().join(format!("proxychains-native-udp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("udp.conf");
    #[allow(unused_mut)]
    let mut modes = vec![
        "udp",
        "udp-connected",
        "udp-domain",
        "udp-ipv6",
        "udp-vectored",
        "udp-iocp",
        "udp-iocp-sendmsg",
        "udp-iocp-recv",
        "udp-recvmsg",
        "udp-iocp-recvmsg",
        "udp-iocp-cancel",
        "udp-v6relay",
    ];
    #[cfg(target_os = "linux")]
    modes.push("udp-dup");
    for mode in modes {
        let ipv6 = mode == "udp-v6relay";
        let host = if ipv6 { "::1" } else { "127.0.0.1" };
        let listener = TcpListener::bind((host, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(&config, format!("strict_chain\nproxy_dns\nproxy_udp\n[ProxyList]\nsocks5 {host} {port} user password\n")).unwrap();
        let server = std::thread::spawn(move || {
            // Two successive sockets must each get a fresh control connection.
            let sockets = if matches!(mode, "udp-iocp-cancel" | "udp-dup") { 1 } else { 2 };
            for _ in 0..sockets {
                let deadline = Instant::now() + Duration::from_secs(15);
                let mut control = loop {
                    match listener.accept() {
                        Ok((control, _)) => break control,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => panic!("UDP ASSOCIATE did not arrive: {e}"),
                    }
                };
                control.set_nonblocking(false).unwrap();
                control
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut hello = [0; 4];
                control.read_exact(&mut hello).unwrap();
                assert_eq!(hello, [5, 2, 0, 2]);
                control.write_all(&[5, 2]).unwrap();
                let mut auth = [0; 15];
                control.read_exact(&mut auth).unwrap();
                assert_eq!(&auth, b"\x01\x04user\x08password");
                control.write_all(&[1, 0]).unwrap();
                let mut command = [0; 10];
                control.read_exact(&mut command).unwrap();
                assert_eq!(command, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
                let relay = UdpSocket::bind((host, 0)).unwrap();
                relay
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                // Wildcard BND.ADDR must use the TCP proxy address.
                let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
                if ipv6 {
                    reply = vec![5, 0, 0, 4];
                    reply.extend([0; 16]);
                }
                reply.extend(relay.local_addr().unwrap().port().to_be_bytes());
                control.write_all(&reply).unwrap();
                let rounds = if mode == "udp-iocp-cancel" { 1 } else if mode == "udp-dup" { 2 } else { 4 };
                for round in 0..rounds {
                    let mut packet = [0; 65535];
                    let (n, client) = relay.recv_from(&mut packet).unwrap();
                    assert_eq!(&packet[..3], &[0, 0, 0]);
                    let header_len = match mode {
                        "udp-domain" => {
                            assert_eq!(&packet[3..21], b"\x03\x10udp.test.invalid");
                            23
                        }
                        "udp-ipv6" | "udp-v6relay" => {
                            assert_eq!(packet[3], 4);
                            assert_eq!(
                                &packet[4..20],
                                &"2001:db8::123"
                                    .parse::<std::net::Ipv6Addr>()
                                    .unwrap()
                                    .octets()
                            );
                            22
                        }
                        _ => {
                            assert_eq!(&packet[3..8], &[1, 192, 0, 2, 123]);
                            10
                        }
                    };
                    assert_eq!(&packet[header_len - 2..header_len], &443u16.to_be_bytes());
                    if mode == "udp-dup" {
                        let expected: &[u8] = if round == 0 { b"dup-original" } else { b"dup-clone" };
                        assert_eq!(&packet[header_len..n], expected);
                    } else if round == 1 {
                        assert_eq!(n, header_len, "zero-length payload");
                    } else {
                        assert_eq!(
                            &packet[header_len..header_len + 2],
                            &client.port().to_be_bytes(),
                            "keep the application's bound socket"
                        );
                        assert_eq!(&packet[header_len + 2..n], b"native-udp-payload");
                    }
                    if mode == "udp-iocp-cancel" {
                        std::thread::sleep(Duration::from_millis(250));
                    }
                    // Reject a fragment without exposing framing or terminating the receive.
                    let mut fragment = packet[..n].to_vec();
                    fragment[2] = 1;
                    relay.send_to(&fragment, client).unwrap();
                    relay.send_to(&packet[..n], client).unwrap();
                }
                assert_eq!(
                    control.read(&mut [0]).unwrap(),
                    0,
                    "close releases control connection"
                );
            }
        });
        let status = run(&library, &fixture, &config, mode);
        server.join().unwrap();
        assert_eq!(status, 23, "native mode {mode}");
        // The proxy is gone: failure must not become a direct send.
        assert_eq!(run(&library, &fixture, &config, "udp-failure"), 23);
    }
    for response in [
        vec![5, 7, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        std::fs::write(
            &config,
            format!(
                "proxy_udp\n[ProxyList]\nsocks5 127.0.0.1 {}\n",
                listener.local_addr().unwrap().port()
            ),
        )
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut control = accept(&listener);
            let mut greeting = [0; 3];
            control.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).unwrap();
            let mut request = [0; 10];
            control.read_exact(&mut request).unwrap();
            control.write_all(&response).unwrap();
        });
        assert_eq!(run(&library, &fixture, &config, "udp-failure"), 23);
        server.join().unwrap();
    }
    // Closing TCP invalidates the association; later sends must not reach the relay.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(
        &config,
        format!(
            "proxy_udp\n[ProxyList]\nsocks5 127.0.0.1 {}\n",
            listener.local_addr().unwrap().port()
        ),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let mut control = accept(&listener);
        let mut greeting = [0; 3];
        control.read_exact(&mut greeting).unwrap();
        control.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        control.read_exact(&mut request).unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
        response.extend(relay.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&response).unwrap();
        let mut packet = [0; 1024];
        relay.recv_from(&mut packet).unwrap();
        control.shutdown(std::net::Shutdown::Both).unwrap();
        drop(control);
        relay
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        assert!(relay.recv_from(&mut packet).is_err());
    });
    assert_eq!(run(&library, &fixture, &config, "udp-control-closed"), 23);
    server.join().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => panic!("UDP fixture failed to connect: {e}"),
        }
    }
}

fn run(library: &str, fixture: &str, config: &std::path::Path, mode: &str) -> i32 {
    #[cfg(windows)]
    {
        use proxychains_injector::{ProcessInfo, ProxychainsInjector};
        std::env::set_var("PROXYCHAINS_CONF_FILE", config);
        ProxychainsInjector::new(std::path::Path::new(library))
            .unwrap()
            .spawn_inject_wait(&ProcessInfo {
                pid: None,
                name: None,
                command: fixture.into(),
                args: vec![mode.into()],
            })
            .unwrap()
    }
    #[cfg(unix)]
    {
        let mut command = std::process::Command::new(fixture);
        command.arg(mode).env("PROXYCHAINS_CONF_FILE", config);
        #[cfg(target_os = "linux")]
        command.env("LD_PRELOAD", library);
        #[cfg(target_os = "macos")]
        command
            .env("DYLD_INSERT_LIBRARIES", library)
            .env_remove("DYLD_FORCE_FLAT_NAMESPACE");
        process::status(&mut command).code().unwrap()
    }
}
