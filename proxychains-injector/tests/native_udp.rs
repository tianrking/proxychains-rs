//! Native interception regression: the fixture knows only a normal UDP target.
//! The test proxy records SOCKS framing and the actual application source port.
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
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
        #[cfg(windows)]
        "udp-completion",
        "udp-iocp-cancel",
        "udp-v6relay",
    ];
    #[cfg(target_os = "linux")]
    modes.push("udp-recvmmsg-timeout");
    #[cfg(unix)]
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
            let sockets = if matches!(mode, "udp-iocp-cancel" | "udp-dup" | "udp-recvmmsg-timeout")
            {
                1
            } else {
                2
            };
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
                let rounds = if matches!(mode, "udp-iocp-cancel" | "udp-recvmmsg-timeout") {
                    1
                } else if mode == "udp-dup" {
                    2
                } else {
                    4
                };
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
                    if mode == "udp-recvmmsg-timeout" {
                        assert_eq!(&packet[header_len..n], b"batch-timeout");
                    } else if mode == "udp-dup" {
                        let expected: &[u8] = if round == 0 {
                            b"dup-original"
                        } else {
                            b"dup-clone"
                        };
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
    // A new UDP association skips a failed SOCKS5 node and uses the next
    // eligible node in the default proxy list.
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();
    std::fs::write(
        &config,
        format!(
            "proxy_udp\n[ProxyList]\nsocks5 127.0.0.1 {first_port}\nsocks5 127.0.0.1 {second_port}\n"
        ),
    )
    .unwrap();
    drop(first);
    second.set_nonblocking(true).unwrap();
    let failover_server = std::thread::spawn(move || {
        let mut control = accept(&second);
        let mut hello = [0; 3];
        control.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [5, 1, 0]);
        control.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        control.read_exact(&mut request).unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
        reply.extend(relay.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&reply).unwrap();
        let mut packet = [0; 1024];
        let (n, client) = relay.recv_from(&mut packet).unwrap();
        relay.send_to(&packet[..n], client).unwrap();
        assert_eq!(control.read(&mut [0]).unwrap(), 0);
    });
    assert_eq!(run(&library, &fixture, &config, "udp-failover"), 23);
    failover_server.join().unwrap();

    #[cfg(windows)]
    {
        // RIO exposes a proxy-backed extension table. The fixture exercises
        // registration, queue creation, send completion and cleanup.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        std::fs::write(
            &config,
            format!("proxy_udp\n[ProxyList]\nsocks5 127.0.0.1 {port}\n"),
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut control = accept(&listener);
            let mut hello = [0; 3];
            control.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 0]);
            control.write_all(&[5, 0]).unwrap();
            let mut request = [0; 10];
            control.read_exact(&mut request).unwrap();
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend(relay.local_addr().unwrap().port().to_be_bytes());
            control.write_all(&reply).unwrap();
            let mut packet = [0; 1024];
            let (n, client) = relay.recv_from(&mut packet).unwrap();
            assert_eq!(&packet[..3], &[0, 0, 0]);
            assert_eq!(&packet[3..8], &[1, 192, 0, 2, 123]);
            assert_eq!(&packet[8..10], &443u16.to_be_bytes());
            assert_eq!(&packet[10..n], &[0; 16]);
            relay.send_to(&packet[..n], client).unwrap();
            assert_eq!(control.read(&mut [0]).unwrap(), 0);
        });
        assert_eq!(run(&library, &fixture, &config, "udp-rio"), 23);
        server.join().unwrap();
    }

    // Exercise a real QUIC handshake and bidirectional stream through the
    // transparent SOCKS5 UDP path. The injected client targets the reserved
    // address; the relay forwards the inner QUIC datagrams to a local server.
    let (quic_target, quic_server) = spawn_quic_server();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    std::fs::write(
        &config,
        format!("proxy_udp\n[ProxyList]\nsocks5 127.0.0.1 {proxy_port}\n"),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let relay_server = std::thread::spawn(move || {
        let mut control = accept(&listener);
        let mut hello = [0; 3];
        control.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [5, 1, 0]);
        control.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        control.read_exact(&mut request).unwrap();
        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);

        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let forward = UdpSocket::bind("127.0.0.1:0").unwrap();
        forward
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
        response.extend(relay.local_addr().unwrap().port().to_be_bytes());
        control.write_all(&response).unwrap();

        let client = Arc::new(Mutex::new(None));
        let stopped = Arc::new(AtomicBool::new(false));
        let to_server = relay.try_clone().unwrap();
        let forward_to_server = forward.try_clone().unwrap();
        let target = quic_target;
        let client_for_send = Arc::clone(&client);
        let stopped_for_send = Arc::clone(&stopped);
        let send_thread = std::thread::spawn(move || {
            let mut packet = [0; 65535];
            while !stopped_for_send.load(Ordering::Acquire) {
                match to_server.recv_from(&mut packet) {
                    Ok((n, peer)) => {
                        assert!(n >= 10, "short SOCKS UDP packet");
                        *client_for_send.lock().unwrap() = Some(peer);
                        forward_to_server.send_to(&packet[10..n], target).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(error) => panic!("relay receive failed: {error}"),
                }
            }
        });

        let to_client = relay.try_clone().unwrap();
        let client_for_receive = Arc::clone(&client);
        let stopped_for_receive = Arc::clone(&stopped);
        let receive_thread = std::thread::spawn(move || {
            let mut payload = [0; 65535];
            while !stopped_for_receive.load(Ordering::Acquire) {
                match forward.recv_from(&mut payload) {
                    Ok((n, _)) => {
                        let Some(peer) = *client_for_receive.lock().unwrap() else {
                            continue;
                        };
                        let mut packet = vec![0, 0, 0, 1, 192, 0, 2, 123, 1, 187];
                        packet.extend_from_slice(&payload[..n]);
                        to_client.send_to(&packet, peer).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(error) => panic!("relay response failed: {error}"),
                }
            }
        });

        assert_eq!(control.read(&mut [0]).unwrap(), 0);
        stopped.store(true, Ordering::Release);
        send_thread.join().unwrap();
        receive_thread.join().unwrap();
    });
    assert_eq!(run(&library, &fixture, &config, "quic"), 23);
    relay_server.join().unwrap();
    quic_server.join().unwrap();

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

fn spawn_quic_server() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let certificate_der = rustls::pki_types::CertificateDer::from(certificate.cert);
            let private_key =
                rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
            let mut crypto = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
            crypto.alpn_protocols = vec![b"h3".to_vec()];
            let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
            ));
            let endpoint =
                quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            ready_sender.send(endpoint.local_addr().unwrap()).unwrap();
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let mut h3: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                    .await
                    .expect("http3 server init");
            let resolver = h3
                .accept()
                .await
                .expect("http3 request accept")
                .expect("http3 request stream");
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(request.uri().path(), "/quic");
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data("http3-proxy-response".into())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            endpoint.wait_idle().await;
        });
    });
    (ready_receiver.recv().unwrap(), thread)
}
