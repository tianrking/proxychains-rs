#![cfg(windows)]
use proxychains_injector::{ProcessInfo, ProxychainsInjector};

#[test]
#[ignore = "requires built DLL and fixture paths in PROXYCHAINS_TEST_DLL / PROXYCHAINS_TEST_FIXTURE"]
fn native_readiness_and_failure_cleanup() {
    let dll = std::env::var_os("PROXYCHAINS_TEST_DLL").expect("DLL path required");
    let fixture = std::env::var("PROXYCHAINS_TEST_FIXTURE").expect("fixture path required");
    let dir = std::env::temp_dir().join(format!("proxychains native 测试 {}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("started marker");
    let config = dir.join("proxy.conf");
    std::fs::write(&config, "strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 9\n").unwrap();
    std::env::set_var("PROXYCHAINS_CONF_FILE", &config);
    let info = ProcessInfo { pid: None, name: None, command: fixture.clone(), args: vec![marker.to_string_lossy().into_owned()] };
    let invalid = dir.join("invalid.dll");
    std::fs::write(&invalid, b"not a DLL").unwrap();
    let bad = ProxychainsInjector::new(&invalid).unwrap();
    assert!(bad.spawn_inject_wait(&info).is_err());
    assert!(!marker.exists(), "invalid DLL must never start the payload");
    assert!(bad.spawn_inject_tree_wait(&info).is_err());
    assert!(!marker.exists());
    let good = ProxychainsInjector::new(std::path::Path::new(&dll)).unwrap();
    assert_eq!(good.spawn_inject_wait(&info).unwrap(), 23);
    assert_eq!(std::fs::read(&marker).unwrap(), b"started");
    std::fs::remove_file(&marker).unwrap();
    std::fs::write(&config, "[ProxyList]\nsocks5 INVALID_ENTRY\n").unwrap();
    assert!(good.spawn_inject_wait(&info).is_err());
    assert!(!marker.exists(), "loaded DLL with failed initialization must never start payload");
    let mut child = std::process::Command::new(&fixture).arg("sleep").spawn().unwrap();
    let result = good.inject_by_pid(child.id());
    let alive = child.try_wait().unwrap().is_none();
    std::fs::write(&config, "strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 9\n").unwrap();
    let retry = good.inject_by_pid(child.id());
    let exact_name = std::path::Path::new(&fixture).file_name().unwrap().to_string_lossy();
    let by_name = good.inject_by_name(&exact_name);
    let mut second = std::process::Command::new(&fixture).arg("sleep").spawn().unwrap();
    let ambiguous = good.inject_by_name(&exact_name);
    second.kill().unwrap(); let _ = second.wait();
    child.kill().unwrap(); let _ = child.wait();
    assert!(result.is_err());
    assert!(alive, "failed attach must not terminate an existing process");
    assert!(retry.is_ok(), "corrected configuration must be retryable: {retry:?}");
    assert!(by_name.is_ok(), "unique executable attachment: {by_name:?}");
    assert!(ambiguous.is_err(), "multiple processes require explicit PID");
    verify_tcp_routing(&good, &fixture, &config);
    verify_tcp_connectex(&good, &fixture, &config, "tcp-connectex");
    verify_tcp_connectex(&good, &fixture, &config, "tcp-connectex-iocp");
    verify_tcp_connectex_cancel(&good, &fixture, &config, "tcp-connectex-cancel");
    verify_tcp_connectex_cancel(&good, &fixture, &config, "tcp-connectex-cancel-iocp");
    verify_dns_exa(&good, &fixture, &config);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn verify_tcp_connectex_cancel(
    injector: &ProxychainsInjector,
    fixture: &str,
    config: &std::path::Path,
    mode: &str,
) {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(
        config,
        format!("strict_chain\nproxy_dns\n[ProxyList]\nhttp 127.0.0.1 {port}\n"),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if (e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(10035))
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("cancelled ConnectEx client did not reach mock proxy: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"CONNECT 192.0.2.123:443 HTTP/1.0\r\n"));
        // Keep the proxy handshake blocked long enough to prove cancellation,
        // rather than allowing the worker to finish with a transport error.
        std::thread::sleep(Duration::from_secs(2));
    });
    let info = ProcessInfo {
        pid: None,
        name: None,
        command: fixture.into(),
        args: vec![mode.into(), "192.0.2.123:443".into()],
    };
    assert_eq!(injector.spawn_inject_wait(&info).unwrap(), 23);
    server.join().unwrap();
}

fn verify_dns_exa(injector: &ProxychainsInjector, fixture: &str, config: &std::path::Path) {
    std::fs::write(config, "strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 9\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let info = ProcessInfo {
        pid: None,
        name: None,
        command: fixture.into(),
        args: vec!["dns-exa".into()],
    };
    assert_eq!(injector.spawn_inject_wait(&info).unwrap(), 23);
}

fn verify_tcp_connectex(injector: &ProxychainsInjector, fixture: &str, config: &std::path::Path, mode: &str) {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(config, format!("strict_chain\nproxy_dns\n[ProxyList]\nhttp 127.0.0.1 {port}\n")).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("ConnectEx client did not reach mock proxy: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0]; stream.read_exact(&mut byte).unwrap(); header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"CONNECT 192.0.2.123:443 HTTP/1.0\r\n"), "{}", String::from_utf8_lossy(&header));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        let mut request = [0; 17];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"connectex-request");
        stream.write_all(b"proxy-response").unwrap();
    });
    let info = ProcessInfo {
        pid: None,
        name: None,
        command: fixture.into(),
        args: vec![mode.into(), "192.0.2.123:443".into()],
    };
    assert_eq!(injector.spawn_inject_wait(&info).unwrap(), 23);
    server.join().unwrap();
}

fn verify_tcp_routing(injector: &ProxychainsInjector, fixture: &str, config: &std::path::Path) {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(config, format!("strict_chain\nproxy_dns\n[ProxyList]\nhttp 127.0.0.1 {port}\n")).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("injected process did not reach mock proxy: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0]; stream.read_exact(&mut byte).unwrap(); header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"CONNECT 192.0.2.123:443 HTTP/1.0\r\n"), "{}", String::from_utf8_lossy(&header));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nproxy-response").unwrap();
        let mut request = [0;15]; stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"fixture-request");
    });
    let info = ProcessInfo { pid: None, name: None, command: fixture.into(), args: vec!["tcp".into(), "192.0.2.123:443".into()] };
    let status = injector.spawn_inject_wait(&info);
    server.join().unwrap();
    assert_eq!(status.unwrap(), 23, "injected TCP tunnel must preserve payload");
    // The mock listener has closed. A failed proxy must report failure to this client.
    assert_eq!(injector.spawn_inject_wait(&info).unwrap(), 24);
}
