#![cfg(unix)]
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires built library and fixture paths in PROXYCHAINS_TEST_DLL / PROXYCHAINS_TEST_FIXTURE"]
fn native_preload_tcp_and_invalid_config() {
    let library = std::env::var("PROXYCHAINS_TEST_DLL").expect("native library required");
    let fixture = std::env::var("PROXYCHAINS_TEST_FIXTURE").expect("native fixture required");
    let dir = std::env::temp_dir().join(format!("proxychains-preload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("proxy.conf");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(&config, format!("strict_chain\nproxy_dns\n[ProxyList]\nhttp 127.0.0.1 {port}\n")).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("preloaded client did not reach proxy: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0]; stream.read_exact(&mut byte).unwrap(); header.push(byte[0]); assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"CONNECT 192.0.2.123:443 HTTP/1.0\r\n"));
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nproxy-response").unwrap();
        let mut request = [0;15]; stream.read_exact(&mut request).unwrap(); assert_eq!(&request, b"fixture-request");
    });
    let command = || {
        let mut cmd = std::process::Command::new(&fixture);
        cmd.env("PROXYCHAINS_CONF_FILE", &config).env_remove("PROXYCHAINS_GROUP");
        #[cfg(target_os = "linux")]
        cmd.env("LD_PRELOAD", &library);
        #[cfg(target_os = "macos")]
        cmd.env("DYLD_INSERT_LIBRARIES", &library).env("DYLD_FORCE_FLAT_NAMESPACE", "1");
        cmd
    };
    let status = command().args(["tcp", "192.0.2.123:443"]).status().unwrap();
    server.join().unwrap(); assert_eq!(status.code(), Some(23));
    assert_eq!(command().args(["tcp", "192.0.2.123:443"]).status().unwrap().code(), Some(24));
    std::fs::write(&config, "[ProxyList]\nsocks5 INVALID_ENTRY\n").unwrap();
    let marker = dir.join("must-not-start");
    assert_eq!(command().arg(&marker).status().unwrap().code(), Some(127));
    assert!(!marker.exists());
    std::fs::remove_dir_all(dir).unwrap();
}
