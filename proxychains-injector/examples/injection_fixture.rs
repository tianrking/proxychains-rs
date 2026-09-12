fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("tcp") {
        use std::io::{Read, Write};
        let mut stream = match std::net::TcpStream::connect(&args[2]) {
            Ok(stream) => stream,
            Err(_) => std::process::exit(24),
        };
        assert_eq!(stream.read_timeout().unwrap(), None, "hook must restore application timeout");
        assert_eq!(stream.write_timeout().unwrap(), None, "hook must restore application timeout");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
        stream.write_all(b"fixture-request").unwrap();
        let mut response = [0; 14];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"proxy-response");
        std::process::exit(23);
    }
    if args.get(1).map(String::as_str) == Some("sleep") {
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    if let Some(marker) = args.get(1) { std::fs::write(marker, b"started").unwrap(); }
    std::process::exit(23);
}
