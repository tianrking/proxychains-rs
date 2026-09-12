fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sleep") {
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    if let Some(marker) = args.get(1) { std::fs::write(marker, b"started").unwrap(); }
    std::process::exit(23);
}
