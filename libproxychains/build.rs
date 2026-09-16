fn main() {
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    // The shim is compiled when a Unix compiler is available.  Windows hosts
    // still need to be able to run cross-target `cargo check` without a
    // Linux/macOS C toolchain; Unix CI and native builds compile it normally.
    if host.contains("-linux-") || host.contains("-darwin") {
        assert!(target.contains("-linux-") || target.contains("-darwin"));
        cc::Build::new()
            .file("src/fcntl_shim.c")
            .warnings(true)
            .compile("proxychains_fcntl_shim");
    }
}
