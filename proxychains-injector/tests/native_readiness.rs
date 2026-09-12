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
    child.kill().unwrap(); let _ = child.wait();
    assert!(result.is_err());
    assert!(alive, "failed attach must not terminate an existing process");
    assert!(retry.is_ok(), "corrected configuration must be retryable: {retry:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}
