use proxychains::ConfigParser;

#[test]
fn explicit_missing_config_never_falls_back_to_working_directory() {
    let path = std::env::temp_dir().join(format!("proxychains-missing-{}.conf", std::process::id()));
    assert!(!path.exists());
    let parser = ConfigParser::new().with_path(path.clone());
    assert_eq!(parser.find_config_file(), Some(path));
    assert!(parser.parse().is_err());
}
