//! Proxychains4 CLI binary
//!
//! This is the main entry point for running commands through proxy chains.
//!
//! Platform support:
//! - Unix (Linux/macOS): Uses LD_PRELOAD/DYLD_INSERT_LIBRARIES
//! - Windows: Uses DLL injection

use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

use proxychains::{Config, ConfigParser};

/// Proxychains4 - Run commands through proxy chains
#[derive(Parser, Debug)]
#[command(name = "proxychains4")]
#[command(author = "Proxychains Rust Team")]
#[command(version)]
#[command(about = "Run commands through a chain of proxies", long_about = None)]
struct Args {
    /// Quiet mode - suppress output
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Configuration file path
    #[arg(short = 'f', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Print debug information
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Proxy group name, matches config sections like [ProxyList:<group>]
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,

    /// List available proxy groups from config and exit
    #[arg(long)]
    list_groups: bool,

    /// Validate config and print selected proxies without running command
    #[arg(long)]
    check: bool,

    /// Probe configured proxy nodes and print per-node reachability
    #[arg(long)]
    probe: bool,

    /// Probe timeout in milliseconds (default: config tcp_connect_time_out)
    #[arg(long, value_name = "MS")]
    probe_timeout_ms: Option<u64>,

    /// Print probe result as JSON (machine-readable)
    #[arg(long)]
    probe_json: bool,

    /// The command to run
    #[arg(
        required_unless_present_any = ["list_groups", "check", "probe"],
        trailing_var_arg = true
    )]
    command: Vec<String>,
}

fn main() {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else if args.quiet {
        Level::ERROR
    } else {
        Level::INFO
    };

    if !args.quiet {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(log_level)
            .with_target(false)
            .compact()
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }

    if args.list_groups {
        if let Err(e) = list_groups(&args) {
            if !args.quiet {
                eprintln!("proxychains: {}", e);
            }
            process::exit(1);
        }
        process::exit(0);
    }

    // Parse configuration
    let config = load_config(&args);

    if config.is_err() {
        if !args.quiet {
            eprintln!("proxychains: {}", config.as_ref().unwrap_err());
        }
        process::exit(1);
    }

    let config = config.unwrap();

    // Check if we have proxies configured
    if !config.has_proxies() {
        if !args.quiet {
            eprintln!("proxychains: No proxies configured");
        }
        process::exit(1);
    }

    if !args.quiet {
        info!("Proxychains4 starting...");
        info!("Chain type: {}", config.chain_type);
        info!("Proxies: {}", config.proxy_count());
        if let Some(group) = args.group.as_deref() {
            info!("Proxy group: {}", group);
        }
    }

    if args.check {
        print_check_summary(&config, &args);
        process::exit(0);
    }

    if args.probe {
        let failed = run_probe(&config, &args);
        process::exit(if failed == 0 { 0 } else { 2 });
    }

    // Execute the command with platform-specific injection
    match execute_command(&args, &config) {
        Ok(status) => {
            process::exit(status);
        }
        Err(e) => {
            if !args.quiet {
                error!("Failed to execute command: {}", e);
            }
            process::exit(1);
        }
    }
}

/// Load configuration from file or environment
fn load_config(args: &Args) -> Result<Config, String> {
    build_parser(args).parse().map_err(|e| e.to_string())
}

fn build_parser(args: &Args) -> ConfigParser {
    let mut parser = ConfigParser::new();

    if let Some(ref path) = args.config {
        parser = parser.with_path(path.clone());
    }

    if let Some(ref group) = args.group {
        parser = parser.with_group(group.clone());
    }

    parser
}

fn list_groups(args: &Args) -> Result<(), String> {
    let parser = build_parser(args);
    let mut groups = parser.list_proxy_groups().map_err(|e| e.to_string())?;
    groups.sort();
    if groups.is_empty() {
        println!("No [ProxyList] groups found in config");
        return Ok(());
    }
    for group in groups {
        println!("{}", group);
    }
    Ok(())
}

fn print_check_summary(config: &Config, args: &Args) {
    println!("Config check: OK");
    println!("Chain type: {}", config.chain_type);
    println!("Proxy count: {}", config.proxy_count());
    println!("Proxy DNS: {}", config.proxy_dns);
    println!(
        "Selected group: {}",
        args.group.as_deref().unwrap_or("default/all")
    );
    for (idx, proxy) in config.proxies.iter().enumerate() {
        let auth = if proxy.user.is_some() { "auth" } else { "no-auth" };
        println!(
            "  {}. {} {}:{} ({})",
            idx + 1,
            proxy.proxy_type,
            proxy.ip,
            proxy.port,
            auth
        );
    }
}

fn run_probe(config: &Config, args: &Args) -> usize {
    let timeout = args
        .probe_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(config.tcp_connect_timeout);
    let mut failed = 0usize;
    let mut results = Vec::with_capacity(config.proxies.len());
    let selected_group = args.group.as_deref().unwrap_or("default/all").to_string();

    for (idx, proxy) in config.proxies.iter().enumerate() {
        let target_v4 = SocketAddrV4::new(proxy.ip, proxy.port);
        let target = SocketAddr::V4(target_v4);
        let start = Instant::now();
        match TcpStream::connect_timeout(&target, timeout) {
            Ok(stream) => {
                let elapsed = start.elapsed().as_millis();
                let _ = stream.shutdown(std::net::Shutdown::Both);
                results.push(ProbeNode {
                    index: idx + 1,
                    proxy_type: proxy.proxy_type.to_string(),
                    address: format!("{}:{}", proxy.ip, proxy.port),
                    ok: true,
                    latency_ms: elapsed,
                    failure_type: None,
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                let elapsed = start.elapsed().as_millis();
                let failure_type = classify_probe_error(&e).to_string();
                results.push(ProbeNode {
                    index: idx + 1,
                    proxy_type: proxy.proxy_type.to_string(),
                    address: format!("{}:{}", proxy.ip, proxy.port),
                    ok: false,
                    latency_ms: elapsed,
                    failure_type: Some(failure_type),
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let report = build_probe_report(results, timeout, selected_group);
    if args.probe_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print_probe_report(&report);
    }
    failed
}

fn classify_probe_error(err: &std::io::Error) -> &'static str {
    match err.kind() {
        ErrorKind::TimedOut => "timeout",
        ErrorKind::ConnectionRefused => "refused",
        ErrorKind::ConnectionReset => "reset",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::AddrNotAvailable => "addr_unavailable",
        ErrorKind::NotConnected => "not_connected",
        _ => "other",
    }
}

fn build_probe_report(results: Vec<ProbeNode>, timeout: Duration, group: String) -> ProbeReport {
    let total = results.len();
    let ok = results.iter().filter(|r| r.ok).count();
    let fail = total.saturating_sub(ok);
    let mut stats = ProbeFailureStats::default();
    for r in &results {
        if r.ok {
            continue;
        }
        match r.failure_type.as_deref() {
            Some("timeout") => stats.timeout += 1,
            Some("refused") => stats.refused += 1,
            Some("reset") => stats.reset += 1,
            Some("network_unreachable") => stats.network_unreachable += 1,
            Some("addr_unavailable") => stats.addr_unavailable += 1,
            Some("not_connected") => stats.not_connected += 1,
            _ => stats.other += 1,
        }
    }
    ProbeReport {
        schema_version: "1.0".to_string(),
        generated_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        timeout_ms: timeout.as_millis(),
        selected_group: group,
        summary: ProbeSummary { total, ok, fail },
        failure_stats: stats,
        nodes: results,
    }
}

fn print_probe_report(report: &ProbeReport) {
    println!("Proxy probe:");
    println!("  timeout_ms={}", report.timeout_ms);
    println!("  group={}", report.selected_group);
    for n in &report.nodes {
        if n.ok {
            println!(
                "  [{}] OK   {:<8} {}  {} ms",
                n.index, n.proxy_type, n.address, n.latency_ms
            );
        } else {
            println!(
                "  [{}] FAIL {:<8} {}  {} ms  [{}] ({})",
                n.index,
                n.proxy_type,
                n.address,
                n.latency_ms,
                n.failure_type.as_deref().unwrap_or("other"),
                n.error.as_deref().unwrap_or("unknown")
            );
        }
    }
    println!(
        "Probe summary: total={}, ok={}, fail={}",
        report.summary.total, report.summary.ok, report.summary.fail
    );
    println!(
        "Failure stats: timeout={}, refused={}, reset={}, net_unreach={}, addr_unavail={}, not_connected={}, other={}",
        report.failure_stats.timeout,
        report.failure_stats.refused,
        report.failure_stats.reset,
        report.failure_stats.network_unreachable,
        report.failure_stats.addr_unavailable,
        report.failure_stats.not_connected,
        report.failure_stats.other
    );
}

#[derive(Debug, Serialize)]
struct ProbeReport {
    schema_version: String,
    generated_at: u64,
    timeout_ms: u128,
    selected_group: String,
    summary: ProbeSummary,
    failure_stats: ProbeFailureStats,
    nodes: Vec<ProbeNode>,
}

#[derive(Debug, Serialize)]
struct ProbeSummary {
    total: usize,
    ok: usize,
    fail: usize,
}

#[derive(Debug, Serialize, Default)]
struct ProbeFailureStats {
    timeout: usize,
    refused: usize,
    reset: usize,
    network_unreachable: usize,
    addr_unavailable: usize,
    not_connected: usize,
    other: usize,
}

#[derive(Debug, Serialize)]
struct ProbeNode {
    index: usize,
    proxy_type: String,
    address: String,
    ok: bool,
    latency_ms: u128,
    failure_type: Option<String>,
    error: Option<String>,
}

/// Set proxychains-specific environment variables
fn set_proxychains_env(config: &Config, args: &Args) {
    if args.quiet {
        env::set_var("PROXYCHAINS_QUIET_MODE", "1");
    }

    if config.proxy_dns {
        env::set_var("PROXYCHAINS_DNS", "1");
    }

    if let Some(ref path) = args.config {
        env::set_var("PROXYCHAINS_CONF_FILE", path);
    }

    if let Some(ref group) = args.group {
        env::set_var("PROXYCHAINS_PROXY_GROUP", group);
    }
}

// ============================================================================
// Unix Implementation (LD_PRELOAD/DYLD_INSERT_LIBRARIES)
// ============================================================================

#[cfg(unix)]
fn execute_command(args: &Args, config: &Config) -> Result<i32, String> {
    use std::ffi::CString;

    if args.command.is_empty() {
        return Err("No command specified".to_string());
    }

    // Find the library path
    let library_path = find_library_path()?;

    debug!("Library path: {}", library_path);

    // Set environment variables
    set_preload_env(&library_path)?;

    // Set proxychains environment variables
    set_proxychains_env(config, args);

    // Build command arguments
    let program = &args.command[0];
    let c_args: Vec<CString> = args
        .command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    let c_argv: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    debug!("Executing: {}", program);

    // Execute the command
    unsafe {
        let ret = libc::execvp(
            CString::new(program.as_str()).unwrap().as_ptr(),
            c_argv.as_ptr(),
        );

        if ret < 0 {
            return Err(format!("execvp failed: {}", std::io::Error::last_os_error()));
        }
    }

    Ok(0)
}

/// Find the proxychains library path (Unix)
#[cfg(unix)]
fn find_library_path() -> Result<String, String> {
    // Try common locations
    let search_paths = vec![
        // Same directory as binary
        get_binary_dir()
            .map(|d| d.join("libproxychains.dylib"))
            .unwrap_or_default(),
        get_binary_dir()
            .map(|d| d.join("libproxychains.so"))
            .unwrap_or_default(),
        // Build directory
        PathBuf::from("./target/release/libproxychains.dylib"),
        PathBuf::from("./target/release/libproxychains.so"),
        PathBuf::from("./target/debug/libproxychains.dylib"),
        PathBuf::from("./target/debug/libproxychains.so"),
        // System paths
        PathBuf::from("/usr/local/lib/libproxychains.dylib"),
        PathBuf::from("/usr/local/lib/libproxychains.so"),
        PathBuf::from("/usr/lib/libproxychains.so"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/libproxychains.so"),
    ];

    for path in search_paths {
        if path.exists() {
            return Ok(path.to_string_lossy().to_string());
        }
    }

    // Try to find via environment variable
    if let Ok(path) = env::var("PROXYCHAINS_LIB") {
        return Ok(path);
    }

    Err("Could not find libproxychains library".to_string())
}

/// Set LD_PRELOAD environment variable (Unix)
#[cfg(unix)]
fn set_preload_env(library_path: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        env::set_var("LD_PRELOAD", library_path);
        debug!("Set LD_PRELOAD={}", library_path);
    }

    #[cfg(target_os = "macos")]
    {
        env::set_var("DYLD_INSERT_LIBRARIES", library_path);
        env::set_var("DYLD_FORCE_FLAT_NAMESPACE", "1");
        debug!("Set DYLD_INSERT_LIBRARIES={}", library_path);
    }

    Ok(())
}

// ============================================================================
// Windows Implementation (DLL Injection)
// ============================================================================

#[cfg(windows)]
fn execute_command(args: &Args, config: &Config) -> Result<i32, String> {
    use proxychains_injector::{ProxychainsInjector, ProcessInfo, find_library_path};

    if args.command.is_empty() {
        return Err("No command specified".to_string());
    }

    // Find the DLL path
    let dll_path = find_library_path().map_err(|e| e.to_string())?;

    debug!("DLL path: {:?}", dll_path);

    // Set proxychains environment variables
    set_proxychains_env(config, args);

    // Create the injector
    let injector = ProxychainsInjector::new(&dll_path)
        .map_err(|e| format!("Failed to create injector: {}", e))?;

    // Create process info
    let process_info = ProcessInfo {
        pid: None,
        name: None,
        command: args.command[0].clone(),
        args: args.command[1..].to_vec(),
    };

    debug!("Spawning and injecting: {:?}", process_info);

    // Spawn the process and inject DLL
    let mut child = injector
        .spawn_and_inject(&process_info)
        .map_err(|e| format!("Failed to spawn and inject: {}", e))?;

    // Wait for the process to complete
    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for process: {}", e))?;

    let exit_code = status
        .code()
        .unwrap_or(1);

    info!("Process exited with code: {}", exit_code);

    Ok(exit_code)
}

// ============================================================================
// Common Functions
// ============================================================================

/// Get the directory containing the current binary
fn get_binary_dir() -> Option<PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::try_parse_from(["proxychains4", "curl", "https://example.com"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.command, vec!["curl", "https://example.com"]);
        assert!(!args.quiet);
    }

    #[test]
    fn test_args_with_options() {
        let args = Args::try_parse_from([
            "proxychains4",
            "-q",
            "-f",
            "/etc/proxychains.conf",
            "--group",
            "jp",
            "wget",
            "http://example.com",
        ]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.quiet);
        assert_eq!(args.config, Some(PathBuf::from("/etc/proxychains.conf")));
        assert_eq!(args.group, Some("jp".to_string()));
        assert_eq!(args.command, vec!["wget", "http://example.com"]);
    }

    #[test]
    fn test_args_list_groups_without_command() {
        let args = Args::try_parse_from(["proxychains4", "--list-groups"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.list_groups);
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_args_probe_without_command() {
        let args = Args::try_parse_from(["proxychains4", "--probe"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.probe);
        assert!(args.command.is_empty());
    }

    #[test]
    fn test_args_probe_json() {
        let args = Args::try_parse_from(["proxychains4", "--probe", "--probe-json"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.probe_json);
    }
}
