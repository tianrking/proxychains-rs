//! Proxychains4 CLI binary
//!
//! This is the main entry point for running commands through proxy chains.
//!
//! Platform support:
//! - Unix (Linux/macOS): Uses LD_PRELOAD/DYLD_INSERT_LIBRARIES
//! - Windows: Uses DLL injection

use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, error, info, Level};
use tracing_subscriber::FmtSubscriber;

use proxychains::config::{ProxyType, RouteAction, RouteProtocol};
use proxychains::proxy::{connect_to_proxy, tunnel_through_proxy, TargetAddress, UdpAssociation};
use proxychains::{Config, ConfigParser};

/// Proxychains4 - Run commands through proxy chains
#[derive(Parser, Debug)]
#[command(name = "proxychains4")]
#[command(author = "tianrking")]
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

    /// In text probe output, print only failed nodes
    #[arg(long)]
    probe_fail_only: bool,

    /// Run end-to-end protocol and target checks for every configured proxy
    #[arg(long)]
    doctor: bool,

    /// TCP target used by --doctor (default: example.com:80)
    #[arg(long, value_name = "HOST:PORT", default_value = "example.com:80")]
    doctor_target: String,

    /// Optional UDP echo target used by --doctor for SOCKS5 UDP ASSOCIATE
    #[arg(long, value_name = "HOST:PORT")]
    doctor_udp_echo: Option<String>,

    /// Print doctor results as JSON
    #[arg(long)]
    doctor_json: bool,

    /// Explain which routing rule would handle HOST:PORT and exit
    #[arg(long, value_name = "HOST:PORT")]
    explain: Option<String>,

    /// Protocol used by --explain (tcp or udp)
    #[arg(long, default_value = "tcp", requires = "explain")]
    explain_protocol: String,

    /// Process name used by --explain for process matching rules
    #[arg(long, requires = "explain")]
    explain_process: Option<String>,

    /// Write hook connection events as JSONL to this file
    #[arg(long, value_name = "FILE")]
    log_file: Option<PathBuf>,

    /// Print connection events from a JSONL log file and exit
    #[arg(long)]
    events: bool,

    /// Keep waiting for new connection events after printing the log
    #[arg(long, requires = "events")]
    events_follow: bool,

    /// Launch a saved project profile
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Enable process-tree mode (inject/proxy child and grandchild processes)
    #[arg(long)]
    tree: bool,

    /// Attach to an existing Windows process. Existing connections are unaffected.
    #[arg(long, conflicts_with_all = ["attach_name", "tree", "command"])]
    pid: Option<u32>,

    /// Attach to one exact executable name; ambiguous matches require --pid.
    #[arg(long, conflicts_with_all = ["pid", "tree", "command"])]
    attach_name: Option<String>,

    /// The command to run
    #[arg(
        required_unless_present_any = ["list_groups", "check", "probe", "doctor", "explain", "events", "profile", "pid", "attach_name"],
        trailing_var_arg = true
    )]
    command: Vec<String>,

    #[arg(skip)]
    launch_cwd: Option<PathBuf>,
    #[arg(skip)]
    launch_env: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct LaunchProfile {
    command: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    config: Option<PathBuf>,
    group: Option<String>,
    env: Vec<(String, String)>,
}

fn main() {
    let mut args = Args::parse();
    if let Some(profile) = args.profile.clone() {
        if let Err(error) = apply_profile(&mut args, &profile) {
            eprintln!("proxychains: profile {}: {error}", profile.display());
            process::exit(1);
        }
    }
    // Freeze the selected path before children change their working directory.
    if let Some(path) = build_parser(&args).find_config_file() {
        match std::fs::canonicalize(&path) {
            Ok(path) => args.config = Some(path),
            Err(e) => {
                eprintln!("proxychains: cannot open config {}: {}", path.display(), e);
                process::exit(1);
            }
        }
    }

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

    if args.events {
        let failed = run_events(&args);
        process::exit(if failed { 1 } else { 0 });
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

    if !args.command.is_empty() && !args.events && !args.doctor && !args.probe {
        if let Some(cwd) = &args.launch_cwd {
            if let Err(error) = env::set_current_dir(cwd) {
                eprintln!("proxychains: cannot enter profile directory {}: {error}", cwd.display());
                process::exit(1);
            }
        }
        for (key, value) in &args.launch_env {
            env::set_var(key, value);
        }
    }

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

    if args.doctor {
        let failed = run_doctor(&config, &args);
        process::exit(if failed == 0 { 0 } else { 2 });
    }

    if args.explain.is_some() {
        let failed = print_route_explanation(&config, &args);
        process::exit(if failed { 1 } else { 0 });
    }

    if args.pid.is_some() || args.attach_name.is_some() {
        set_proxychains_env(&config, &args);
        #[cfg(windows)]
        {
            let result = proxychains_injector::find_library_path()
                .and_then(|path| proxychains_injector::ProxychainsInjector::new(&path))
                .and_then(|injector| match args.pid {
                    Some(pid) => injector.inject_by_pid(pid),
                    None => injector.inject_by_name(args.attach_name.as_deref().unwrap()),
                });
            match result {
                Ok(()) => {
                    println!("Hooks ready; only subsequent supported connections are affected.");
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("proxychains: attach failed: {e}");
                    process::exit(1);
                }
            }
        }
        #[cfg(not(windows))]
        {
            eprintln!("proxychains: process attachment requires Windows; use launch mode on this platform");
            process::exit(1);
        }
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
        let auth = if proxy.user.is_some() {
            "auth"
        } else {
            "no-auth"
        };
        println!(
            "  {}. {} {}:{} ({})",
            idx + 1,
            proxy.proxy_type,
            proxy.host,
            proxy.port,
            auth
        );
    }
}

fn print_route_explanation(config: &Config, args: &Args) -> bool {
    let Some(raw_target) = args.explain.as_deref() else {
        return true;
    };
    let (host, port) = match parse_doctor_target(raw_target) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("proxychains: {error}");
            return true;
        }
    };
    let protocol = match args.explain_protocol.to_ascii_lowercase().as_str() {
        "tcp" => RouteProtocol::Tcp,
        "udp" => RouteProtocol::Udp,
        other => {
            eprintln!("proxychains: invalid --explain-protocol {other:?}; use tcp or udp");
            return true;
        }
    };
    let current_process = env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let process = args
        .explain_process
        .as_deref()
        .unwrap_or(current_process.as_str());
    let domain = host.parse::<std::net::IpAddr>().is_err().then_some(host.as_str());
    let action = config.route_action_for_process(protocol, domain, port, process);
    println!("Target: {host}:{port}");
    println!("Protocol: {:?}", protocol);
    println!("Process: {}", if process.is_empty() { "(unknown)" } else { process });
    if let Some(rule) = config.matching_route_rule(protocol, domain, port, process) {
        println!("Matched rule: {:?}", rule);
    } else {
        println!("Matched rule: (none; default proxy)");
    }
    println!("Rule action: {:?}", action);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if action == RouteAction::Proxy && config.should_bypass_ip(&ip) {
            println!("Effective action: Direct (local address bypass)");
        } else {
            println!("Effective action: {:?}", action);
        }
    } else {
        println!("Effective action: {:?} (IP bypass depends on resolved address)", action);
    }
    false
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
        let target = match proxy.resolved_socket_addr() {
            Ok(addr) => addr,
            Err(e) => {
                failed += 1;
                results.push(ProbeNode {
                    index: idx + 1,
                    proxy_type: proxy.proxy_type.to_string(),
                    address: format!("{}:{}", proxy.host, proxy.port),
                    ok: false,
                    latency_ms: 0,
                    failure_type: Some("resolve_error".to_string()),
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        let start = Instant::now();
        match TcpStream::connect_timeout(&target, timeout) {
            Ok(stream) => {
                let elapsed = start.elapsed().as_millis();
                let _ = stream.shutdown(std::net::Shutdown::Both);
                results.push(ProbeNode {
                    index: idx + 1,
                    proxy_type: proxy.proxy_type.to_string(),
                    address: format!("{}:{}", proxy.host, proxy.port),
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
                    address: format!("{}:{}", proxy.host, proxy.port),
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
        print_probe_report(&report, args.probe_fail_only);
    }
    failed
}

fn parse_doctor_target(raw: &str) -> Result<(String, u16), String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("doctor target cannot be empty".to_string());
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid target {value:?}; expected HOST:PORT"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid target port {port:?}"))?;
    if host.is_empty() || host.contains('[') || host.contains(']') {
        return Err(format!("invalid target host {host:?}"));
    }
    Ok((host.to_string(), port))
}

fn run_doctor(config: &Config, args: &Args) -> usize {
    let target = match parse_doctor_target(&args.doctor_target) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("proxychains: doctor: {error}");
            return 1;
        }
    };
    let udp_target = match args
        .doctor_udp_echo
        .as_deref()
        .map(parse_doctor_target)
        .transpose()
    {
        Ok(target) => target,
        Err(error) => {
            eprintln!("proxychains: doctor: {error}");
            return 1;
        }
    };
    let timeout = args
        .probe_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(config.tcp_connect_timeout);
    let mut nodes = Vec::with_capacity(config.proxies.len());
    for (index, proxy) in config.proxies.iter().enumerate() {
        nodes.push(doctor_proxy(
            proxy,
            index + 1,
            &target,
            udp_target.as_ref(),
            timeout,
        ));
    }
    let failed = nodes.iter().filter(|node| !node.ok).count();
    let report = DoctorReport {
        schema_version: "1.0".to_string(),
        target: format!("{}:{}", target.0, target.1),
        udp_echo_target: udp_target
            .as_ref()
            .map(|(host, port)| format!("{host}:{port}")),
        timeout_ms: timeout.as_millis(),
        nodes,
    };
    if args.doctor_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print_doctor_report(&report);
    }
    failed
}

fn doctor_proxy(
    proxy: &proxychains::config::ProxyData,
    index: usize,
    target: &(String, u16),
    udp_echo_target: Option<&(String, u16)>,
    timeout: Duration,
) -> DoctorNode {
    let address = format!("{}:{}", proxy.host, proxy.port);
    let mut node = DoctorNode {
        index,
        proxy_type: proxy.proxy_type.to_string(),
        address,
        ok: false,
        transport: DoctorStage::skipped(),
        authentication: DoctorStage::skipped(),
        target: DoctorStage::skipped(),
        udp_associate: DoctorStage::skipped(),
        udp_echo: DoctorStage::skipped(),
    };
    let started = Instant::now();
    let mut stream = match connect_to_proxy(proxy, timeout) {
        Ok(stream) => {
            node.transport = DoctorStage::ok(started.elapsed());
            stream
        }
        Err(error) => {
            node.transport =
                DoctorStage::failed(started.elapsed(), "transport", &error.to_string());
            return node;
        }
    };
    let handshake_started = Instant::now();
    if proxy.proxy_type == ProxyType::Socks5 && (proxy.user.is_some() != proxy.pass.is_some()) {
        node.authentication = DoctorStage::failed(
            handshake_started.elapsed(),
            "authentication",
            "both username and password are required",
        );
        return node;
    }
    match tunnel_through_proxy(
        &mut stream,
        proxy,
        &TargetAddress::from_domain(target.0.clone()),
        target.1,
        timeout,
    ) {
        Ok(()) => {
            node.authentication = DoctorStage::ok(handshake_started.elapsed());
            node.target = DoctorStage::ok(handshake_started.elapsed());
        }
        Err(error) => {
            let kind = if proxy.proxy_type == ProxyType::Socks5 {
                if proxy.user.is_some() {
                    "authentication_or_protocol"
                } else {
                    "protocol_or_target"
                }
            } else {
                "protocol_or_target"
            };
            node.authentication =
                DoctorStage::failed(handshake_started.elapsed(), kind, &error.to_string());
            node.target =
                DoctorStage::failed(handshake_started.elapsed(), "target", &error.to_string());
            return node;
        }
    }
    if let Some((udp_host, udp_port)) = udp_echo_target {
        if proxy.proxy_type != ProxyType::Socks5 {
            node.udp_associate =
                DoctorStage::skipped_with("requires_socks5", "UDP ASSOCIATE requires SOCKS5");
            node.udp_echo =
                DoctorStage::skipped_with("requires_socks5", "UDP ASSOCIATE requires SOCKS5");
        } else {
            let udp_started = Instant::now();
            match UdpAssociation::connect(proxy, timeout, timeout) {
                Ok(association) => {
                    node.udp_associate = DoctorStage::ok(udp_started.elapsed());
                    let echo_started = Instant::now();
                    let send = association.send_to(
                        &TargetAddress::from_domain(udp_host.clone()),
                        *udp_port,
                        b"proxychains-doctor",
                    );
                    match send.and_then(|_| association.recv_from().map(|_| ())) {
                        Ok(()) => node.udp_echo = DoctorStage::ok(echo_started.elapsed()),
                        Err(error) => {
                            node.udp_echo = DoctorStage::failed(
                                echo_started.elapsed(),
                                "udp_echo",
                                &error.to_string(),
                            )
                        }
                    }
                }
                Err(error) => {
                    node.udp_associate = DoctorStage::failed(
                        udp_started.elapsed(),
                        "udp_associate",
                        &error.to_string(),
                    )
                }
            }
        }
    }
    node.ok = node.transport.ok
        && node.authentication.ok
        && node.target.ok
        && (!udp_echo_target.is_some() || (node.udp_associate.ok && node.udp_echo.ok));
    node
}

fn print_doctor_report(report: &DoctorReport) {
    println!("Proxy doctor:");
    println!(
        "  target={} timeout_ms={}",
        report.target, report.timeout_ms
    );
    if let Some(target) = &report.udp_echo_target {
        println!("  udp_echo_target={target}");
    }
    for node in &report.nodes {
        println!(
            "  [{}] {} {} -> {}",
            node.index,
            if node.ok { "OK" } else { "FAIL" },
            node.proxy_type,
            node.address
        );
        print_doctor_stage("transport", &node.transport);
        print_doctor_stage("authentication", &node.authentication);
        print_doctor_stage("target", &node.target);
        if node.udp_echo.is_skipped() && node.udp_associate.is_skipped() {
            continue;
        }
        print_doctor_stage("udp_associate", &node.udp_associate);
        print_doctor_stage("udp_echo", &node.udp_echo);
    }
    let ok = report.nodes.iter().filter(|node| node.ok).count();
    println!(
        "Doctor summary: total={}, ok={}, fail={}",
        report.nodes.len(),
        ok,
        report.nodes.len().saturating_sub(ok)
    );
}

fn print_doctor_stage(name: &str, stage: &DoctorStage) {
    let status = if stage.ok {
        "OK"
    } else if stage.skipped {
        "SKIP"
    } else {
        "FAIL"
    };
    let detail = stage.error.as_deref().unwrap_or("");
    println!(
        "      {status:<4} {name:<16} {} ms {}",
        stage.latency_ms, detail
    );
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: String,
    target: String,
    udp_echo_target: Option<String>,
    timeout_ms: u128,
    nodes: Vec<DoctorNode>,
}

#[derive(Debug, Serialize)]
struct DoctorNode {
    index: usize,
    proxy_type: String,
    address: String,
    ok: bool,
    transport: DoctorStage,
    authentication: DoctorStage,
    target: DoctorStage,
    udp_associate: DoctorStage,
    udp_echo: DoctorStage,
}

#[derive(Debug, Serialize)]
struct DoctorStage {
    ok: bool,
    skipped: bool,
    latency_ms: u128,
    failure_type: Option<String>,
    error: Option<String>,
}

impl DoctorStage {
    fn ok(elapsed: Duration) -> Self {
        Self {
            ok: true,
            skipped: false,
            latency_ms: elapsed.as_millis(),
            failure_type: None,
            error: None,
        }
    }
    fn skipped() -> Self {
        Self::skipped_with("not_requested", "")
    }
    fn skipped_with(kind: &str, message: &str) -> Self {
        Self {
            ok: false,
            skipped: true,
            latency_ms: 0,
            failure_type: Some(kind.to_string()),
            error: (!message.is_empty()).then(|| message.to_string()),
        }
    }
    fn failed(elapsed: Duration, kind: &str, message: &str) -> Self {
        Self {
            ok: false,
            skipped: false,
            latency_ms: elapsed.as_millis(),
            failure_type: Some(kind.to_string()),
            error: Some(message.to_string()),
        }
    }
    fn is_skipped(&self) -> bool {
        self.skipped
    }
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
    let success_rate = if total == 0 {
        0.0
    } else {
        (ok as f64) * 100.0 / (total as f64)
    };
    let best_latency_ms = results.iter().filter(|r| r.ok).map(|r| r.latency_ms).min();
    let worst_latency_ms = results.iter().filter(|r| r.ok).map(|r| r.latency_ms).max();
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
    let generated_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    ProbeReport {
        schema_version: "1.0".to_string(),
        generated_at,
        generated_at_iso8601: format_unix_ts_iso8601(generated_at),
        timeout_ms: timeout.as_millis(),
        selected_group: group,
        summary: ProbeSummary {
            total,
            ok,
            fail,
            success_rate,
            best_latency_ms,
            worst_latency_ms,
        },
        failure_stats: stats,
        nodes: results,
    }
}

fn format_unix_ts_iso8601(ts: u64) -> String {
    OffsetDateTime::from_unix_timestamp(ts as i64)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn print_probe_report(report: &ProbeReport, fail_only: bool) {
    println!("Proxy probe:");
    println!("  timeout_ms={}", report.timeout_ms);
    println!("  group={}", report.selected_group);
    for n in &report.nodes {
        if fail_only && n.ok {
            continue;
        }
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
        "Probe summary: total={}, ok={}, fail={}, success_rate={:.2}%",
        report.summary.total, report.summary.ok, report.summary.fail, report.summary.success_rate
    );
    if let Some(best) = report.summary.best_latency_ms {
        println!("Latency: best={} ms", best);
    }
    if let Some(worst) = report.summary.worst_latency_ms {
        println!("Latency: worst={} ms", worst);
    }
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
    generated_at_iso8601: String,
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
    success_rate: f64,
    best_latency_ms: Option<u128>,
    worst_latency_ms: Option<u128>,
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

    if let Some(ref path) = args.log_file {
        env::set_var("PROXYCHAINS_LOG_FILE", path);
    }
}

fn apply_profile(args: &mut Args, path: &PathBuf) -> Result<(), String> {
    let contents = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let profile_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let resolve_path = |value: &str| {
        let candidate = PathBuf::from(value);
        if candidate.is_absolute() {
            candidate
        } else {
            profile_dir.join(candidate)
        }
    };
    let mut profile = LaunchProfile::default();
    for (line_number, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {} must be KEY=VALUE", line_number + 1))?;
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "command" => profile.command = value.to_string(),
            "args" => profile.args = value.split_whitespace().map(str::to_string).collect(),
            "cwd" => profile.cwd = Some(resolve_path(value)),
            "config" => profile.config = Some(resolve_path(value)),
            "group" => profile.group = Some(value.to_string()),
            key if key.strip_prefix("env.").is_some_and(|name| !name.is_empty()) => {
                profile.env.push((key[4..].to_string(), value.to_string()));
            }
            _ => return Err(format!("unknown key {key:?} on line {}", line_number + 1)),
        }
    }
    if profile.command.is_empty() {
        return Err("profile requires command=...".to_string());
    }
    if !args.command.is_empty() {
        return Err("a profile supplies the command; do not append a command".to_string());
    }
    args.command = std::iter::once(profile.command).chain(profile.args).collect();
    if args.config.is_none() {
        args.config = profile.config;
    }
    if args.group.is_none() {
        args.group = profile.group;
    }
    args.launch_cwd = profile.cwd;
    args.launch_env = profile.env;
    Ok(())
}

fn run_events(args: &Args) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let path = args
        .log_file
        .clone()
        .or_else(|| env::var_os("PROXYCHAINS_LOG_FILE").map(PathBuf::from));
    let Some(path) = path else {
        eprintln!("proxychains: --events requires --log-file FILE");
        return true;
    };
    let mut offset = 0u64;
    loop {
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error)
                if args.events_follow && error.kind() == std::io::ErrorKind::NotFound =>
            {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(error) => {
                eprintln!("proxychains: cannot read connection log {}: {error}", path.display());
                return true;
            }
        };
        if file.seek(SeekFrom::Start(offset)).is_err() {
            eprintln!("proxychains: cannot seek connection log {}", path.display());
            return true;
        }
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            eprintln!("proxychains: cannot read connection log {}", path.display());
            return true;
        }
        offset += bytes.len() as u64;
        if !bytes.is_empty() {
            print!("{}", String::from_utf8_lossy(&bytes));
        }
        if !args.events_follow {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
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

    if args.tree {
        debug!("tree mode enabled (unix): relying on environment inheritance");
    }

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
            return Err(format!(
                "execvp failed: {}",
                std::io::Error::last_os_error()
            ));
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
        // Explicit dyld interpose tuples preserve normal two-level namespace binding.
        env::remove_var("DYLD_FORCE_FLAT_NAMESPACE");
        debug!("Set DYLD_INSERT_LIBRARIES={}", library_path);
    }

    Ok(())
}

// ============================================================================
// Windows Implementation (DLL Injection)
// ============================================================================

#[cfg(windows)]
fn execute_command(args: &Args, config: &Config) -> Result<i32, String> {
    use proxychains_injector::{find_library_path, ProcessInfo, ProxychainsInjector};

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

    let exit_code = if args.tree {
        injector
            .spawn_inject_tree_wait(&process_info)
            .map_err(|e| format!("Failed to spawn/inject tree/wait: {}", e))?
    } else {
        injector
            .spawn_inject_wait(&process_info)
            .map_err(|e| format!("Failed to spawn/inject/wait: {}", e))?
    };

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
    fn attach_modes_require_unambiguous_target() {
        assert!(Args::try_parse_from(["proxychains4", "--pid", "123"]).is_ok());
        assert!(Args::try_parse_from(["proxychains4", "--attach-name", "app.exe"]).is_ok());
        assert!(Args::try_parse_from(["proxychains4", "--pid", "123", "--tree"]).is_err());
        assert!(Args::try_parse_from(["proxychains4", "--pid", "123", "app.exe"]).is_err());
    }

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

    #[test]
    fn test_args_probe_fail_only() {
        let args = Args::try_parse_from(["proxychains4", "--probe", "--probe-fail-only"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.probe_fail_only);
    }

    #[test]
    fn test_args_doctor_without_command() {
        let args = Args::try_parse_from([
            "proxychains4",
            "--doctor",
            "--doctor-target",
            "127.0.0.1:8080",
            "--doctor-json",
        ])
        .unwrap();
        assert!(args.doctor);
        assert_eq!(args.doctor_target, "127.0.0.1:8080");
        assert!(args.doctor_json);
        assert!(args.command.is_empty());
    }

    #[test]
    fn doctor_target_parser_accepts_domain_and_ipv6() {
        assert_eq!(
            parse_doctor_target("example.test:443").unwrap(),
            ("example.test".into(), 443)
        );
        assert_eq!(parse_doctor_target("[::1]:53").unwrap(), ("::1".into(), 53));
        assert!(parse_doctor_target("missing-port").is_err());
        assert!(parse_doctor_target("host:0").is_ok());
    }

    #[test]
    fn explain_arguments_parse_without_command() {
        let args = Args::try_parse_from([
            "proxychains4",
            "--explain",
            "example.com:443",
            "--explain-protocol",
            "udp",
            "--explain-process",
            "curl.exe",
        ])
        .unwrap();
        assert_eq!(args.explain.as_deref(), Some("example.com:443"));
        assert_eq!(args.explain_protocol, "udp");
        assert_eq!(args.explain_process.as_deref(), Some("curl.exe"));
    }

    #[test]
    fn doctor_performs_real_socks5_handshake() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header, [5, 1, 0, 3]);
            let mut len = [0; 1];
            stream.read_exact(&mut len).unwrap();
            let mut domain = vec![0; len[0] as usize + 2];
            stream.read_exact(&mut domain).unwrap();
            assert_eq!(&domain[..domain.len() - 2], b"target.test");
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).unwrap();
        });

        let proxy = proxychains::config::ProxyData::new_host("127.0.0.1", port, ProxyType::Socks5);
        let node = doctor_proxy(
            &proxy,
            1,
            &("target.test".into(), 443),
            None,
            Duration::from_secs(2),
        );
        server.join().unwrap();
        assert!(node.ok);
        assert!(node.transport.ok);
        assert!(node.authentication.ok);
        assert!(node.target.ok);
        assert!(node.udp_associate.skipped);
    }

    #[test]
    fn profile_loads_command_context_without_shell_expansion() {
        let path = std::env::temp_dir().join(format!("proxychains-profile-{}.conf", std::process::id()));
        std::fs::write(&path, "command = cargo\nargs = test --locked\ncwd = project\nconfig = config/proxychains.conf\ngroup = work\nenv.RUST_LOG = info\n").unwrap();
        let mut args = Args::try_parse_from(["proxychains4", "--profile", path.to_str().unwrap()]).unwrap();
        apply_profile(&mut args, &path).unwrap();
        assert_eq!(args.command, vec!["cargo", "test", "--locked"]);
        assert_eq!(args.group.as_deref(), Some("work"));
        assert_eq!(args.launch_cwd, Some(path.parent().unwrap().join("project")));
        assert_eq!(args.config, Some(path.parent().unwrap().join("config/proxychains.conf")));
        assert_eq!(args.launch_env, vec![("RUST_LOG".into(), "info".into())]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_args_tree_without_command_fails() {
        let args = Args::try_parse_from(["proxychains4", "--tree"]);
        assert!(args.is_err());
    }

    #[test]
    fn test_args_tree_with_command() {
        let args = Args::try_parse_from(["proxychains4", "--tree", "curl", "https://example.com"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.tree);
    }
}
