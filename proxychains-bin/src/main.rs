//! Proxychains4 CLI binary
//!
//! This is the main entry point for running commands through proxy chains.

use std::env;
use std::ffi::CString;
use std::path::PathBuf;
use std::process;

use clap::Parser;
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

    /// The command to run
    #[arg(required = true, trailing_var_arg = true)]
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
    }

    // Execute the command with LD_PRELOAD
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
    let mut parser = ConfigParser::new();

    if let Some(ref path) = args.config {
        parser = parser.with_path(path.clone());
    }

    parser.parse().map_err(|e| e.to_string())
}

/// Execute the command with LD_PRELOAD set
fn execute_command(args: &Args, config: &Config) -> Result<i32, String> {
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

/// Find the proxychains library path
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

/// Get the directory containing the current binary
fn get_binary_dir() -> Option<PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
}

/// Set LD_PRELOAD environment variable
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

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Err("Unsupported operating system".to_string());
    }

    Ok(())
}

/// Set proxychains-specific environment variables
fn set_proxychains_env(config: &Config, args: &Args) {
    if args.quiet {
        env::set_var("PROXYCHAINS_QUIET_MODE", "1");
    }

    if config.proxy_dns {
        env::set_var("PROXYCHAINS_DNS", "1");
    }

    // Note: The actual config file path is handled by the library
    // when it reads PROXYCHAINS_CONF_FILE
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
            "wget",
            "http://example.com",
        ]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.quiet);
        assert_eq!(args.config, Some(PathBuf::from("/etc/proxychains.conf")));
        assert_eq!(args.command, vec!["wget", "http://example.com"]);
    }
}
