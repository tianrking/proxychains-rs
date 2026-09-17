//! Loopback SOCKS5 service backed by a configured proxychains route.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use proxychains::{ConfigParser, LocalSocks5Credentials, LocalSocks5Server};

#[derive(Parser, Debug)]
#[command(name = "proxychains-socks5")]
#[command(about = "Expose a local SOCKS5 CONNECT listener through a proxychains route")]
struct Args {
    /// Proxychains configuration for the upstream route
    #[arg(short = 'f', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Named [ProxyList:GROUP] from the configuration
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,

    /// Listener address. Non-loopback addresses require --allow-remote.
    #[arg(long, default_value = "127.0.0.1:1081", value_name = "HOST:PORT")]
    listen: SocketAddr,

    /// Explicitly allow clients outside loopback. Use --username and --password.
    #[arg(long)]
    allow_remote: bool,

    /// Local SOCKS5 username. Requires --password.
    #[arg(long, requires = "password")]
    username: Option<String>,

    /// Local SOCKS5 password. Requires --username.
    #[arg(long, requires = "username")]
    password: Option<String>,

    /// Maximum simultaneous local client connections
    #[arg(long, default_value_t = 128, value_name = "COUNT")]
    max_clients: usize,
}

fn main() {
    let args = Args::parse();
    if !args.allow_remote && !args.listen.ip().is_loopback() {
        fail("refusing non-loopback listener without --allow-remote");
    }
    if args.allow_remote && (args.username.is_none() || args.password.is_none()) {
        fail("--allow-remote requires --username and --password");
    }
    let mut parser = ConfigParser::new();
    if let Some(path) = args.config {
        parser = parser.with_path(path);
    }
    if let Some(group) = args.group {
        parser = parser.with_group(group);
    }
    let config = parser
        .parse()
        .unwrap_or_else(|error| fail(&error.to_string()));
    let credentials = match (args.username, args.password) {
        (Some(username), Some(password)) => Some(
            LocalSocks5Credentials::new(username, password)
                .unwrap_or_else(|error| fail(&error.to_string())),
        ),
        (None, None) => None,
        _ => unreachable!("clap enforces paired local credentials"),
    };
    let server = LocalSocks5Server::new(config, credentials, args.max_clients)
        .unwrap_or_else(|error| fail(&error.to_string()));
    let listener = TcpListener::bind(args.listen).unwrap_or_else(|error| {
        fail(&format!("cannot bind {}: {error}", args.listen));
    });
    let address = listener.local_addr().unwrap_or(args.listen);
    eprintln!("proxychains-socks5: listening on {address}; upstream is the configured proxy chain");
    let shutdown = Arc::new(AtomicBool::new(false));
    if let Err(error) = server.serve(listener, shutdown) {
        fail(&error.to_string());
    }
}

fn fail(message: &str) -> ! {
    eprintln!("proxychains-socks5: {message}");
    process::exit(1);
}
