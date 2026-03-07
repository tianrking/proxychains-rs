# RUST Proxychains4

A modern Rust implementation of the classic proxychains tool, providing elegant and powerful proxy chaining capabilities.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-GPL%2.0-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

## Features

- **Multiple Proxy Protocols**: SOCKS4, SOCKS4a, SOCKS5 (with authentication), HTTP CONNECT
- **Chain Modes**: Strict, Dynamic, Random, Load Balance, Failover
- **DNS Handling**: Local resolution, Remote DNS through proxy, Fake IP mapping
- **IPv6 Support**: Full IPv6 compatibility (planned)
- **HTTPS Proxy**: Secure proxy connections (planned)
- **Configuration**: Compatible with original proxychains.conf format
- **Cross-platform**: Linux (LD_PRELOAD) and macOS (DYLD_INSERT_LIBRARIES)
- **Thread Safe**: All operations are thread-safe

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Entry                           │
│  proxychains4 [options] <command>                        │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Config Parser                         │
│  • Parse config file                                    │
│  • Environment variable overrides                       │
│  • CLI argument overrides                               │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    Hook Layer                           │
│  ┌─────────────┐              ┌─────────────┐          │
│  │ LD_PRELOAD  │              │   ptrace    │          │
│  │  (default)  │              │ (fallback)  │          │
│  └─────────────┘              └─────────────┘          │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Core Engine                           │
│  ┌─────────┬─────────┬─────────┬─────────┐             │
│  │ SOCKS4  │ SOCKS5  │  HTTP   │ HTTPS   │             │
│  └─────────┴─────────┴─────────┴─────────┘             │
│  ┌─────────────────────────────────────┐               │
│  │  Chain Manager (chain/balance/failover)│            │
│  └─────────────────────────────────────┘               │
│  ┌─────────────────────────────────────┐               │
│  │  DNS Resolver (local/remote/FakeIP)  │              │
│  └─────────────────────────────────────┘               │
│  ┌─────────────────────────────────────┐               │
│  │  Rule Filter (Bypass/Allow)          │              │
│  └─────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

```
RUST_proxychains4/
├── Cargo.toml                    # Workspace configuration
├── proxychains/                  # Core library
│   ├── src/
│   │   ├── lib.rs
│   │   ├── config/               # Configuration parsing
│   │   ├── proxy/                # Proxy protocol implementations
│   │   ├── chain/                # Chain management
│   │   ├── dns/                  # DNS handling
│   │   ├── hook/                 # LD_PRELOAD hooks
│   │   └── net/                  # Network utilities
│   └── Cargo.toml
├── proxychains-bin/              # CLI binary
│   ├── src/
│   │   └── main.rs
│   └── Cargo.toml
├── libproxychains/               # LD_PRELOAD library
│   ├── src/
│   │   └── lib.rs
│   └── Cargo.toml
└── proxychains.conf              # Example configuration
```

## Installation

### From Source

```bash
# Clone the repository
cd /path/to/RUST_proxychains4

# Build in release mode
cargo build --release

# The binaries will be at:
# - target/release/proxychains4 (CLI binary)
# - target/release/libproxychains.dylib (macOS) or libproxychains.so (Linux)
```

### Install System-wide

```bash
# Install binary
sudo cp target/release/proxychains4 /usr/local/bin/

# Install library
sudo cp target/release/libproxychains.dylib /usr/local/lib/  # macOS
# OR
sudo cp target/release/libproxychains.so /usr/local/lib/       # Linux

# Install default config
sudo cp proxychains.conf /usr/local/etc/
```

## Usage

```bash
# Basic usage
proxychains4 curl https://ifconfig.me

# With config file
proxychains4 -f /path/to/config.conf wget https://example.com

# Quiet mode
proxychains4 -q curl https://ifconfig.me

# Verbose mode
proxychains4 -v curl https://ifconfig.me
```

## Configuration

Configuration file format (compatible with original proxychains):

```ini
# Chain types: dynamic_chain, strict_chain, random_chain
# - dynamic_chain: Skip dead proxies, continue with working ones
# - strict_chain: All proxies must work
# - random_chain: Randomly select proxies
dynamic_chain

# Proxy DNS through the chain (recommended to prevent DNS leaks)
proxy_dns

# Remote DNS subnet for fake IPs (default: 224)
remote_dns_subnet 224

# Timeouts (milliseconds)
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Local networks to bypass (CIDR notation)
localnet 127.0.0.0/255.0.0.0
localnet 192.168.0.0/255.255.0.0
localnet 10.0.0.0/255.0.0.0

# DNAT rules (destination NAT)
# dnat original_ip:original_port new_ip:new_port

# Proxy list
[ProxyList]
# Format: type host port [user pass]

# SOCKS5 proxies
# socks5 192.168.1.1 1080 user password
# socks5 192.168.1.2 1080

# SOCKS4 proxies
# socks4 192.168.1.3 1080

# HTTP proxies
# http 192.168.1.4 8080 user password
# http 192.168.1.5 3128

# Example: Default Tor proxy
# socks5 127.0.0.1 9050
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PROXYCHAINS_CONF_FILE` | Path to configuration file |
| `PROXYCHAINS_QUIET_MODE` | Set to enable quiet mode |
| `PROXYCHAINS_SOCKS5_HOST` | Quick SOCKS5 proxy host |
| `PROXYCHAINS_SOCKS5_PORT` | Quick SOCKS5 proxy port |
| `PROXYCHAINS_DNS` | Enable/disable DNS proxying |

### Quick SOCKS5 Setup

```bash
export PROXYCHAINS_SOCKS5_HOST=127.0.0.1
export PROXYCHAINS_SOCKS5_PORT=9050
proxychains4 curl https://ifconfig.me
```

## Proxy Types

### SOCKS5

Full SOCKS5 protocol support with:
- No authentication
- Username/password authentication (RFC 1929)
- Domain name resolution (remote DNS)
- IPv4 and IPv6 addresses

### SOCKS4/4a

SOCKS4 and SOCKS4a protocol support with:
- IPv4 addresses
- Domain name resolution (SOCKS4a)
- User ID authentication

### HTTP CONNECT

HTTP CONNECT proxy support with:
- HTTP/1.0 and HTTP/1.1
- Basic authentication
- HTTPS targets (via HTTP CONNECT)

## Chain Modes

### Dynamic Chain (Default)

Tries proxies in order, skipping dead/unreachable proxies. Most resilient mode - continues trying until successful connection.

### Strict Chain

All proxies must be available and working. Fails immediately if any proxy is down. No retry mechanism.

### Random Chain

Randomly selects proxies from the list. Useful for load distribution and anonymity.

### Load Balance (Planned)

Round-robin selection for Evenly distributes connections across available proxies.

### Failover (Planned)

Try proxies in order until one works. Automatic failover on on next available proxy.

## Development

### Prerequisites

- Rust 1.70 or0 or later
- Cargo

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture
```

## Comparison with Original proxychains

| Feature | Original (C) | Rust Version |
|---------|--------------|---------------|
| Code size | ~1900 lines | ~3500 lines |
| Protocols | 4 types | 4 types |
| Injection | LD_PRELOAD only | LD_PRELOAD + ptrace (planned) |
| IPv6 | ❌ | ✅ (planned) |
| Chain modes | 3 types | 5 types |
| DNS | Basic | Enhanced |
| Thread Safety | Basic | Full |
| Error Handling | setjmp/longjmp | Result types |

## License

GPL-2.0

## Acknowled

This project is a Rust implementation of the original [proxychains-ng](https://github.com/rofl0r/proxychains-ng) project.
