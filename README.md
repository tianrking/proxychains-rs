# proxychains-rs

English | [简体中文](README.zh-CN.md)

A modern Rust implementation of classic `proxychains4`, with cross-platform process-level proxy chaining:
- Linux: `LD_PRELOAD`
- macOS: `DYLD_INSERT_LIBRARIES`
- Windows: DLL injection + Winsock API hooks

## Current Status

| Platform | Runtime mechanism | Status |
|---|---|---|
| Linux | `LD_PRELOAD` | Stable |
| macOS | `DYLD_INSERT_LIBRARIES` | Stable |
| Windows | DLL injection + MinHook | Beta (production-usable, still expanding edge-case coverage) |

## Linux Compatibility (Important)

`proxychains-rs` works on mainstream Linux distributions, but "all Linux versions perfectly" is not a realistic claim.

What is supported now:
- Mainstream glibc-based distros on `x86_64` (Ubuntu, Debian, Fedora, RHEL-like)
- Dynamic-linked applications that use libc/Winsock-equivalent socket APIs

What is not guaranteed:
- Very old distributions / very old glibc
- `musl` environments (for example Alpine) without extra validation
- Statically linked networking stacks that bypass hookable libc entry points

Recommendation:
- Treat Ubuntu/Debian/Fedora/RHEL-like modern releases as primary supported targets.
- If you need strict enterprise guarantee, run CI in your exact distro matrix.

## Key Features

- Proxy protocols: `socks5`, `socks4`/`socks4a`, `http`, `raw`
- Chain modes: `dynamic_chain`, `strict_chain`, `random_chain`, `load_balance`, `failover`
- Proxy groups: `[ProxyList:<group>]` + `--group`
- Discovery/validation:
  - `--list-groups`
  - `--check`
  - `--probe` (quick per-node reachability/latency check)
  - `--probe-json` (machine-readable probe output)
- DNS:
  - `proxy_dns`
  - compatibility aliases: `proxy_dns_old`, `proxy_dns_daemon`
  - fake-IP mapping with reverse mapping support
- Hot config reload (long-running process):
  - hooks re-check and reload config automatically (about every 2 seconds)
  - works on Linux/macOS/Windows with aligned behavior
- Compatibility aliases:
  - `round_robin_chain` -> `load_balance`
- IPv6 progress:
  - IPv6 targets supported through SOCKS5/HTTP hops
  - SOCKS4/4a does not support IPv6 targets

## Build

Prerequisites:
- Rust 1.70+
- Cargo

Build and test:

```bash
cargo test --workspace --all-targets
cargo build --release --workspace
```

## Binaries

After build:

| Platform | CLI | Library |
|---|---|---|
| Linux | `target/release/proxychains4` | `target/release/libproxychains.so` |
| macOS | `target/release/proxychains4` | `target/release/libproxychains.dylib` |
| Windows | `target/release/proxychains4.exe` | `target/release/proxychains.dll` |

## Quick Usage

```bash
# Linux/macOS
proxychains4 curl https://ifconfig.me

# Windows
proxychains4.exe curl https://ifconfig.me
```

Validate config and groups:

```bash
proxychains4 -f ./proxychains.conf --list-groups
proxychains4 -f ./proxychains.conf --group jp --check
proxychains4 -f ./proxychains.conf --group jp --probe
proxychains4 -f ./proxychains.conf --probe --probe-timeout-ms 1200
proxychains4 -f ./proxychains.conf --probe --probe-json
```

## Example Config

```ini
dynamic_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8

# compatibility alias examples:
# round_robin_chain
# proxy_dns_old
# proxy_dns_daemon 127.0.0.1:1053

[ProxyList]
socks5 127.0.0.1 1080
# socks4 127.0.0.1 1081
# http   127.0.0.1 8080

[ProxyList:jp]
socks5 10.0.0.2 1080

[ProxyList:us]
socks5 10.0.0.3 1080
```

## DNS and Leak-Prevention Notes

- Enable `proxy_dns` to route hostname resolution through proxychains logic.
- In modern code paths, hooks avoid system-DNS fallback in proxy DNS mode.
- As with any hook-based system, test with your target applications (especially unusual runtime/linking models).

## CI / Release

- CI: multi-platform build/test in GitHub Actions
- Release: tagged builds publish assets (Windows zip, Linux tar/deb, macOS tar)

## Troubleshooting

- `No proxies configured`: check `[ProxyList]` and `-f` path
- DNS leak concern: ensure `proxy_dns` is enabled
- Windows DLL error: keep `proxychains4.exe` and `proxychains.dll` in same directory
- Linux preload issue: verify dynamic linking and `LD_PRELOAD` behavior

## License

GPL-2.0

## Acknowledgment

Inspired by [proxychains-ng](https://github.com/rofl0r/proxychains-ng).
