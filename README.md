# proxychains-rs

English | [简体中文](README.zh-CN.md)

Transparent UDP is available with `proxy_udp` and one or more SOCKS5 nodes per
selected UDP proxy group. New associations fail over across eligible nodes;
each UDP socket keeps its first selected group and proxy.
It intercepts supported application socket calls through UDP ASSOCIATE, including
authenticated IPv4/IPv6/domain datagrams. See [setup and limitations](docs/udp-proxying.md).
Windows synchronous, IOCP, and overlapped completion-routine UDP calls,
including `WSASendMsg`/`WSARecvMsg`, are covered by native fixtures. A real Quinn+h3 HTTP/3 GET and response also pass
through the transparent SOCKS5 relay in CI; browser and MsQuic compatibility
remain uncertified.

A modern Rust implementation of classic `proxychains4`, with cross-platform process-level proxy chaining:
- Linux: `LD_PRELOAD`
- macOS: `DYLD_INSERT_LIBRARIES`
- Windows: DLL injection + Winsock API hooks

## Current Status

| Platform | Runtime mechanism | Status |
|---|---|---|
| Linux | `LD_PRELOAD` | Compile-checked; native regression gate added, event-loop compatibility pending |
| macOS | `DYLD_INSERT_LIBRARIES` | Compile-checked; native regression gate added, protected apps and event loops not certified |
| Windows | DLL injection + MinHook | Creation-time tree injection, UDP IOCP/completion-routine fixtures, and ConnectEx close-cancellation fixtures pass; RIO remains incomplete |

Author: **tianrking**. See [implementation status](docs/implementation-status.md)
for verified behavior, commands and unfinished work. This is not system-enforced
network isolation. `raw` is a no-handshake mode, not an IP tunnel. Arbitrary UDP,
ICMP, browser/MsQuic HTTP/3 workflows and complete Agent compatibility are not certified.

New interfaces: `proxychains4 --pid PID`, `proxychains4 --attach-name FILE.exe`
(Windows), and `proxychains-udp -f FILE --listen 127.0.0.1:1053 --target 1.1.1.1:53`
(explicit UDP forwarding through exactly one SOCKS5 node).

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
- Process tree mode: `--tree`
  - Windows: creation-time debugger events inject the root and every child before it resumes
    - debugger-sensitive launchers automatically retry with suspended-root injection and descendant polling; this compatibility path has a short race window
  - Linux/macOS: inherited preload environment for child processes
- Discovery/validation:
  - `--list-groups`
  - `--check`
  - `--probe` (quick per-node reachability/latency check)
  - `--probe-json` (machine-readable probe output)
  - `--doctor` (end-to-end protocol and target diagnostics)
  - `--explain HOST:PORT` (show the matched route rule and effective action)
  - Shared proxy health cooldown (`proxy_health_cooldown_ms`) prevents repeated
    attempts against a failing node across new connections and UDP associations;
    existing TCP streams and UDP sockets are never migrated.
  - `--log-file FILE` (best-effort JSONL connection events with process, timing and selected UDP proxy fields)
  - `--events --log-file FILE [--events-follow]` (view recorded events)
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
  - Ordered routing rules:
  - `route direct|proxy|reject domain|domain_suffix|port|protocol|process VALUE`
  - `route_group GROUP domain|domain_suffix|port|protocol|process VALUE` selects
    a named proxy group for matching TCP connections.
  - The first matching rule wins; unmatched traffic keeps the configured proxy chain.
- Project launch profiles:
  - `--profile FILE` saves a command, arguments, working directory, environment, config file, and group.

## Build

Prerequisites:
- Rust 1.88+
- Cargo

Build and test:

```bash
cargo test --locked --workspace --all-targets
cargo build --locked --release --workspace
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

Forced validation manual:
- [docs/forced-proxy-validation.md](docs/forced-proxy-validation.md)

Validate config and groups:

```bash
proxychains4 -f ./proxychains.conf --list-groups
proxychains4 -f ./proxychains.conf --group jp --check
proxychains4 -f ./proxychains.conf --group jp --probe
proxychains4 -f ./proxychains.conf --probe --probe-timeout-ms 1200
proxychains4 -f ./proxychains.conf --probe --probe-json
proxychains4 -f ./proxychains.conf --doctor --doctor-target example.com:80
proxychains4 -f ./proxychains.conf --doctor --doctor-target example.com:80 --doctor-udp-echo 1.1.1.1:53 --doctor-json
proxychains4 -f ./proxychains.conf --explain git.internal.example:443 --explain-process git.exe
proxychains4 -f ./proxychains.conf --tree curl https://ifconfig.me
proxychains4 --profile ./profiles/build.profile
```

`--probe` only checks whether a proxy endpoint accepts a TCP connection.
`--doctor` separately checks transport, protocol/authentication, target
connection, and optional SOCKS5 UDP ASSOCIATE plus an actual UDP echo. Its
JSON stages classify actionable failures as `authentication`, `dns`,
`timeout`, `refused`, `reset`, `proxy_rejected`, or `target` where the
protocol cannot provide a more specific cause. A successful UDP ASSOCIATE
alone is not reported as working UDP forwarding.

Set `--log-file` when launching a command to record intercepted TCP and UDP
connection outcomes as JSONL. The record contains process name, PID, optional
`PROXYCHAINS_SESSION_ID`, target, stage, result, and latency, but never proxy
credentials or payload bytes. UDP records include `udp_associate`, `udp_send`,
and `udp_receive` events, the selected association proxy when available, and
the last failed proxy when association failover exhausts its candidates. Use
`--events --events-follow` in another terminal to follow the file; follow mode
waits for a log file that has not been created yet. Logging is best-effort: a
busy or unavailable log file never blocks a connection hook.

When a command is launched through the CLI, a session ID is generated
automatically and inherited by its child processes. Set `PROXYCHAINS_SESSION_ID`
before launching to provide your own correlation key.

A profile is a small `KEY = VALUE` file. Supported keys are `command`,
`args` (whitespace-separated), `cwd`, `config`, `group`, and `env.NAME`:
Relative `cwd` and `config` paths are resolved from the profile's directory,
so the profile remains portable when launched from another directory.

```text
command = cargo
args = test --locked
cwd = C:/src/my-project
config = C:/src/my-project/proxychains.conf
group = development
env.RUST_LOG = info
```

## Example Config

```ini
dynamic_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8
# Keep failed nodes out of new connection selection for this long (milliseconds).
proxy_health_cooldown_ms 5000
# Bypass local networks; IPv4 masks and IPv6 CIDR prefixes are accepted.
# localnet 192.168.0.0/255.255.0.0
# localnet 2001:db8:1234::/48

# Optional ordered routing rules (first match wins):
# route direct domain_suffix .internal.example
# route reject port 25
# route direct protocol udp
# route_group jp domain git.example.com
# route_group jp protocol udp

# compatibility alias examples:
# round_robin_chain
# proxy_dns_old
# proxy_dns_daemon 127.0.0.1:1053

[ProxyList]
socks5 127.0.0.1 1080
# socks5 proxy.example.com 1080
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
