# Agent network implementation status

Owner and commit author: tianrking.

This tracks the requested reliability and capability work. A completed implementation
does not imply verification on an unavailable operating system or application.

| Milestone | Status | Validation required |
| --- | --- | --- |
| TCP protocol correctness | Core regressions fixed | Windows local protocol tests pass; Agent workflows pending |
| DNS mapping and configuration lifecycle | Core fixes implemented | Custom subnet, concurrency, exhaustion and explicit missing path tests |
| Injection readiness and process attachment | Implemented, Windows fixture passes | Invalid DLL/config, successful attach, corrected-config retry, name ambiguity, real TCP payload and failed proxy |
| Unix socket lifecycle and event-loop compatibility | Premature close and flag loss fixed; event-loop compatibility pending | Linux/macOS compile checks pass; native preload fixture added but not run locally; replacing an fd still does not preserve epoll/kqueue registrations |
| UDP and IPv6 transport | SOCKS5 UDP transport, explicit forwarder and opt-in transparent UDP hooks implemented | Windows native UDP fixture passes, including IPv6 relay, domains, authentication, vectored I/O and failures; see [UDP scope](udp-proxying.md); async Windows UDP and general QUIC remain unsupported |
| Shared proxy health and cooldown | Implemented for chain manager and Windows hook selection | Unit tests cover cross-manager suppression, bounded expiry, success recovery and config parsing; cross-target Windows compile check passes |
| Agent compatibility and diagnostic bridge | Pending | Exact installed Agent versions and workflows |
| System-enforced network isolation | Pending | Platform-specific enforcement and independent observation |
| Reproducible builds and release | Author/repository corrected, lockfile tracked, native CI gates added | Local Windows builds; new remote CI and signed release certification remain pending |

Existing hook mode must not be described as universal or system-enforced fail-closed
network isolation. Attaching to a running process cannot retroactively proxy its
existing connections. UDP tunneling is distinct from interception of arbitrary UDP
applications; neither implies ICMP/raw-IP forwarding.

The pre-1.0 Rust API now returns Result from DnsCache::get_or_create and
resolve_to_fake_ip. Callers must handle capacity exhaustion instead of assuming
that old fake addresses can be recycled. DNS mappings are process-local, not a
cross-process DNS service.

## Available commands

Build with `cargo build --locked --release --workspace` (Rust 1.88 or newer).
The local compiler used for verification was Rust 1.98.1; 1.88 is the highest
declared minimum of locked dependencies, not a locally tested compiler version.

Windows attachment, with the matching DLL next to the launcher:

```text
proxychains4 -f proxychains.conf --pid 12345
proxychains4 -f proxychains.conf --attach-name example.exe
```

Names must resolve to exactly one process. Architecture must match the injector.
Only future intercepted connections are affected; existing sockets are untouched.
The suspended launcher waits for explicit hook readiness. Windows `--tree`
uses debugger creation events to inject each child before it resumes, closing
the old process-table polling window. The public `spawn_and_inject` API still
injects after launch and does not have the same before-first-instruction
guarantee. ConnectEx/IOCP support is not certified.

Explicit UDP forwarding through a configuration containing exactly one SOCKS5 node:

```text
proxychains-udp -f socks5-only.conf --listen 127.0.0.1:1053 --target 1.1.1.1:53
```

Point an application's UDP destination at the loopback port. This example can
carry UDP DNS; it does not change system DNS or intercept arbitrary applications.
The remote endpoint is a fixed IP:port. Each local source has a separate SOCKS5
control channel and datagram socket. At most 64 clients are retained; each queue
is bounded, idle sessions expire after 60 seconds, overload drops packets, and
association failure never creates a direct target socket. Fragmented SOCKS5 UDP
packets are rejected. DNS TCP fallback is not provided by this UDP-only command.

## Remaining work before broad compatibility claims

1. Replace Windows descendant polling with creation-time propagation, including
   process creation variants, architecture combinations and a safe failure policy.
2. Implement native asynchronous socket semantics: Windows ConnectEx/IOCP,
   Unix nonblocking connect, epoll/kqueue and fd duplication/closure tracking.
3. Add an OS enforcement/data-plane backend for UDP interception and prevention
   of bypass: Windows WFP/TUN, Linux namespaces/firewall/TUN, macOS supported
   Network Extension mechanisms. These require their own implementation and
   privileged/native tests; adding the SOCKS5 codec does not implement them.
4. Define scoped IP tunneling rather than claim "all protocols". HTTP CONNECT
   and SOCKS4 cannot carry arbitrary UDP/ICMP. QUIC requires a working UDP route,
   MTU/fragmentation handling and actual HTTP/3 tests.
5. Run versioned Claude Code, Codex and Antigravity workflows: login, model
   streaming, cancellation, tools, MCP, terminal descendants and updates, while
   independently observing DNS/IPv4/IPv6/UDP egress and proxy failure behavior.
6. Run native Linux/macOS CI for this branch and produce signed native release
   artifacts. No new remote CI result or live Agent certification is implied.

The Windows hook now makes one chain attempt per application socket: a socket
already connected during a failed handshake cannot be reconnected safely. A new
application socket can use the retained failed-node selection state.
