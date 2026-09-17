# macOS reliability validation — 2026-09-17

Environment: Apple Silicon (`arm64`), macOS 27.0, Rust 1.88.0.
This is a local fixture-based validation, not certification of every macOS
application, Intel Mac, browser, or external proxy provider.

## Completed changes

| Change | Regression evidence |
| --- | --- |
| Publish original Unix function pointers through `OnceLock`, without mutable global publication | Core tests and native preload TCP/UDP suites |
| Enforce a socket handshake deadline across protocol stages, restoring prior socket timeouts | Slow SOCKS5 regression: 400 ms budget across two delayed stages; completion bounded below 700 ms |
| Move JSONL disk writes to a worker with a 256-record queue | Deliberately blocked writer test verifies producers reject excess records rather than waiting |
| Share immutable Unix configuration snapshots; parse reloads outside the hook state lock | Test verifies the lock is available during parsing, snapshots survive replacement, reload interval applies, and invalid updates retain the last good config |
| Interpose macOS `dup` and `dup2`; preserve UDP session state after a failed duplication | Native UDP fixture verifies original and duplicate use one SOCKS5 association, including failed `dup2(-1, fd)` |
| Prevent optimized early TLS access during dyld/libSystem initialization | Release initially aborted in `_tlv_bootstrap_error`; non-inlined TLS query fixes the reproduced failure; release TCP and UDP suites now pass |
| Mark Unix raw-sockaddr readers `unsafe` with caller requirements | Workspace tests and Clippy pass; pre-1.0 Rust callers must now acknowledge the pointer safety contract |

## Verification

The workspace suite passes 91 tests; five tests are ignored by default.
The two native injection suites were additionally run explicitly against both
debug and optimized release artifacts. The three external-backend tests were
not run. The native UDP suite includes a real Quinn + h3 HTTP/3 request and
response through a local SOCKS5 relay, not just a UDP codec simulation.
An additional release run with JSONL logging enabled passes both suites and
produces 332 parseable events; all have schema `1.0` and no `password` or
`payload` field. The observed count is not a delivery guarantee.

```sh
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets
cargo build --locked --workspace --examples
cargo build --locked --workspace
PROXYCHAINS_TEST_DLL="$PWD/target/debug/libproxychains.dylib" \
PROXYCHAINS_TEST_FIXTURE="$PWD/target/debug/examples/injection_fixture" \
cargo test --locked -p proxychains-injector --test native_preload --test native_udp -- --ignored

cargo build --locked --release --workspace --examples
cargo build --locked --release --workspace
PROXYCHAINS_TEST_DLL="$PWD/target/release/libproxychains.dylib" \
PROXYCHAINS_TEST_FIXTURE="$PWD/target/release/examples/injection_fixture" \
cargo test --locked -p proxychains-injector --test native_preload --test native_udp -- --ignored
```

CI now includes optimized macOS injection tests, an explicit Rust 1.88 check,
and non-advisory Unix Clippy errors. Existing lint warnings remain; this is not
a `-D warnings` clean baseline. Formatting and Windows Clippy remain advisory.
Remote CI has not been run for these local commits.

## Remaining compatibility and performance work

- Unix TCP still performs a synchronous handshake and replaces the application
  descriptor. Full nonblocking connect, epoll/kqueue registrations, source binds
  and socket-option preservation need a coordinated implementation and tests.
- macOS `fcntl(F_DUPFD*)` duplication is not intercepted; testing `dup` does not
  certify Rust `UdpSocket::try_clone` or every other duplication API on macOS.
- Windows overlapped UDP still creates a thread per operation. Resource bounds,
  cancellation ownership and browser QUIC require native Windows work.
- JSONL is best-effort: full queues and records above 16 KiB are dropped. The
  worker does not flush at process exit; fork children skip inherited queues
  until exec. `trace::dropped_events()` exposes losses. This is not an audit log.
- The handshake deadline is per proxy hop, not one total chain deadline. Generic
  `Read + Write` codec entry points cannot interrupt an arbitrary blocking reader.
- Hooks are not system-enforced isolation and cannot cover every process or
  networking API. These tests do not establish SIP/hardened-app compatibility.
- No matched throughput/latency benchmark against upstream proxychains has been
  performed. Broader features alone do not prove overall performance superiority.

All changes are local commits; nothing has been pushed or released.
