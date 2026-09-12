# Agent network implementation status

Owner and commit author: tianrking.

This tracks the requested reliability and capability work. A completed implementation
does not imply verification on an unavailable operating system or application.

| Milestone | Status | Validation required |
| --- | --- | --- |
| TCP protocol correctness | Core regressions fixed | Windows local protocol tests pass; Agent workflows pending |
| DNS mapping and configuration lifecycle | Core fixes implemented | Custom subnet, concurrency, exhaustion and explicit missing path tests |
| Injection readiness and process attachment | Pending | Native Windows failure and success fixtures |
| Unix socket lifecycle and event-loop compatibility | Pending | Linux/macOS native preload tests |
| UDP and IPv6 transport | Pending | Datagram association, IPv6 proxy and target fixtures |
| Agent compatibility and diagnostic bridge | Pending | Exact installed Agent versions and workflows |
| System-enforced network isolation | Pending | Platform-specific enforcement and independent observation |
| Release and platform certification | Pending | Signed native artifacts and CI for final commits |

Existing hook mode must not be described as universal or system-enforced fail-closed
network isolation. Attaching to a running process cannot retroactively proxy its
existing connections. UDP tunneling is distinct from interception of arbitrary UDP
applications; neither implies ICMP/raw-IP forwarding.

The pre-1.0 Rust API now returns Result from DnsCache::get_or_create and
resolve_to_fake_ip. Callers must handle capacity exhaustion instead of assuming
that old fake addresses can be recycled. DNS mappings are process-local, not a
cross-process DNS service.
