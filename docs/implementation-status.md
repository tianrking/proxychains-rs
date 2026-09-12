# Agent network implementation status

Owner and commit author: tianrking.

This tracks the requested reliability and capability work. A completed implementation
does not imply verification on an unavailable operating system or application.

| Milestone | Status | Validation required |
| --- | --- | --- |
| TCP protocol correctness | In progress | Authentication, payload preservation, every proxy hop |
| DNS mapping and configuration lifecycle | Pending | Subnets, concurrent allocation, stale mappings |
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
