# Transparent SOCKS5 UDP proxying

Related to [issue #1](https://github.com/tianrking/proxychains-rs/issues/1).

Add `proxy_udp` to a configuration with one or more SOCKS5 nodes, then launch
the application through `proxychains4`. The server must support UDP ASSOCIATE
and its returned UDP relay must be reachable from the client. A `route_group`
rule may select a named group containing one or more SOCKS5 nodes for a UDP
destination, which allows the default TCP configuration to contain a chain.
New UDP associations try eligible nodes in order and use the UDP-specific health
cooldown to skip recently failed nodes. A UDP failure does not hide a node that
is still healthy for TCP, and TCP failures do not remove a working UDP node from
UDP selection. An established association is not migrated if its proxy later
fails.

```ini
strict_chain
proxy_dns
proxy_udp
tcp_connect_time_out 3000
tcp_read_time_out 5000

[ProxyList]
socks5 127.0.0.1 1080
# Authentication: socks5 127.0.0.1 1080 username password
```

```text
proxychains4 -f socks5-udp.conf application [arguments...]
```

Without `proxy_udp`, the new datagram hooks pass through. Invalid UDP proxy
configurations fail initialization. HTTP CONNECT, SOCKS4 and multi-hop UDP chains
are unsupported. Each UDP socket keeps the proxy group chosen for its first
proxied destination; a later rule cannot switch an established SOCKS5
association. `proxychains-udp` remains an explicit fixed-target forwarder.

## Supported socket paths

| Platform | Intercepted operations |
| --- | --- |
| Linux/macOS | `connect`, `sendto`/`recvfrom`, `send`/`recv`, `write`/`read`, `sendmsg`/`recvmsg`, `writev`/`readv`, `getpeername`, `close` |
| Linux | Also `sendmmsg`, and `recvmmsg` with an overall timeout (including `MSG_WAITFORONE`) |
| Windows | `connect`/`WSAConnect`, `sendto`/`recvfrom`, `send`/`recv`, synchronous, IOCP and completion-routine `WSASendTo`/`WSARecvFrom`, `WSASend`/`WSARecv`, synchronous, IOCP and completion-routine `WSASendMsg`/`WSARecvMsg`, `getpeername`, `closesocket` |

Both connected and unconnected datagram sockets are supported. SOCKS frames can
contain IPv4, IPv6 or domain destinations; IPv4 and IPv6 relays are supported.
With `proxy_dns`, synthetic addresses become domains in outgoing SOCKS packets.
Domain-form responses map back to synthetic addresses. An IP-form response on an
unconnected socket exposes the IP supplied by the relay: the protocol cannot
associate it with a particular domain when several domains are in use.

Each socket retains its OS handle, bound port, timeouts and nonblocking mode.
Payload I/O uses that socket; each association has a separate TCP control channel.
The hook removes framing and reports the remote source rather than the relay.
Peek, zero-byte datagrams and platform receive truncation behavior are preserved.
Existing poll/select registrations stay attached to the original socket.

The first connect/send performs a bounded **synchronous** SOCKS handshake, even
on nonblocking sockets. Subsequent datagrams use the original socket flags.
Association failure returns an error without direct fallback. TCP control closure
invalidates the association and places its proxy in the shared health cooldown;
close/recreate the application socket to recover. New UDP associations skip a
proxy while it is in cooldown and successful associations clear that state.
Control closure is checked around I/O but does not independently wake an infinite
poll/receive, so applications should use receive timeouts.

Loopback and configured local networks bypass on sockets without an association,
following the existing bypass policy. Once established, an association stays on
the relay route even when destinations change. Use separate sockets for direct
and proxied traffic. UDP uses initialization-time configuration; restart the
application after changing its proxy. Closing a socket releases its association.
Simultaneous close/reuse and ongoing I/O are outside the supported contract.

## Compatibility boundaries

- Windows asynchronous `WSASendMsg`/`WSARecvMsg` is supported for sockets
  associated with a completion port or using an overlapped completion routine;
  the same applies to `WSASendTo`/`WSARecvFrom`. RIO queries now receive a
  proxy-backed extension table: registered buffers, request/completion queues,
  `RIOSend`/`RIOReceive`, and completion dequeue are routed through the existing
  SOCKS5 UDP data plane. RIO address/control metadata and provider-specific
  notification behavior remain outside the certified surface. Synchronous and
  asynchronous message extension functions are exposed through
  `SIO_GET_EXTENSION_FUNCTION_POINTER`. IOCP `WSASendTo`/`WSARecvFrom`
  completion is supported for sockets associated with a completion port, with
  close cancellation reported through the completion packet.
- Unix ancillary sends are accepted with packet-info and ECN metadata stripped;
  UDP segmentation offload remains unsupported because SOCKS UDP carries one
  datagram per packet. `connect(AF_UNSPEC)` disconnect is rejected. Timed Linux
  `recvmmsg` uses one overall deadline and returns partial batches when it
  expires. Receive control data is marked truncated because relay metadata does
  not describe the original sender.
- On Linux, `dup`, `dup2`, `dup3` and `fcntl(F_DUPFD*)` preserve the shared
  SOCKS5 association and remove replaced descriptor state. macOS dyld
  interposition leaves descriptor duplication on the native path. Descriptor passing, sockets inherited across fork/exec, Windows socket duplication, direct syscalls, io_uring,
  static executables and APIs outside the table remain unsupported.
- SOCKS fragmentation (`FRAG != 0`) is dropped. The payload must fit a UDP packet
  including the SOCKS header: 10 bytes for IPv4, 22 for IPv6, or 7 plus the domain
  byte length. No IP tunneling or ICMP support is added.
- QUIC payloads are opaque UDP. A native Quinn+h3 fixture verifies a real
  HTTP/3 GET and response through the SOCKS5 relay; browser QUIC and MsQuic
  remain uncertified. RIO queue and completion behavior is covered by a native
  Windows fixture, including a successful `RIOSendEx` datagram through a live
  SOCKS5 relay. RIO receive-address/control metadata and provider-specific
  notification behavior still need an application-level fixture.

On Windows, asynchronous `GetAddrInfoExA/W` calls retain the proxy-DNS fake
name until completion. Callback mode forwards the original callback and
`OVERLAPPED` pointer unchanged; event mode releases the context when the
caller invokes `GetAddrInfoExOverlappedResult`. `DnsQuery_A/W` async mode still
uses the system resolver because its completion lifetime is not exposed by the
current hook layer. The synchronous `DnsQuery_UTF8` variant is intercepted with
the same fake-IP mapping as `DnsQuery_A/W`. Modern `DnsQueryEx` callback queries
are intercepted and
retain the fake name until the documented DNS completion callback, while the
caller's query context is restored before forwarding that callback.

This is process-level API interposition, not OS-enforced network isolation.

The Windows `ConnectEx` extension is intercepted as well. Calls without an
`OVERLAPPED` complete synchronously; overlapped calls return
`WSA_IO_PENDING`, preserve the optional initial send buffer, and complete via
the caller's event or the socket's associated IOCP. Closing a socket marks the
pending operation `WSA_OPERATION_ABORTED` and publishes its completion before
the worker exits. The caller must keep the `OVERLAPPED` and byte-count storage
valid until that completion is observed; an already pending operation cannot be
migrated to another socket.

## Native validation

The `native_udp` integration test launches an ordinary UDP program through the
actual DLL/preload library. A local authenticated SOCKS5 server independently
checks UDP ASSOCIATE, IPv4/IPv6/domain framing, the original bound port, empty
packets and control-channel closure. The client checks payload/source recovery,
peek, truncation, nonblocking receive, vectored I/O, Unix descriptor duplication,
socket reuse and failures.
The Windows run additionally submits relay-backed `WSASendTo`, `WSARecvFrom`,
`WSASendMsg` and `WSARecvMsg` operations through an actual completion port and
checks pending status, completion identity, byte counts and payload delivery.
The Windows matrix also closes a socket while an IOCP receive is pending and
checks that the completion is reported as `WSA_OPERATION_ABORTED`.
Other cases cover IPv6 control/relay sockets, rejected associations, invalid
relay ports and control shutdown. CI and release workflows run this test on
Windows, Linux and macOS after building the native library.

Windows:

```powershell
cargo build --locked --workspace --examples
cargo build --locked --workspace
$env:PROXYCHAINS_TEST_DLL = "$pwd/target/debug/proxychains.dll"
$env:PROXYCHAINS_TEST_FIXTURE = "$pwd/target/debug/examples/injection_fixture.exe"
cargo test --locked -p proxychains-injector --test native_udp -- --ignored
```

Linux (use `libproxychains.dylib` on macOS):

```sh
cargo build --locked --workspace --examples
cargo build --locked --workspace
export PROXYCHAINS_TEST_DLL="$PWD/target/debug/libproxychains.so"
export PROXYCHAINS_TEST_FIXTURE="$PWD/target/debug/examples/injection_fixture"
cargo test --locked -p proxychains-injector --test native_udp -- --ignored
```

These fixtures verify a controlled local proxy. They do not certify a third-party
proxy service, NAT traversal or an HTTP/3 application.
