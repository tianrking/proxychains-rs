# Local SOCKS5 service for Codex, Claude Code, and other agents

`proxychains-socks5` exposes a local SOCKS5 CONNECT endpoint and sends every
accepted connection through the selected proxychains configuration. It is a
client-facing adapter, not a direct-connect fallback: if the upstream proxy
chain fails, the client receives a SOCKS5 failure response.

The service binds to `127.0.0.1:1081` by default. Keep it loopback-only unless
you intentionally need remote clients. A non-loopback listener requires both
`--allow-remote` and local SOCKS5 credentials.

## Start the local service

Create an upstream configuration containing a real proxy endpoint you control:

```text
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080 upstream-user upstream-password
```

Then run the service separately from the agent process:

```bash
cargo run --release -p proxychains-bin --bin proxychains-socks5 -- \
  -f ./agent-upstream.conf \
  --listen 127.0.0.1:1081 \
  --username agent --password 'choose-a-long-local-secret'
```

The upstream proxy is mandatory. Do not put `raw` in this configuration: the
service rejects it at startup because `raw` is not an upstream proxy protocol.
Domain CONNECT requests are relayed as domains to SOCKS4a, SOCKS5, or HTTP
CONNECT upstream hops, so the local service does not resolve agent target names.

## Use the service with an agent

For clients that support SOCKS proxy environment variables, use `socks5h` so
the client does not resolve target domains itself:

```bash
export ALL_PROXY='socks5h://agent:choose-a-long-local-secret@127.0.0.1:1081'
export all_proxy="$ALL_PROXY"
unset NO_PROXY no_proxy

codex
# or: claude
```

`ALL_PROXY` support is determined by the agent/runtime. For a process that does
not honor that variable, launch it through the native hook instead. The hook
uses the same upstream configuration directly:

```bash
proxychains4 -f ./agent-upstream.conf --tree -- codex
# or: proxychains4 -f ./agent-upstream.conf --tree -- claude
```

On Linux and macOS, `--tree` propagates preload settings to child processes. On
Windows it uses creation-time DLL injection for the root and child processes.
Use one approach per agent process: either `ALL_PROXY` through the local
listener or a direct `proxychains4 --tree` launch. Starting the local service
itself under `proxychains4` is unnecessary and can create a proxy loop.

## Supported local SOCKS5 contract

- SOCKS version 5 CONNECT with IPv4, IPv6, or domain targets.
- No-auth mode, or RFC 1929 username/password mode when local credentials are
  configured.
- A bounded number of concurrent clients (`--max-clients`, default 128).
- TCP bidirectional relay only. Unsupported SOCKS commands return a SOCKS5
  command-not-supported response; they never become a direct connection.

For UDP-aware applications, use the existing `proxy_udp` hook path or the
explicit `proxychains-udp` forwarder. The local SOCKS5 listener intentionally
does not pretend to implement SOCKS UDP ASSOCIATE.
