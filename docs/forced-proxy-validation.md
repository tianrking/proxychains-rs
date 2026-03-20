# Forced Proxy Validation Manual

This manual provides a fail-closed validation flow:
- direct path must show your direct egress IP;
- valid proxy must show a different proxy egress IP;
- invalid proxy must fail (must not silently fall back to direct).

## 1) Prepare a working local proxy

Example (replace with your own proxy endpoint):

- SOCKS5 at `127.0.0.1:5091`
- HTTP at `127.0.0.1:5098`

## 2) Create test configs

Good config (`proxy-good.conf`):

```ini
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 5091
```

Bad config (`proxy-bad.conf`):

```ini
strict_chain
proxy_dns
tcp_read_time_out 5000
tcp_connect_time_out 2000

[ProxyList]
socks5 127.0.0.1 5999
```

## 3) One-shot verification commands

### Windows (PowerShell)

```powershell
curl.exe --max-time 15 https://ifconfig.me
.\proxychains4.exe -f .\proxy-good.conf -v curl --max-time 15 https://ifconfig.me
.\proxychains4.exe -f .\proxy-bad.conf -v curl --max-time 10 https://ifconfig.me; $LASTEXITCODE
```

Expected:
- line 1 (direct) and line 2 (proxy) should be different IPs;
- line 3 should fail and return non-zero exit code (for curl usually `7`).

### Linux/macOS

```bash
curl --max-time 15 https://ifconfig.me
./proxychains4 -f ./proxy-good.conf -v curl --max-time 15 https://ifconfig.me
./proxychains4 -f ./proxy-bad.conf -v curl --max-time 10 https://ifconfig.me; echo $?
```

Expected:
- direct IP != proxied IP
- bad proxy run exits non-zero

## 4) DNS leak protection quick check

When `proxy_dns` is enabled, hostname resolution inside proxied process should be fake-IP mapped.

Linux/macOS:

```bash
./proxychains4 -q -f ./proxy-good.conf python3 -c "import socket;print(socket.getaddrinfo('dns-proxychains-check.invalid',443,0,socket.SOCK_STREAM)[0][4][0])"
./proxychains4 -q -f ./proxy-good.conf python3 -c "import socket;print(socket.getaddrinfo('dns-proxychains-check.invalid',443,socket.AF_INET6,socket.SOCK_STREAM)[0][4][0])"
```

Expected:
- IPv4 output starts with `224.`
- IPv6 output starts with `::ffff:224.`

## 5) Troubleshooting

- `No proxies configured`: verify `[ProxyList]` and `-f` path.
- Direct/proxy IP same: proxy endpoint may share same egress as direct path; run bad-proxy test to verify fail-closed behavior.
- Windows: keep `proxychains4.exe` and `proxychains.dll` in same directory.
