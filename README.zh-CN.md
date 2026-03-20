# proxychains-rs

[English](README.md) | 简体中文

`proxychains-rs` 是经典 `proxychains4` 的现代 Rust 实现，支持跨平台“指定进程走代理链”：
- Linux: `LD_PRELOAD`
- macOS: `DYLD_INSERT_LIBRARIES`
- Windows: DLL 注入 + Winsock API Hook

## 当前状态

| 平台 | 运行机制 | 状态 |
|---|---|---|
| Linux | `LD_PRELOAD` | 稳定 |
| macOS | `DYLD_INSERT_LIBRARIES` | 稳定 |
| Windows | DLL 注入 + MinHook | Beta（已可实用，持续补齐边缘场景） |

## Linux 支持范围（重要）

“所有 Linux 版本都完美支持”不现实，当前建议按下面理解：

已支持：
- 主流 `glibc` 发行版 `x86_64`（Ubuntu / Debian / Fedora / RHEL 系）
- 使用动态链接 libc 套接字接口的应用

暂不保证：
- 过旧发行版或过旧 glibc
- `musl` 环境（例如 Alpine）未做完整矩阵验证
- 静态链接网络栈、绕过可 hook libc 入口的程序

建议：
- 把现代 Ubuntu/Debian/Fedora/RHEL-like 作为主支持范围。
- 若要企业级保证，请在你的目标发行版矩阵上跑 CI 验证。

## 核心功能

- 代理协议：`socks5`、`socks4`/`socks4a`、`http`、`raw`
- 链路模式：`dynamic_chain`、`strict_chain`、`random_chain`、`load_balance`、`failover`
- 代理分组：`[ProxyList:<group>]` + `--group`
- 配置发现/校验：
  - `--list-groups`
  - `--check`
  - `--probe`（快速探测每个节点连通性与时延）
  - `--probe-json`（机器可读 JSON 输出）
- DNS：
  - `proxy_dns`
  - 兼容别名：`proxy_dns_old`、`proxy_dns_daemon`
  - Fake-IP 映射与反查
- 兼容别名：
  - `round_robin_chain` -> `load_balance`
- IPv6 进展：
  - IPv6 目标可通过 SOCKS5/HTTP 跳转
  - SOCKS4/4a 不支持 IPv6 目标

## 编译

前置条件：
- Rust 1.70+
- Cargo

构建与测试：

```bash
cargo test --workspace --all-targets
cargo build --release --workspace
```

## 产物

构建完成后：

| 平台 | CLI | 动态库 |
|---|---|---|
| Linux | `target/release/proxychains4` | `target/release/libproxychains.so` |
| macOS | `target/release/proxychains4` | `target/release/libproxychains.dylib` |
| Windows | `target/release/proxychains4.exe` | `target/release/proxychains.dll` |

## 快速使用

```bash
# Linux/macOS
proxychains4 curl https://ifconfig.me

# Windows
proxychains4.exe curl https://ifconfig.me
```

查看分组/校验配置：

```bash
proxychains4 -f ./proxychains.conf --list-groups
proxychains4 -f ./proxychains.conf --group jp --check
proxychains4 -f ./proxychains.conf --group jp --probe
proxychains4 -f ./proxychains.conf --probe --probe-timeout-ms 1200
proxychains4 -f ./proxychains.conf --probe --probe-json
```

## 示例配置

```ini
dynamic_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8

# 兼容别名示例：
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

## DNS 与泄漏防护说明

- 建议开启 `proxy_dns`。
- 在当前主路径实现中，`proxy_dns` 模式会尽量避免回退系统 DNS。
- Hook 方案天然受目标程序运行时/链接模型影响，需对关键目标程序做实测。

## CI / Release

- CI：GitHub Actions 多平台编译测试
- Release：tag 触发构建并发布资产（Windows zip、Linux tar/deb、macOS tar）

## 常见问题

- `No proxies configured`：检查 `[ProxyList]` 和 `-f` 路径
- 担心 DNS 泄漏：确认 `proxy_dns` 已开启
- Windows DLL 报错：保证 `proxychains4.exe` 与 `proxychains.dll` 同目录
- Linux preload 异常：确认目标程序是动态链接并且支持 `LD_PRELOAD`

## License

GPL-2.0

## 致谢

灵感来源于 [proxychains-ng](https://github.com/rofl0r/proxychains-ng)。
