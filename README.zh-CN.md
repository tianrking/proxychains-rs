# proxychains-rs

[English](README.md) | 简体中文

新增透明 UDP 代理：配置 `proxy_udp` 并使用单个 SOCKS5 节点后，支持的应用
socket 调用会通过 UDP ASSOCIATE 转发，支持认证、IPv4、IPv6 和域名封装。
详见 [配置方法、接口覆盖与限制](docs/udp-proxying.md)。
Windows overlapped/IOCP UDP 尚不支持，也不代表所有 QUIC/HTTP/3 应用已经兼容。

`proxychains-rs` 是经典 `proxychains4` 的现代 Rust 实现，支持跨平台“指定进程走代理链”：
- Linux: `LD_PRELOAD`
- macOS: `DYLD_INSERT_LIBRARIES`
- Windows: DLL 注入 + Winsock API Hook

## 当前状态

| 平台 | 运行机制 | 状态 |
|---|---|---|
| Linux | `LD_PRELOAD` | 交叉编译检查通过；已加入原生回归门禁，事件循环兼容性待完善 |
| macOS | `DYLD_INSERT_LIBRARIES` | 交叉编译检查通过；受保护应用和事件循环尚未认证 |
| Windows | DLL 注入 + MinHook | 已改为创建事件树注入；ConnectEx/IOCP 尚未完整实现 |

作者：**tianrking**。已验证的能力、使用方法和未完成事项见
[实施状态](docs/implementation-status.md)。当前不是系统级网络隔离工具，
`raw` 不是原始 IP 隧道；任意应用 UDP、ICMP、QUIC 工作流和完整 Agent 兼容性尚未认证。

新增 Windows 附加入口：`proxychains4 --pid PID`、
`proxychains4 --attach-name FILE.exe`。新增显式 UDP 转发入口：
`proxychains-udp -f FILE --listen 127.0.0.1:1053 --target 1.1.1.1:53`，
配置必须只有一个 SOCKS5 节点，应用需主动使用本地 UDP 端口。

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
- 进程树模式：`--tree`
  - Windows：通过创建事件在根进程及每个子进程恢复前完成注入
  - Linux/macOS：通过 preload 环境变量继承覆盖子进程
- 配置发现/校验：
  - `--list-groups`
  - `--check`
  - `--probe`（快速探测每个节点连通性与时延）
  - `--probe-json`（机器可读 JSON 输出）
  - `--doctor`（端到端协议和目标诊断）
  - 共享代理健康冷却（`proxy_health_cooldown_ms`）：让新连接自动避开
    近期失败的节点；已经建立的连接不会被迁移。
  - `--log-file FILE`（把已捕获的 TCP/UDP 连接结果写入 JSONL）
  - `--events --log-file FILE [--events-follow]`（查看连接记录）
- DNS：
  - `proxy_dns`
  - 兼容别名：`proxy_dns_old`、`proxy_dns_daemon`
  - Fake-IP 映射与反查
- 配置热更新（长进程）：
  - hook 层会自动周期性重读配置（约每 2 秒）
  - Linux/macOS/Windows 行为对齐
- 兼容别名：
  - `round_robin_chain` -> `load_balance`
- IPv6 进展：
  - IPv6 目标可通过 SOCKS5/HTTP 跳转
  - SOCKS4/4a 不支持 IPv6 目标
- 有序分流规则：
  - `route direct|proxy|reject domain|domain_suffix|port|protocol|process VALUE`
  - 第一条匹配规则生效，未匹配的连接保持原代理链行为。
- 项目启动配置：
  - `--profile FILE` 保存命令、参数、工作目录、环境变量、配置文件和代理组。

## 编译

前置条件：
- Rust 1.88+
- Cargo

构建与测试：

```bash
cargo test --locked --workspace --all-targets
cargo build --locked --release --workspace
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

强制代理验证手册：
- [docs/forced-proxy-validation.md](docs/forced-proxy-validation.md)

查看分组/校验配置：

```bash
proxychains4 -f ./proxychains.conf --list-groups
proxychains4 -f ./proxychains.conf --group jp --check
proxychains4 -f ./proxychains.conf --group jp --probe
proxychains4 -f ./proxychains.conf --probe --probe-timeout-ms 1200
proxychains4 -f ./proxychains.conf --probe --probe-json
proxychains4 -f ./proxychains.conf --doctor --doctor-target example.com:80
proxychains4 -f ./proxychains.conf --doctor --doctor-target example.com:80 --doctor-udp-echo 1.1.1.1:53 --doctor-json
proxychains4 -f ./proxychains.conf --tree curl https://ifconfig.me
proxychains4 --profile ./profiles/build.profile
```

`--probe` 只检查代理端口是否接受 TCP 连接。`--doctor` 会分别检查传输、
协议/认证、目标连接，以及可选的 SOCKS5 UDP ASSOCIATE 和真实 UDP 回显。
仅建立 UDP ASSOCIATE 不会被报告为 UDP 转发正常。

启动命令时加入 `--log-file`，即可把 hook 捕获到的 TCP/UDP 连接结果写成
JSONL。记录包含进程号、目标、阶段、结果和时延，不包含代理凭据或报文内容。
另一个终端运行 `--events --events-follow` 可以持续查看记录。记录是尽力而为的，
日志文件忙或不可用时不会阻塞连接 hook。

启动配置是简单的 `KEY = VALUE` 文件，支持 `command`、空格分隔的 `args`、
`cwd`、`config`、`group` 和 `env.NAME`。相对的 `cwd`、`config` 路径均按
profile 文件所在目录解析，从其他目录启动也能保持一致：

```text
command = cargo
args = test --locked
cwd = C:/src/my-project
config = C:/src/my-project/proxychains.conf
group = development
env.RUST_LOG = info
```

## 示例配置

```ini
dynamic_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8
# 代理失败后，从新连接选择中冷却的时间（毫秒）
proxy_health_cooldown_ms 5000

# 可选的有序分流规则（第一条匹配生效）：
# route direct domain_suffix .internal.example
# route reject port 25
# route direct protocol udp

# 兼容别名示例：
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
