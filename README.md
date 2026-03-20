# proxychains-rs

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-GPL%2.0-blue.svg)](LICENSE)

A modern Rust implementation of the classic proxychains tool, providing elegant and powerful proxy chaining capabilities with cross-platform support.

## Quick Start

```bash
# 1. Build
cargo build --release

# 2. Create config file (Linux/macOS)
cp proxychains.conf ~/.proxychains/

# 3. Run
./target/release/proxychains4 curl https://ifconfig.me
```

## Features

- **Multiple Proxy Protocols**: SOCKS4, SOCKS4a, SOCKS5 (with authentication), HTTP CONNECT
- **Chain Modes**: Strict, Dynamic, Random, Load Balance, Failover
- **DNS Handling**: Local resolution, Remote DNS through proxy, Fake IP mapping
- **Cross-platform**:
  - Linux (LD_PRELOAD)
  - macOS (DYLD_INSERT_LIBRARIES)
  - **Windows (DLL Injection + API Hooking)**
- **Thread Safe**: All operations are thread-safe

## Platform Support

| Platform | Mechanism | Status |
|----------|-----------|--------|
| Linux | LD_PRELOAD | Stable |
| macOS | DYLD_INSERT_LIBRARIES | Stable |
| Windows | DLL Injection + MinHook | Beta |

---

## How to Compile

### Prerequisites

- **Rust 1.70+**: Install from https://rustup.rs
- **Cargo**: Comes with Rust

#### Platform-specific Requirements

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config

# Fedora/RHEL
sudo dnf install gcc pkg-config
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**
1. Install Visual Studio Build Tools from https://visualstudio.microsoft.com/downloads/
2. Select "Desktop development with C++" workload
3. Ensure MSVC toolchain is active:
   ```powershell
   rustup default stable-x86_64-pc-windows-msvc
   ```

### Build Commands

```bash
# Clone repository
git clone https://github.com/your-repo/proxychains-rs.git
cd proxychains-rs

# Debug build (faster compile, larger binary, slower runtime)
cargo build

# Release build (slower compile, smaller binary, faster runtime) - RECOMMENDED
cargo build --release

# Run tests
cargo test
```

### Build Outputs

After successful build, you'll find:

| Platform | CLI Binary | Library |
|----------|------------|---------|
| Linux | `target/release/proxychains4` | `target/release/libproxychains.so` |
| macOS | `target/release/proxychains4` | `target/release/libproxychains.dylib` |
| Windows | `target/release/proxychains4.exe` | `target/release/proxychains.dll` |

---

## Installation

### System-wide Installation

#### Linux

```bash
sudo cp target/release/proxychains4 /usr/local/bin/
sudo cp target/release/libproxychains.so /usr/local/lib/
sudo ldconfig
sudo cp proxychains.conf /usr/local/etc/
```

#### macOS

```bash
sudo cp target/release/proxychains4 /usr/local/bin/
sudo cp target/release/libproxychains.dylib /usr/local/lib/
sudo cp proxychains.conf /usr/local/etc/
```

#### Windows

Copy files to a directory in your PATH:

```powershell
# Option 1: Copy to Windows directory (requires admin)
copy target\release\proxychains4.exe C:\Windows\
copy target\release\proxychains.dll C:\Windows\

# Option 2: Add build directory to PATH (current session only)
$env:PATH += ";$PWD\target\release"

# Option 3: Add to user PATH permanently
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\path\to\proxychains-rs\target\release", "User")
```

---

## Usage

### Basic Usage

```bash
# Linux / macOS
proxychains4 curl https://ifconfig.me

# Windows
proxychains4.exe curl https://ifconfig.me
```

### Command Line Options

```
Usage: proxychains4 [OPTIONS] <COMMAND> [ARGS...]

Options:
  -f, --file <PATH>    Configuration file path
  --group <GROUP>      Proxy group name (uses [ProxyList:<GROUP>])
  -q, --quiet          Quiet mode (suppress output)
  -v, --verbose        Verbose mode (debug output)
  -h, --help           Show help

Examples:
  proxychains4 curl https://example.com
  proxychains4 -f /path/to/config.conf wget https://example.com
  proxychains4 -q firefox
```

### Using with Different Programs

```bash
# Web browsers
proxychains4 firefox
proxychains4 chromium

# Download tools
proxychains4 wget https://example.com/file.zip
proxychains4 curl https://api.ipify.org

# SSH
proxychains4 ssh user@remote-host

# Git
proxychains4 git clone https://github.com/repo.git
```

---

## Configuration

### Configuration File Format

```ini
# Chain types: dynamic_chain, strict_chain, random_chain
dynamic_chain

# Proxy DNS through the chain (recommended - prevents DNS leaks)
proxy_dns

# Remote DNS subnet for fake IPs (default: 224)
remote_dns_subnet 224

# Timeouts (milliseconds)
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8

# Local networks to bypass (CIDR notation)
localnet 127.0.0.0/255.0.0.0
localnet 192.168.0.0/255.255.0.0

# Proxy list
[ProxyList]
# Format: type host port [user pass]

# SOCKS5 proxies
socks5 127.0.0.1 1080

# SOCKS5 with authentication
socks5 192.168.1.1 1080 username password

# SOCKS4 proxies
socks4 192.168.1.2 1080

# HTTP proxies
http 192.168.1.3 8080
http 192.168.1.4 8080 user pass

# Optional grouped lists
[ProxyList:jp]
socks5 10.0.0.2 1080

[ProxyList:us]
socks5 10.0.0.3 1080
```

Group usage example:
```bash
proxychains4 --group jp curl https://ifconfig.me
```

### Configuration File Locations

The configuration file is searched in the following order:

**Linux / macOS:**
1. Path specified by `-f` flag
2. `PROXYCHAINS_CONF_FILE` environment variable
3. `./proxychains.conf`
4. `~/.proxychains/proxychains.conf`
5. `/etc/proxychains.conf`
6. `/usr/local/etc/proxychains.conf`

**Windows:**
1. Path specified by `-f` flag
2. `PROXYCHAINS_CONF_FILE` environment variable
3. `.\proxychains.conf`
4. `%APPDATA%\proxychains\proxychains.conf`
5. `%PROGRAMDATA%\proxychains\proxychains.conf`
6. Same directory as `proxychains4.exe`

### Quick Setup

```bash
# Create config directory
mkdir -p ~/.proxychains

# Copy example config
cp proxychains.conf ~/.proxychains/

# Edit with your proxy settings
nano ~/.proxychains/proxychains.conf
```

---

## Windows Technical Details

On Windows, proxychains uses a different mechanism compared to Unix systems:

### How It Works

1. **DLL Injection**: `proxychains4.exe` creates a new process in suspended state
2. **API Hooking**: Injects `proxychains.dll` which uses MinHook to intercept Winsock2 calls
3. **Hooked Functions**:
   - `connect`
   - `getaddrinfo`
   - `freeaddrinfo`
   - `gethostbyname`
   - `getnameinfo`

### Windows Requirements

- Windows 10 or later
- Visual Studio Build Tools (MSVC toolchain)
- Rust with MSVC target: `rustup target add x86_64-pc-windows-msvc`

### Windows Limitations

- May be detected by antivirus software (DLL injection is a common technique)
- Requires same architecture (32-bit process needs 32-bit DLL)
- Some programs may not work if they statically link Winsock
- Admin privileges may be required for some target processes

---

## Project Structure

```
proxychains-rs/
├── proxychains/           # Core library
│   ├── src/
│   │   ├── config/        # Configuration parsing
│   │   ├── proxy/         # Proxy protocol implementations
│   │   ├── chain/         # Chain management
│   │   ├── dns/           # DNS handling
│   │   ├── hook/          # Platform-specific hooks
│   │   ├── net/           # Network utilities
│   │   └── platform/      # Platform abstraction
├── proxychains-bin/       # CLI binary
├── libproxychains/        # Dynamic library for injection
├── proxychains-injector/  # Windows DLL injection
└── proxychains.conf       # Example configuration
```

---

## Troubleshooting

### Common Issues

**"library not found" error:**
```bash
# Linux
sudo ldconfig
# Or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

**"DLL not found" error (Windows):**
- Ensure `proxychains.dll` is in the same directory as `proxychains4.exe`
- Or copy both to a PATH directory

**Proxy not working:**
1. Verify your proxy server is running
2. Check configuration file syntax
3. Use `-v` flag for debug output: `proxychains4 -v curl https://ifconfig.me`

**DNS leaks:**
- Add `proxy_dns` to your configuration file

---

## License

GPL-2.0

## Acknowledgments

This project is a Rust implementation of the original [proxychains-ng](https://github.com/rofl0r/proxychains-ng) project.

---
---

# proxychains-rs (中文文档)

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-GPL%2.0-blue.svg)](LICENSE)

经典 proxychains 工具的现代 Rust 实现，提供优雅且强大的代理链功能，支持跨平台。

## 快速开始

```bash
# 1. 编译
cargo build --release

# 2. 创建配置文件 (Linux/macOS)
cp proxychains.conf ~/.proxychains/

# 3. 运行
./target/release/proxychains4 curl https://ifconfig.me
```

## 特性

- **多种代理协议**: SOCKS4, SOCKS4a, SOCKS5 (带认证), HTTP CONNECT
- **链式模式**: 严格链, 动态链, 随机链, 负载均衡, 故障转移
- **DNS 处理**: 本地解析, 通过代理的远程 DNS, Fake IP 映射
- **跨平台支持**:
  - Linux (LD_PRELOAD)
  - macOS (DYLD_INSERT_LIBRARIES)
  - **Windows (DLL 注入 + API Hooking)**
- **线程安全**: 所有操作都是线程安全的

## 平台支持

| 平台 | 机制 | 状态 |
|------|------|------|
| Linux | LD_PRELOAD | 稳定 |
| macOS | DYLD_INSERT_LIBRARIES | 稳定 |
| Windows | DLL 注入 + MinHook | 测试版 |

---

## 如何编译

### 前置要求

- **Rust 1.70+**: 从 https://rustup.rs 安装
- **Cargo**: 随 Rust 一起安装

#### 平台特定要求

**Linux:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config

# Fedora/RHEL
sudo dnf install gcc pkg-config
```

**macOS:**
```bash
xcode-select --install
```

**Windows:**
1. 从 https://visualstudio.microsoft.com/downloads/ 安装 Visual Studio Build Tools
2. 选择 "Desktop development with C++" 工作负载
3. 确保 MSVC 工具链已激活:
   ```powershell
   rustup default stable-x86_64-pc-windows-msvc
   ```

### 编译命令

```bash
# 克隆仓库
git clone https://github.com/your-repo/proxychains-rs.git
cd proxychains-rs

# Debug 构建 (编译快，二进制大，运行慢)
cargo build

# Release 构建 (编译慢，二进制小，运行快) - 推荐
cargo build --release

# 运行测试
cargo test
```

### 编译输出

编译成功后，你将获得:

| 平台 | CLI 二进制 | 库文件 |
|------|-----------|--------|
| Linux | `target/release/proxychains4` | `target/release/libproxychains.so` |
| macOS | `target/release/proxychains4` | `target/release/libproxychains.dylib` |
| Windows | `target/release/proxychains4.exe` | `target/release/proxychains.dll` |

---

## 安装

### 系统级安装

#### Linux

```bash
sudo cp target/release/proxychains4 /usr/local/bin/
sudo cp target/release/libproxychains.so /usr/local/lib/
sudo ldconfig
sudo cp proxychains.conf /usr/local/etc/
```

#### macOS

```bash
sudo cp target/release/proxychains4 /usr/local/bin/
sudo cp target/release/libproxychains.dylib /usr/local/lib/
sudo cp proxychains.conf /usr/local/etc/
```

#### Windows

将文件复制到 PATH 目录:

```powershell
# 方法 1: 复制到 Windows 目录 (需要管理员权限)
copy target\release\proxychains4.exe C:\Windows\
copy target\release\proxychains.dll C:\Windows\

# 方法 2: 添加构建目录到 PATH (仅当前会话)
$env:PATH += ";$PWD\target\release"

# 方法 3: 永久添加到用户 PATH
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\path\to\proxychains-rs\target\release", "User")
```

---

## 使用方法

### 基本用法

```bash
# Linux / macOS
proxychains4 curl https://ifconfig.me

# Windows
proxychains4.exe curl https://ifconfig.me
```

### 命令行选项

```
用法: proxychains4 [选项] <命令> [参数...]

选项:
  -f, --file <路径>    配置文件路径
  -q, --quiet          静默模式 (抑制输出)
  -v, --verbose        详细模式 (调试输出)
  -h, --help           显示帮助

示例:
  proxychains4 curl https://example.com
  proxychains4 -f /path/to/config.conf wget https://example.com
  proxychains4 -q firefox
```

### 与不同程序配合使用

```bash
# 网页浏览器
proxychains4 firefox
proxychains4 chromium

# 下载工具
proxychains4 wget https://example.com/file.zip
proxychains4 curl https://api.ipify.org

# SSH
proxychains4 ssh user@remote-host

# Git
proxychains4 git clone https://github.com/repo.git
```

---

## 配置

### 配置文件格式

```ini
# 链类型: dynamic_chain, strict_chain, random_chain
dynamic_chain

# 通过代理链代理 DNS (推荐 - 防止 DNS 泄露)
proxy_dns

# 远程 DNS 子网用于 Fake IP (默认: 224)
remote_dns_subnet 224

# 超时设置 (毫秒)
tcp_read_time_out 15000
tcp_connect_time_out 8000
max_chain_retries 8

# 绕过的本地网络 (CIDR 表示法)
localnet 127.0.0.0/255.0.0.0
localnet 192.168.0.0/255.255.0.0

# 代理列表
[ProxyList]
# 格式: 类型 主机 端口 [用户名 密码]

# SOCKS5 代理
socks5 127.0.0.1 1080

# SOCKS5 带认证
socks5 192.168.1.1 1080 username password

# SOCKS4 代理
socks4 192.168.1.2 1080

# HTTP 代理
http 192.168.1.3 8080
http 192.168.1.4 8080 user pass
```

### 配置文件位置

配置文件按以下顺序搜索:

**Linux / macOS:**
1. `-f` 标志指定的路径
2. `PROXYCHAINS_CONF_FILE` 环境变量
3. `./proxychains.conf`
4. `~/.proxychains/proxychains.conf`
5. `/etc/proxychains.conf`
6. `/usr/local/etc/proxychains.conf`

**Windows:**
1. `-f` 标志指定的路径
2. `PROXYCHAINS_CONF_FILE` 环境变量
3. `.\proxychains.conf`
4. `%APPDATA%\proxychains\proxychains.conf`
5. `%PROGRAMDATA%\proxychains\proxychains.conf`
6. 与 `proxychains4.exe` 同目录

### 快速设置

```bash
# 创建配置目录
mkdir -p ~/.proxychains

# 复制示例配置
cp proxychains.conf ~/.proxychains/

# 编辑你的代理设置
nano ~/.proxychains/proxychains.conf
```

---

## Windows 技术细节

在 Windows 上，proxychains 使用与 Unix 系统不同的机制:

### 工作原理

1. **DLL 注入**: `proxychains4.exe` 创建暂停状态的新进程
2. **API Hooking**: 注入 `proxychains.dll`，使用 MinHook 拦截 Winsock2 调用
3. **Hook 的函数**:
   - `connect`
   - `getaddrinfo`
   - `freeaddrinfo`
   - `gethostbyname`
   - `getnameinfo`

### Windows 要求

- Windows 10 或更高版本
- Visual Studio Build Tools (MSVC 工具链)
- Rust MSVC 目标: `rustup target add x86_64-pc-windows-msvc`

### Windows 限制

- 可能被杀毒软件检测 (DLL 注入是常用技术)
- 需要相同架构 (32 位进程需要 32 位 DLL)
- 静态链接 Winsock 的程序可能无法工作
- 某些目标进程可能需要管理员权限

---

## 项目结构

```
proxychains-rs/
├── proxychains/           # 核心库
│   ├── src/
│   │   ├── config/        # 配置解析
│   │   ├── proxy/         # 代理协议实现
│   │   ├── chain/         # 链管理
│   │   ├── dns/           # DNS 处理
│   │   ├── hook/          # 平台特定钩子
│   │   ├── net/           # 网络工具
│   │   └── platform/      # 平台抽象
├── proxychains-bin/       # CLI 二进制
├── libproxychains/        # 注入用动态库
├── proxychains-injector/  # Windows DLL 注入器
└── proxychains.conf       # 示例配置
```

---

## 故障排除

### 常见问题

**"library not found" 错误:**
```bash
# Linux
sudo ldconfig
# 或设置 LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

**"DLL not found" 错误 (Windows):**
- 确保 `proxychains.dll` 与 `proxychains4.exe` 在同一目录
- 或将两者复制到 PATH 目录

**代理不工作:**
1. 验证代理服务器正在运行
2. 检查配置文件语法
3. 使用 `-v` 标志查看调试输出: `proxychains4 -v curl https://ifconfig.me`

**DNS 泄露:**
- 在配置文件中添加 `proxy_dns`

---

## 许可证

GPL-2.0

## 致谢

本项目是原始 [proxychains-ng](https://github.com/rofl0r/proxychains-ng) 项目的 Rust 实现。
