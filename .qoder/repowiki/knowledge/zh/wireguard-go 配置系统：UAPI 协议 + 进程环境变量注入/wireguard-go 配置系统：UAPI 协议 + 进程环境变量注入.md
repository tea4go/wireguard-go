---
kind: configuration_system
name: wireguard-go 配置系统：UAPI 协议 + 进程环境变量注入
category: configuration_system
scope:
    - '**'
source_files:
    - main.go
    - main_windows.go
    - version.go
    - device/uapi.go
    - device/constants.go
    - ipc/uapi_unix.go
    - ipc/uapi_windows.go
    - conn/controlfns.go
---

## 1. 采用的方式

wireguard-go 没有使用任何配置文件格式（无 YAML/TOML/JSON/envfile），也没有命令行参数解析框架。其“配置”由两部分组成：
- **进程启动期配置**：通过 `os.Args` 与一组预定义的环境变量，决定 TUN/UAPI 文件描述符、前台/后台模式、日志级别。
- **运行时配置**：通过 WireGuard UAPI（Unix domain socket / Windows 命名管道）的 `get=1` / `set=1` 明文键值协议动态加载 peer、密钥、allowed_ip、listen_port、fwmark 等。

因此，该仓库的配置系统本质上是：**极简 CLI + 环境变量 + 标准 UAPI 协议**，所有持久化配置均由外部编排器（systemd、容器、supervisor、wg-quick 等）负责生成并写入 UAPI。

## 2. 关键文件

| 文件 | 作用 |
|---|---|
| `main.go`（非 Windows） | 解析 `-f/--foreground`、读取 `WG_TUN_FD`、`WG_UAPI_FD`、`WG_PROCESS_FOREGROUND`、`LOG_LEVEL`；创建 TUN/UAPI；fork 子进程完成 daemonize；启动 `device.NewDevice` 与 UAPI listener |
| `main_windows.go` | Windows 入口，仅接受一个接口名参数，默认 verbose 日志，直接调用 `ipc.UAPIListen` |
| `version.go` | 提供 `Version` 常量，用于 `--version` 输出 |
| `device/uapi.go` | 实现 UAPI 协议：`IpcGetOperation`（序列化当前设备/peer 状态）、`IpcSetOperation`（按行解析 key=value 并应用）、`handleDeviceLine`、`handlePeerLine` |
| `device/constants.go` | 协议级与实现级常量（如 `RekeyAfterTime`、`MaxPeers` 等），不属于用户可配置项，但构成配置语义边界 |
| `ipc/*` | 跨平台 UAPI 监听/连接抽象（Unix socket / Windows named pipe / WASM stub） |
| `conn/controlfns*.go` | 通过 `net.ListenConfig.Control` 回调设置 socket 选项（sticky socket、GSO/GRO 等），属于网络栈层面的“隐式配置” |

## 3. 架构与设计决策

### 3.1 进程启动期：环境变量优先于配置文件

`main.go` 中定义了三个固定常量作为环境变量名：
- `ENV_WG_TUN_FD = "WG_TUN_FD"`：若存在则从 fd 打开已有 TUN 设备，否则调用 `tun.CreateTUN(interfaceName, device.DefaultMTU)`。
- `ENV_WG_UAPI_FD = "WG_UAPI_FD"`：同上，复用已有 UAPI fd。
- `ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"`：控制是否前台运行；当未显式传入 `-f/--foreground` 时以此环境变量为准。

日志级别通过 `LOG_LEVEL` 环境变量控制，取值映射为 `device.LogLevelVerbose` / `LogLevelError` / `LogLevelSilent`，默认 `LogLevelError`。

daemonize 流程：主进程 fork 自身为子进程，将 TUN fd 固定到 fd 3、UAPI fd 固定到 fd 4，并在子进程 env 中追加 `WG_TUN_FD=3`、`WG_UAPI_FD=4`、`WG_PROCESS_FOREGROUND=1`，使子进程以“前台模式”继续执行后续逻辑。这是一种典型的“父进程准备资源 → 子进程接管”的配置传递方式。

### 3.2 运行时配置：WireGuard UAPI 协议

UAPI 是 wireguard-go 的核心配置通道，位于 `device/uapi.go`：
- `IpcGetOperation` 按行输出 `private_key`、`listen_port`、`fwmark`、每个 peer 的 `public_key`、`preshared_key`、`endpoint`、`protocol_version`、`last_handshake_time_*`、`tx_bytes`、`rx_bytes`、`persistent_keepalive_interval`、`allowed_ip`。
- `IpcSetOperation` 逐行解析 `key=value`，遇到空行结束一次 set 操作。首条 `public_key=` 之前的行视为 device 级配置（`handleDeviceLine`），之后进入 peer 级配置（`handlePeerLine`）。

支持的 device 级 key：
- `private_key`：Noise 私钥（十六进制）
- `listen_port`：UDP 监听端口，修改后调用 `BindUpdate()` 重新绑定
- `fwmark`：Linux 防火墙标记，调用 `BindSetMark()` 设置
- `replace_peers=true`：清空全部 peer

支持的 peer 级 key：
- `update_only=true`：禁止创建新 peer，仅更新已存在的
- `remove=true`：删除当前 peer
- `preshared_key`：预共享密钥
- `endpoint`：对端地址（由 `bind.ParseEndpoint` 解析）
- `persistent_keepalive_interval`：保活间隔（秒）
- `replace_allowed_ips=true`：清空 allowed_ip
- `allowed_ip=<prefix>` 或 `-<prefix>`：添加/移除允许网段
- `protocol_version=1`：协议版本校验

错误通过 `IPCError` 包装返回，包含 `errno=<code>` 响应码（`IpcErrorInvalid`、`IpcErrorPortInUse`、`IpcErrorIO`、`IpcErrorProtocol`、`IpcErrorUnknown`）。

### 3.3 平台差异

- Unix (`main.go`)：支持 `-f/--foreground` 与 `WG_*` 环境变量，支持 daemonize。
- Windows (`main_windows.go`)：仅接受一个参数（接口名），强制 verbose 日志，不支持环境变量注入，也不做 daemonize。
- 其他平台通过 build tag 选择不同实现（如 `ipc/uapi_bsd.go`、`ipc/uapi_wasm.go`）。

## 4. 约定与约束

1. **无配置文件**：仓库内不存在 `.yaml`、`.toml`、`.env`、`.conf` 等配置文件；所有配置必须通过 UAPI 或启动期环境变量注入。
2. **环境变量白名单**：仅识别 `WG_TUN_FD`、`WG_UAPI_FD`、`WG_PROCESS_FOREGROUND`、`LOG_LEVEL` 四个环境变量，其余被忽略。
3. **UAPI 协议严格性**：`IpcSetOperation` 遇到未知 key 会返回 `IpcErrorInvalid`；peer 配置必须以 `public_key=` 开头；每行必须是 `key=value` 形式，否则返回 `IpcErrorProtocol`。
4. **配置生效时机**：device 级配置（如 `listen_port`、`fwmark`）在 set 后立即生效；peer 级配置在 `handlePostConfig` 中触发 `Start()`、必要时发送 keepalive 和 staged packets。
5. **安全约束**：私钥、预共享密钥均以十六进制明文传输，依赖 UAPI 通道（本地 socket / 命名管道）的安全边界；`IpcGetOperation` 会输出 `private_key` 与 `preshared_key`，调用方需自行保护输出。
6. **最大 peer 数**：由 `device.MaxPeers = 1 << 16` 硬编码限制，UAPI 无法绕过。
7. **日志级别不可变运行时调整**：`LOG_LEVEL` 仅在进程启动时读取一次，运行中修改无效。
8. **Windows 平台限制**：不读取任何环境变量，不接受 `-f`，日志级别固定为 verbose，且明确声明该二进制仅为调试用途，生产应使用 `wireguard-windows`。

## 5. 总结

wireguard-go 的配置系统极其精简：启动阶段用少量环境变量完成 TUN/UAPI 资源注入与运行模式选择，运行时完全依赖标准的 WireGuard UAPI 文本协议进行 peer 与设备配置。这种设计把“如何持久化配置”的责任完全交给外部编排层，而 wireguard-go 只负责“如何应用配置”，符合其作为底层隧道守护进程的定位。