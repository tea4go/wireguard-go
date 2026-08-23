# wireguard-go 无 GUI 平替 WireGuard for Windows 差距分析报告

> 报告日期：2026-08-23
> 分析对象：当前仓库 `tea4go/wireguard-go` 的 `master` 分支，提交 `db6d4bf`
> 对标对象：官方 `WireGuard/wireguard-windows` 当前 `master` 分支
> 报告用途：为后续需求、设计、开发和验收提供输入

## 1. 目标与结论

本报告将目标收敛为一个**无 GUI、通过命令行和 Windows 服务运行的 WireGuard 客户端**，不再要求复制官方客户端的桌面界面和企业管理功能。

当前仓库已经具备 WireGuard 协议数据面、Wintun 收发、管理员命名管道 UAPI 和基本 Windows 入口，但仍缺少安全运行一个 Windows VPN 所必需的配置、服务和网络编排能力。

首版至少需要补齐：

1. `.conf` 配置解析、校验和私钥安全存储。
2. Windows Tunnel Service 和 SCM 生命周期管理。
3. IPv4/IPv6 地址、路由、DNS 和 MTU 配置。
4. 默认路由、Endpoint 出口和流量防泄漏。
5. 网络变化、休眠唤醒、崩溃和系统重启后的恢复。
6. 管理员 CLI、日志、安装、卸载和 Wintun 驱动分发。

**功能平替可以实现，但 `wireguard-go + Wintun` 是用户态数据面，不能预先承诺与官方 `WireGuardNT` 内核驱动具有相同的吞吐、CPU、内存和功耗。** 性能是否满足平替要求，需要通过实测决定。

推荐复用官方 `wireguard-windows` 中与配置、Tunnel Service、Windows 网络编排和防火墙相关的 MIT 许可代码，去掉 UI、Manager Service、自动更新和企业策略，只增加 `wireguard-go` 引擎适配层。

## 2. 首版范围

### 2.1 必须实现

- Windows amd64。
- 管理员命令行。
- 标准 WireGuard `.conf` 文件。
- 多个已安装配置，但同一时间只允许一个活动隧道。
- 每个配置对应一个 Windows Tunnel Service。
- 手动启动、停止、查询状态和卸载。
- 可选的开机自动启动。
- IPv4、IPv6 和双栈。
- 分流和全流量隧道。
- DNS、MTU、路由和 kill-switch。
- DPAPI 私钥保护和严格文件 ACL。
- 本地日志和基本故障定位。
- Wintun 驱动安装、升级和卸载。
- 异常退出后的系统网络恢复。

### 2.2 明确不做

- GUI、系统托盘、桌面通知和图形配置编辑器。
- Manager Service 和每用户 UI 会话。
- 自动更新和更新服务器。
- MSI、GPO 和企业软件分发。
- 受限操作员和复杂角色权限。
- 生命周期脚本：`PreUp`、`PostUp`、`PreDown`、`PostDown`。
- ZIP 批量导入导出。
- 多个隧道同时运行。
- 云端配置下发、账号、SSO 和终端管理。
- arm64、x86 和多语言界面。
- ETW、性能计数器和一键诊断包。
- WireGuardNT 与 wireguard-go 双引擎。

这些能力后续可以单独立项，但不进入首版需求和工作量。

## 3. 当前仓库能力

### 3.1 已具备

| 能力 | 当前状态 | 代码依据 |
|---|---|---|
| WireGuard 协议和 Noise 握手 | 已具备 | `device/` |
| Peer、AllowedIPs、Endpoint、Keepalive | 已具备 | `device/uapi.go` |
| IPv4/IPv6 UDP 传输 | 已具备 | `conn/` |
| Wintun 适配器创建和数据收发 | 已具备 | `tun/tun_windows.go` |
| Windows 管理员 UAPI 命名管道 | 已具备 | `ipc/uapi_windows.go` |
| 单接口前台进程 | 已具备 | `main_windows.go` |
| 握手时间和收发字节状态 | 引擎层已具备 | `device/uapi.go` |
| 基本进程日志 | 已具备 | `device/logger.go` |

### 3.2 缺失

当前 Windows 入口只接收接口名称，创建 Wintun、启动 `device.Device` 并监听 UAPI。它不会读取 `.conf`，也不会配置 Windows 地址、路由、DNS、防火墙或 Windows 服务。

UAPI 只处理 WireGuard 协议字段，不处理 Windows 网络配置。当前缺少：

- `[Interface] Address`
- `[Interface] DNS` 和 DNS 搜索域
- `[Interface] MTU`
- `[Interface] Table`
- 从 Peer `AllowedIPs` 生成 Windows 路由
- `/0` 默认路由和流量防泄漏
- Endpoint 物理出口保护
- 配置持久化和私钥保护
- Windows Service Control Manager 集成

### 3.3 当前性能问题

`tun/tun_windows.go` 仍存在：

- `BatchSize()` 固定返回 `1`，没有 Wintun 批处理。
- 写入 Wintun 时存在一次内存复制。
- MTU 变化没有实时监听。

这些问题不阻塞功能开发，但可能影响最终性能验收。

当前 `go.mod` 使用的 Wintun 版本来自 2023 年。正式发布前必须验证驱动兼容性、签名和升级路径。

## 4. 最小差距矩阵

优先级：

- **P0**：没有该能力就不能安全、稳定地建立隧道。
- **P1**：正式发布和日常维护所需。

| 领域 | 必须补齐的能力 | 当前状态 | 优先级 |
|---|---|---|---|
| 配置 | 解析和校验 `.conf` | 缺失 | P0 |
| 配置 | Address、DNS、MTU、Table | 缺失 | P0 |
| 密钥 | DPAPI 加密、文件 ACL、日志脱敏 | 缺失 | P0 |
| 服务 | 每配置一个 Tunnel Service | 缺失 | P0 |
| 服务 | SCM 状态、停止超时、开机启动和故障恢复 | 缺失 | P0 |
| 生命周期 | 启动、停止、状态、幂等和失败回滚 | 仅有引擎 up/down | P0 |
| 地址 | IPv4/IPv6 地址和接口 Metric | 缺失 | P0 |
| 路由 | AllowedIPs 路由增删、去重和 Table=off | 缺失 | P0 |
| 出口 | Endpoint 走物理网络，避免递归进入隧道 | 未产品化验证 | P0 |
| DNS | DNS 服务器、搜索域、恢复和泄漏检查 | 缺失 | P0 |
| 防火墙 | `/0` kill-switch、DNS 限制和规则清理 | 缺失 | P0 |
| MTU | 显式 MTU 和自动推导 | 只有引擎内固定值 | P0 |
| 网络变化 | 断网重连、默认路由和地址变化 | 缺失 | P0 |
| 电源事件 | 休眠、唤醒、快速启动和关机 | 缺失 | P0 |
| 故障恢复 | 崩溃后清理路由、DNS、防火墙和适配器 | 缺失 | P0 |
| CLI | 安装、启停、状态、日志和卸载 | 缺失 | P0 |
| 单活动隧道 | 阻止第二个隧道同时启动 | 缺失 | P0 |
| 日志 | 文件滚动、错误码和敏感信息过滤 | 只有控制台日志 | P1 |
| 安装 | Wintun 和程序文件的安装、升级、卸载 | 缺失 | P1 |
| 发布 | amd64 包、代码签名和版本信息 | 缺失 | P1 |
| 性能 | Wintun 批处理和减少复制 | 未完成 | P1 |
| 测试 | Windows VM 网络、恢复和泄漏测试 | 缺失 | P1 |

## 5. 必要设计

### 5.1 配置支持范围

首版只支持运行隧道所需字段：

```ini
[Interface]
PrivateKey =
Address =
ListenPort =
DNS =
MTU =
Table =

[Peer]
PublicKey =
PresharedKey =
AllowedIPs =
Endpoint =
PersistentKeepalive =
```

要求：

- 支持多个 Peer。
- 严格校验密钥、CIDR、端口、Endpoint 和重复字段。
- `Table=off` 时不自动添加 AllowedIPs 路由。
- 不执行任何生命周期脚本。
- 安装配置时将私钥转为 DPAPI 加密存储。
- `status` 和日志不得输出私钥或预共享密钥。

### 5.2 Windows 服务模型

不需要 Manager Service。每个已安装配置对应一个 Tunnel Service：

```text
Administrator CLI
        |
Windows SCM
        |
Tunnel Service
        |
Network Orchestrator
        |
wireguard-go + Wintun
```

建议命令：

```text
wireguard-go.exe install <config.conf> [--autostart]
wireguard-go.exe uninstall <tunnel-name>
wireguard-go.exe start <tunnel-name>
wireguard-go.exe stop <tunnel-name>
wireguard-go.exe status <tunnel-name>
wireguard-go.exe log <tunnel-name>
wireguard-go.exe list
```

内部服务入口可以使用隐藏参数，例如：

```text
wireguard-go.exe service <tunnel-name>
```

服务必须：

- 正确上报 StartPending、Running、StopPending 和 Stopped。
- 支持 SCM 停止、系统关机和服务启动超时。
- 使用全局互斥量保证只有一个活动隧道。
- 启动失败时回滚已完成的网络配置。
- 异常启动时先清理该隧道遗留资源。
- 使用最小必要权限和严格服务 ACL。

### 5.3 网络配置事务

启动隧道必须作为可回滚事务：

1. 读取并解密配置。
2. 校验配置和当前活动隧道。
3. 解析 Endpoint 并确定物理出口。
4. 创建 Wintun 适配器。
5. 启动 `wireguard-go` 数据面。
6. 设置地址、MTU 和接口 Metric。
7. 设置 AllowedIPs 路由。
8. 设置 DNS。
9. 安装必要的 WFP 防火墙规则。
10. 向 SCM 上报 Running。

任何一步失败，都必须按相反顺序回滚。停止、崩溃恢复和卸载应复用同一套幂等清理逻辑。

正式实现应优先使用 Windows IP Helper、DNS、WFP 和 SCM API，不应依赖解析 `netsh` 或 PowerShell 输出。

### 5.4 全流量和防泄漏

包含 `0.0.0.0/0` 或 `::/0` 时必须：

- 保证 WireGuard Endpoint 的 UDP 流量走物理出口。
- 阻止非隧道接口上的普通 IPv4/IPv6 流量。
- DNS 只允许访问配置中的 DNS 服务器。
- 正确放行 DHCP、NDP 和回环等必要流量。
- 隧道启动失败、进程崩溃或停止时清理规则。

验收必须进行真实抓包和断网测试，不能只检查路由表。

### 5.5 CLI 与 UAPI

不增加 Manager IPC。CLI 使用：

- SCM 控制服务启停。
- 受保护的配置目录管理已安装配置。
- 当前管理员 UAPI 查询 Peer、握手和收发字节。

UAPI 必须继续限制为 Local System 和管理员访问。CLI 查询失败时应返回稳定的退出码和可操作错误信息。

### 5.6 引擎边界

Windows 服务和网络层不应直接依赖 `device.Device` 内部结构，建议增加最小适配接口：

```go
type TunnelEngine interface {
    Start(ctx context.Context, cfg DeviceConfig) error
    Snapshot(ctx context.Context) (RuntimeSnapshot, error)
    Stop(ctx context.Context) error
    Wait() error
}
```

`wireguard-go` 适配器负责：

- 创建和持有 Wintun。
- 把配置转换为 UAPI 配置。
- 启停 `device.Device`。
- 返回 Peer 运行状态。
- 上报不可恢复错误。

Windows 层负责：

- 配置、DPAPI 和 ACL。
- SCM、地址、路由、DNS、MTU 和 WFP。
- CLI、日志、安装和卸载。

这样可以减少对协议核心的修改，降低以后同步上游的成本。

## 6. 可直接转需求的清单

### 6.1 P0 功能

- `REQ-CONF-001`：解析首版支持的 `.conf` 字段。
- `REQ-CONF-002`：拒绝无效名称、密钥、CIDR、端口和 Endpoint。
- `REQ-STORE-001`：使用 DPAPI 保存私钥和预共享密钥。
- `REQ-STORE-002`：配置目录只允许 Local System 和管理员访问。
- `REQ-SVC-001`：安装、启动、停止和卸载 Tunnel Service。
- `REQ-SVC-002`：支持手动启动和可选开机自动启动。
- `REQ-SVC-003`：同一时间只允许一个活动隧道。
- `REQ-SVC-004`：服务失败时回滚所有系统网络改动。
- `REQ-NET-001`：配置 IPv4/IPv6 地址、MTU 和接口 Metric。
- `REQ-NET-002`：根据 AllowedIPs 添加、去重和删除路由。
- `REQ-NET-003`：支持 `Table=off`。
- `REQ-NET-004`：保证 Endpoint 不递归进入隧道。
- `REQ-DNS-001`：配置和恢复 DNS 服务器及搜索域。
- `REQ-FW-001`：为 `/0` 实现 kill-switch 和 DNS 防泄漏。
- `REQ-LIFE-001`：处理断网、默认路由变化、休眠和唤醒。
- `REQ-CLI-001`：提供 install、uninstall、start、stop、status、log 和 list。
- `REQ-CLI-002`：所有命令提供稳定退出码。
- `REQ-LOG-001`：日志不得输出私钥和预共享密钥。

### 6.2 P1 发布和质量

- `REQ-INSTALL-001`：安装和升级 Wintun 驱动。
- `REQ-UNINSTALL-001`：卸载后不残留服务、适配器、路由、DNS 和 WFP 规则。
- `REQ-SIGN-001`：正式发布的程序和驱动包必须通过签名校验。
- `REQ-LOG-002`：日志按大小滚动并限制磁盘占用。
- `REQ-PERF-001`：实现 Wintun 批处理或证明当前性能达到指标。
- `REQ-TEST-001`：建立 Windows amd64 VM 自动化测试。
- `REQ-TEST-002`：建立崩溃恢复和流量泄漏测试。

## 7. 分阶段交付

### 阶段 0：技术验证

交付：

- 命令行前台运行单隧道。
- Address、Route、DNS、MTU 配置和回滚。
- Endpoint 物理出口保护。
- `/0` kill-switch 原型。
- 与官方客户端的初步性能对比。

退出条件：

- IPv4、IPv6、分流和全流量配置均可通信。
- 正常停止和强制终止后无网络配置残留。
- Wi-Fi 与有线切换后可恢复。
- 获得吞吐、CPU 和内存基线。

### 阶段 1：服务化

交付：

- `.conf` 解析和 DPAPI 存储。
- 每配置一个 Tunnel Service。
- CLI、单活动隧道约束和日志。
- 开机自动启动。
- 网络、电源和异常恢复。

退出条件：

- 1000 次启停循环后无资源残留。
- 随机终止服务后系统网络可恢复。
- 重启系统后自动启动行为正确。
- 未授权用户无法读取密钥或控制服务。

### 阶段 2：安装和发布

交付：

- amd64 安装包或安装命令。
- Wintun 驱动安装、升级和卸载。
- 程序签名、版本信息和完整卸载。
- Windows VM 自动化测试。

退出条件：

- 全新安装、覆盖升级和卸载均通过。
- 安装失败后系统可恢复。
- 卸载后不存在产品创建的系统资源。

### 阶段 3：正式平替验收

交付：

- 功能、性能、安全、稳定性和兼容性报告。
- 已知差异和迁移文档。
- 正式支持矩阵。

只有通过该阶段，才适合声明无 GUI 版本可以替代 WireGuard for Windows 的隧道运行能力。

## 8. 验收指标

### 8.1 功能

- 支持 IPv4、IPv6、双栈、分流、全流量和多个 Peer。
- 官方客户端可运行且仅使用首版字段的配置，本产品应具有相同隧道语义。
- `install` 后不再依赖原始明文配置文件。
- 停止或失败后地址、路由、DNS、防火墙和适配器恢复。
- 第二个隧道启动时返回明确冲突错误。

### 8.2 性能

与官方客户端对比：

- TCP 单流和多流吞吐。
- UDP 吞吐、抖动和丢包。
- IPv4、IPv6、小包和大包。
- CPU、工作集和 Go GC。
- 空闲和持续传输时的资源占用。

性能门槛应在阶段 0 获得数据后确定，不能提前假设用户态实现等同于内核驱动。

### 8.3 稳定性

- 1000 次启停循环。
- 服务随机终止。
- 24/72 小时持续传输。
- 休眠和唤醒循环。
- Wi-Fi、有线和热点切换。
- DHCP 地址、默认路由和 DNS 变化。

### 8.4 安全

- 磁盘、日志和崩溃转储中不出现明文私钥。
- 非管理员无法读取配置、访问 UAPI 或控制服务。
- `/0` 模式在启动、运行、失败和停止过程中无流量泄漏。
- 程序、安装包和驱动通过签名校验。
- 服务只保留必要权限。

### 8.5 兼容性

首版建议支持：

- Windows 10 22H2 amd64。
- Windows 11 受支持版本 amd64。
- Windows Server 2019、2022 和 2025 amd64。

## 9. 主要风险

### 9.1 用户态数据面

Wintun 和 Go 数据面会增加用户态与内核态之间的数据搬运。性能、上下文切换和功耗不会天然等同于 WireGuardNT。

缓解：

- 阶段 0 建立官方基线。
- 优先验证 Wintun 批处理。
- 根据实测决定是否继续投入性能优化。

### 9.2 Windows 网络恢复

地址、路由、DNS、防火墙和适配器跨多个 Windows 子系统。只依赖进程退出时的 `defer` 不能保证恢复。

缓解：

- 所有操作必须幂等并支持反向回滚。
- 服务启动时执行该隧道的遗留资源清理。
- 对每个启动步骤执行故障注入测试。

### 9.3 Wintun 驱动

项目仍依赖 Windows 驱动，正式发布涉及驱动兼容性、签名、升级和卸载。

缓解：

- 阶段 0 确定 Wintun 版本和分发方式。
- 测试无驱动、旧驱动、损坏驱动和升级失败。

### 9.4 高权限服务

服务需要修改系统网络状态和创建适配器，属于高权限组件。

缓解：

- 不支持生命周期脚本。
- CLI 和 UAPI 只允许管理员访问。
- 使用最小服务权限和严格 ACL。
- 对配置长度、字段数量和日志内容设置限制。

### 9.5 上游同步

当前仓库是非官方分支，Windows 产品层还可能复用官方 `wireguard-windows`。后续需要跟踪两个上游。

缓解：

- 通过适配层复用代码，不修改协议核心。
- 单独维护上游同步和安全公告流程。

### 9.6 当前测试问题

当前 Windows 全量 `go test ./...` 在 Go 1.26.1 下不能完全通过：`tun/checksum_test.go` 使用的 `unix.IPPROTO_TCP` 在 Windows 构建下未定义。根目录格式测试还会扫描放在仓库内的 Go 临时目录。`go build ./...` 可以完成，数据面、连接和 IPC 等主要包的测试可以运行。

产品开发前应建立明确的 Windows CI、构建标签和受控 Go 版本矩阵。

## 10. 粗略工作量

以下仅用于立项量级判断。

假设：

- 复用官方配置、Tunnel Service 和 Windows 网络编排代码。
- 首版只支持 amd64。
- 无 GUI、Manager Service、自动更新、企业策略和生命周期脚本。
- 团队熟悉 Go、Windows Service、IP Helper 和 WFP。

| 范围 | 人月 |
|---|---:|
| 阶段 0 技术验证 | 2-4 |
| 阶段 1 服务、网络和安全 | 3-5 |
| 阶段 2 安装和发布 | 1-2 |
| 阶段 3 测试和性能收敛 | 2-4 |
| 合计 | 8-15 |

如果从当前仓库完全重写配置、网络和服务层，而不复用官方代码，工作量会明显增加。

## 11. 下一步

进入正式需求前，只需要确认两个决策：

1. 是否允许复用官方 `wireguard-windows` 的 MIT 许可代码。
2. 首版是否接受“可安装多个配置，但同一时间只运行一个隧道”。

随后开展阶段 0，优先验证：

1. Windows Service 中稳定运行 `wireguard-go + Wintun`。
2. Address、Route、DNS 和 MTU 的事务化配置与恢复。
3. 全流量模式下 Endpoint 出口和 kill-switch 无泄漏。
4. 网络切换、休眠唤醒和进程崩溃后的恢复。
5. 与 WireGuardNT 的吞吐、CPU 和内存差距。

阶段 0 的实测结果应作为需求细化、架构设计和排期依据。

## 12. 官方参考资料

- [WireGuard for Windows 源码仓库](https://github.com/WireGuard/wireguard-windows)
- [企业部署和 Tunnel Service 命令](https://github.com/WireGuard/wireguard-windows/blob/master/docs/enterprise.md)
- [Windows 网络配置行为](https://github.com/WireGuard/wireguard-windows/blob/master/docs/netquirk.md)
- [攻击面说明](https://github.com/WireGuard/wireguard-windows/blob/master/docs/attacksurface.md)
- [配置解析实现](https://github.com/WireGuard/wireguard-windows/blob/master/conf/parser.go)
- [Windows 地址、DNS 和防火墙实现](https://github.com/WireGuard/wireguard-windows/blob/master/tunnel/addressconfig.go)
- [官方 wireguard-go Windows TUN 实现](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_windows.go)
