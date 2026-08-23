# wireguard-go 无 GUI 平替 WireGuard for macOS 差距分析报告

> 报告日期：2026-08-23
> 分析对象：当前仓库 `tea4go/wireguard-go` 的 `master` 分支，提交 `db6d4bf`
> 对标对象：官方 `wireguard-apple`、`wireguard-tools` 的 macOS 实现
> 报告用途：为后续需求、设计、开发和验收提供输入

## 1. 目标与结论

本报告目标是实现一个**无 GUI、通过命令行和 launchd 运行的 macOS WireGuard 客户端**。

当前仓库已经具备 WireGuard 协议、macOS `utun`、UAPI、接口状态和 MTU 监听，但没有 `.conf` 编排、launchd 服务、地址、路由、DNS、防泄漏和故障恢复。

首版至少需要补齐：

1. `.conf` 解析和 root 专用配置存储。
2. launchd LaunchDaemon 生命周期。
3. IPv4/IPv6 地址、路由、DNS 和 MTU。
4. 全流量模式的 Endpoint 直连路由和 PF 防泄漏。
5. 网络切换、休眠唤醒和异常退出后的恢复。
6. 管理员 CLI、日志、安装、卸载、签名和公证。

官方 macOS App 使用 Network Extension 和 WireGuardKit，WireGuardKit 仍链接 wireguard-go bridge。无 GUI 版本可以继续使用当前仓库的原生 `utun` 路径，不必引入 App、Network Extension 和 App Store 能力，但需要自行承担系统网络编排和恢复。

推荐复用官方 `wireguard-tools/src/wg-quick/darwin.bash` 的配置、路由、DNS、Endpoint 路由和网络变化逻辑，增加受控 launchd 包装、PF anchor 和异常清理。若产品不能接受 GPLv2 脚本，应依据其行为重新实现最小 Go 编排层。

## 2. 首版范围

### 2.1 必须实现

- Apple Silicon arm64。
- root 管理员 CLI。
- 标准 WireGuard `.conf`。
- 可安装多个配置，但同一时间只保证一个活动隧道。
- 每个配置对应一个 launchd LaunchDaemon。
- 手动启停、状态查询、卸载和可选开机启动。
- IPv4、IPv6、双栈、分流和全流量。
- DNS、搜索域、MTU、路由和 PF kill-switch。
- 配置文件属主为 root，权限不高于 `0600`。
- 本地日志和异常恢复。
- 签名并公证的 arm64 安装包。

### 2.2 明确不做

- GUI、菜单栏、桌面通知和图形配置编辑器。
- Network Extension、System Extension 和 App Store 发布。
- 自动更新。
- 生命周期脚本和 `SaveConfig`。
- ZIP 批量导入导出。
- 多活动隧道冲突编排。
- Keychain 配置同步。
- MDM、配置描述文件、账号、SSO 和云端控制。
- Intel x86_64 和 Universal Binary。
- 多语言界面。
- 高级诊断包和遥测。

## 3. 当前仓库能力

### 3.1 已具备

| 能力 | 当前状态 | 代码依据 |
|---|---|---|
| WireGuard 协议和 Peer 管理 | 已具备 | `device/` |
| IPv4/IPv6 UDP 传输 | 已具备 | `conn/` |
| macOS utun 创建和收发 | 已具备 | `tun/tun_darwin.go` |
| 自动分配 `utunN` | 已具备 | `tun/tun_darwin.go` |
| 实际 utun 名称输出 | 已具备 | `WG_TUN_NAME_FILE` |
| 接口 up/down 和 MTU 事件 | 已具备 | Darwin route socket |
| Unix UAPI socket | 已具备 | `ipc/uapi_bsd.go` |
| 前台和后台进程模式 | 已具备 | `main.go` |
| 握手和流量状态 | 已具备 | `device/uapi.go` |

### 3.2 缺失

当前入口只创建 utun 和 UAPI，不处理：

- `[Interface] Address`
- `[Interface] DNS`
- `[Interface] MTU`
- `[Interface] Table`
- AllowedIPs 路由
- 全流量拆分默认路由
- Endpoint 物理出口路由
- PF 防泄漏
- launchd 服务
- 配置持久化和权限
- 网络变化后的 DNS、MTU 和 Endpoint 路由恢复

### 3.3 平台限制

- macOS 不支持 Linux 风格的 fwmark。
- 当前实现不支持 sticky socket。
- utun 名称由系统分配，配置名与实际接口名不同。
- TUN 和 UDP 收发批大小为 `1`。
- 当前仓库只监听接口路由事件，不负责系统默认出口和 DNS 变化。

## 4. 最小差距矩阵

| 领域 | 必须补齐的能力 | 当前状态 | 优先级 |
|---|---|---|---|
| 配置 | 解析和校验首版 `.conf` 字段 | 缺失 | P0 |
| 配置安全 | root:wheel、`0600`、日志脱敏 | 缺失 | P0 |
| 服务 | 每配置一个 LaunchDaemon | 缺失 | P0 |
| 服务 | 启停、开机启动、退出码和重启策略 | 缺失 | P0 |
| 接口映射 | 配置名到动态 `utunN` 的可靠映射 | 只有名称文件机制 | P0 |
| 地址 | IPv4/IPv6 地址配置和清理 | 缺失 | P0 |
| 路由 | AllowedIPs 路由和 `Table=off` | 缺失 | P0 |
| 全流量 | IPv4/IPv6 两个 `/1` 路由 | 缺失 | P0 |
| Endpoint | 物理网关直连路由和网关变化更新 | 缺失 | P0 |
| DNS | DNS、搜索域、快照和恢复 | 缺失 | P0 |
| MTU | 显式 MTU 和基于默认出口的推导 | 引擎只支持接口 MTU | P0 |
| 防泄漏 | PF anchor 和 DNS 限制 | 缺失 | P0 |
| 网络变化 | 默认路由、服务、DNS 和 MTU变化 | 部分接口事件 | P0 |
| 电源事件 | 休眠、唤醒和快速用户切换 | 缺失 | P0 |
| 故障恢复 | 崩溃后的路由、DNS、PF 和名称文件清理 | 缺失 | P0 |
| CLI | install、start、stop、status、log、uninstall | 缺失 | P0 |
| 发布 | arm64 包、签名和公证 | 缺失 | P1 |
| 测试 | 真机网络、休眠和泄漏测试 | 缺失 | P1 |
| 性能 | 批处理和资源占用验证 | 未完成 | P1 |

## 5. 必要设计

### 5.1 配置支持范围

首版支持：

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
- `Table` 只允许 `auto`、`main` 和 `off`。
- 拒绝生命周期脚本和 `SaveConfig`。
- 配置安装到 `/Library/Application Support/wireguard-go/`。
- 目录为 `0700`，配置为 root:wheel 和 `0600`。
- 日志和 `status` 不得输出私钥或预共享密钥。

### 5.2 launchd 服务模型

```text
Administrator CLI
        |
launchctl
        |
LaunchDaemon per tunnel
        |
wireguard-go-macos service <tunnel-name>
        |
Network Orchestrator + in-process wireguard-go engine
```

建议命令：

```text
wireguard-go-macos install <config.conf> [--autostart]
wireguard-go-macos uninstall <tunnel-name>
wireguard-go-macos start <tunnel-name>
wireguard-go-macos stop <tunnel-name>
wireguard-go-macos status <tunnel-name>
wireguard-go-macos log <tunnel-name>
wireguard-go-macos list
```

LaunchDaemon 必须：

- 启动前台 `service` 模式，由 launchd 直接跟踪唯一服务进程。
- 服务进程在内部创建并持有 wireguard-go 引擎，避免孤儿子进程。
- 设置 `WG_TUN_NAME_FILE` 保存逻辑名称与实际 utun 名称映射。
- 使用全局锁阻止第二个隧道进入网络配置阶段。
- 启动失败时回滚全部已完成操作。
- 异常启动时先清理该隧道遗留状态。
- stdout/stderr 写入受限日志文件。

### 5.3 网络配置事务

启动顺序：

1. 读取并校验 root 配置。
2. 检查活动隧道锁。
3. 解析 Endpoint 和当前物理网关。
4. 在服务进程内创建 wireguard-go 引擎和 utun，并记录实际接口名。
5. 设置 WireGuard 参数并启动数据面。
6. 设置 IPv4/IPv6 地址和 MTU。
7. 添加 AllowedIPs 路由。
8. 为全流量模式添加两个 `/1` 路由。
9. 为 Endpoint 添加物理网关直连路由。
10. 快照并设置 DNS。
11. 安装 PF anchor。
12. 标记服务运行。

停止或失败必须按相反顺序清理。所有清理操作必须幂等。

### 5.4 路由和网络变化

由于没有 fwmark，全流量模式应采用：

- IPv4：`0.0.0.0/1` 和 `128.0.0.0/1`
- IPv6：`::/1` 和 `8000::/1`

Endpoint 必须保持一条经过当前物理网关的更具体路由。默认网关、Endpoint 地址或网络接口变化时，应重新计算该路由。

可复用官方 Darwin `wg-quick` 的 route monitor 行为，但需要补齐其已注明的 Endpoint 动态变化问题。

### 5.5 DNS

最小实现可以复用 `networksetup`：

- 启动前记录所有当前活动网络服务的 DNS 和搜索域。
- 设置隧道 DNS。
- 网络服务变化后重新应用。
- 停止时只恢复本产品修改过的值。

必须处理用户在隧道运行期间手动修改 DNS 的冲突，避免无条件覆盖新的用户配置。

### 5.6 PF 防泄漏

官方 Darwin `wg-quick` 负责默认路由，但不提供完整 kill-switch。全流量模式需要独立 PF anchor：

- 允许 utun 流量。
- 允许 WireGuard Endpoint UDP 走物理接口。
- 允许 DHCP、NDP、回环和必要系统流量。
- DNS 只允许配置中的服务器。
- 阻止其他物理接口明文流量。
- 只管理产品自己的 anchor，不覆盖系统或用户 PF 规则。

### 5.7 网络和电源恢复

服务需要监听：

- route socket 或 SystemConfiguration 网络变化。
- 默认网关变化。
- DNS 服务变化。
- 休眠和唤醒。

唤醒后至少执行：

1. 确认 utun 和 UAPI 存活。
2. 重新解析 Endpoint。
3. 更新 Endpoint 直连路由。
4. 重新计算 MTU。
5. 校验 DNS 和 PF anchor。
6. 触发 WireGuard socket 重新绑定。

## 6. 可直接转需求的清单

### 6.1 P0 功能

- `REQ-MAC-CONF-001`：解析首版 `.conf` 字段并拒绝脚本。
- `REQ-MAC-STORE-001`：配置目录 `0700`，配置文件 root:wheel 和 `0600`。
- `REQ-MAC-SVC-001`：安装、启停和卸载每隧道 LaunchDaemon。
- `REQ-MAC-SVC-002`：支持手动启动和可选开机启动。
- `REQ-MAC-SVC-003`：同一时间只保证一个活动隧道。
- `REQ-MAC-TUN-001`：可靠保存逻辑名称到 `utunN` 的映射。
- `REQ-MAC-NET-001`：配置 IPv4/IPv6 地址和 MTU。
- `REQ-MAC-NET-002`：根据 AllowedIPs 管理路由。
- `REQ-MAC-NET-003`：支持 `Table=off`。
- `REQ-MAC-NET-004`：全流量使用 IPv4/IPv6 拆分默认路由。
- `REQ-MAC-NET-005`：维护 Endpoint 物理网关路由。
- `REQ-MAC-DNS-001`：快照、设置和恢复 DNS 及搜索域。
- `REQ-MAC-FW-001`：使用独立 PF anchor 实现 kill-switch。
- `REQ-MAC-LIFE-001`：处理网络变化、休眠和唤醒。
- `REQ-MAC-RECOVER-001`：异常后清理路由、DNS、PF 和名称文件。
- `REQ-MAC-CLI-001`：提供 install、uninstall、start、stop、status、log 和 list。
- `REQ-MAC-LOG-001`：日志不得输出私钥和预共享密钥。

### 6.2 P1 发布和质量

- `REQ-MAC-PKG-001`：提供 arm64 安装包和完整卸载。
- `REQ-MAC-SIGN-001`：使用 Developer ID 签名并完成 Apple 公证。
- `REQ-MAC-TEST-001`：建立 Apple Silicon 真机自动化测试。
- `REQ-MAC-TEST-002`：建立休眠、网络切换和流量泄漏测试。
- `REQ-MAC-PERF-001`：与官方 App 对比吞吐、CPU、内存和功耗。

## 7. 分阶段交付

### 阶段 0：技术验证

- 通过官方 `wg-quick` Darwin 逻辑启动当前 `wireguard-go`。
- 验证 Address、Route、DNS、MTU 和 Endpoint 路由。
- 验证全流量 IPv4/IPv6。
- 建立官方 App 性能基线。

退出条件：

- 分流和全流量均可通信。
- 停止后路由和 DNS 可恢复。
- 网络切换后 Endpoint 仍可握手。

### 阶段 1：服务化和防泄漏

- launchd LaunchDaemon。
- root 配置存储和 CLI。
- PF anchor。
- 网络、电源和异常恢复。

退出条件：

- 1000 次启停无资源残留。
- 强制终止后可自动清理。
- 休眠和唤醒后隧道恢复。
- 全流量模式无明文泄漏。

### 阶段 2：安装和发布

- arm64 安装包。
- 签名、公证、升级和卸载。
- 真机测试矩阵。

退出条件：

- 全新安装、覆盖安装和卸载通过。
- Gatekeeper 校验通过。
- 卸载后不残留 LaunchDaemon、路由、DNS 或 PF anchor。

### 阶段 3：正式验收

- 功能、性能、安全、稳定性和兼容性报告。
- 已知差异和迁移文档。

## 8. 验收指标

### 8.1 功能

- 支持 IPv4、IPv6、双栈、分流、全流量和多个 Peer。
- 仅使用首版字段的标准配置具有与官方 App 相同的隧道语义。
- 停止或失败后恢复地址、路由、DNS、PF 和 utun 资源。

### 8.2 稳定性

- 1000 次启停。
- 强制终止 launchd 服务。
- 24/72 小时持续传输。
- 休眠和唤醒循环。
- Wi-Fi、有线、热点和多网络服务切换。

### 8.3 安全

- 配置和日志不向普通用户暴露密钥。
- 非管理员不能控制服务。
- PF 规则不覆盖用户现有规则。
- 全流量启动、运行、失败和停止阶段无明文泄漏。
- 安装包通过签名和公证。

### 8.4 性能

与官方 WireGuard App 对比：

- TCP、UDP、IPv4、IPv6。
- 小包和大包。
- CPU、内存和空闲功耗。
- Wi-Fi 和有线网络。

## 9. 主要风险

### 9.1 Network Extension 差异

官方 App 使用系统 Network Extension 管理网络设置，headless 版本直接操作 utun、route、networksetup 和 PF。数据面相近，但生命周期、权限和系统集成不同。

### 9.2 DNS 恢复

`networksetup` 修改的是网络服务配置。用户或系统在隧道运行期间修改 DNS 时，简单恢复旧快照可能覆盖新配置。

### 9.3 PF 共存

错误修改主 PF 配置可能破坏系统或第三方安全软件。必须使用独立 anchor 并验证已有 PF 规则共存。

### 9.4 Endpoint 变化

官方 Darwin `wg-quick` 已注明 Endpoint 动态变化时直连路由更新不完整。产品实现必须跟踪 Endpoint 重新解析和 roaming。

### 9.5 GPLv2

官方 `wg-quick` 属于 `wireguard-tools`，采用 GPLv2。直接分发修改脚本需要遵守 GPLv2。若要求整个新增产品层维持 MIT，应重新实现必要行为。

## 10. 粗略工作量

假设：

- 复用官方 Darwin `wg-quick` 行为。
- 只支持 Apple Silicon arm64。
- 无 GUI、Network Extension、自动更新、MDM 和脚本。

| 范围 | 人月 |
|---|---:|
| 阶段 0 技术验证 | 1-2 |
| launchd、网络和恢复 | 2-4 |
| PF、防泄漏和安全 | 1-2 |
| 安装、测试和性能收敛 | 2-4 |
| 合计 | 6-12 |

如果不复用官方 `wg-quick`，需要额外实现和验证 macOS 网络编排，工作量会增加。

## 11. 下一步

优先验证：

1. launchd 中稳定运行前台 `service` 模式并在进程内持有 wireguard-go 引擎。
2. 配置名与动态 `utunN` 的可靠映射。
3. Endpoint 物理出口在网络切换后持续正确。
4. PF kill-switch 与系统现有 PF 规则共存。
5. 休眠唤醒后的路由、DNS 和 socket 恢复。
6. 与官方 App 的性能差距。

## 12. 官方参考资料

- [WireGuard for Apple 源码](https://github.com/WireGuard/wireguard-apple)
- [WireGuardKit 包定义](https://github.com/WireGuard/wireguard-apple/blob/master/Package.swift)
- [WireGuardAdapter 实现](https://github.com/WireGuard/wireguard-apple/blob/master/Sources/WireGuardKit/WireGuardAdapter.swift)
- [PacketTunnelProvider 实现](https://github.com/WireGuard/wireguard-apple/blob/master/Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift)
- [官方 Darwin wg-quick](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/darwin.bash)
- [官方 wireguard-go README](https://github.com/WireGuard/wireguard-go/blob/master/README.md)
- [官方 Darwin TUN 实现](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_darwin.go)
