# wireguard-go 无 GUI 平替 Linux WireGuard 差距分析报告

> 报告日期：2026-08-23
> 分析对象：当前仓库 `tea4go/wireguard-go` 的 `master` 分支，提交 `db6d4bf`
> 对标对象：Linux 内核 WireGuard、官方 `wireguard-tools` 和 `wg-quick@.service`
> 报告用途：为后续需求、设计、开发和验收提供输入

## 1. 目标与结论

本报告目标是实现一个**无 GUI、通过命令行和 systemd 运行的 Linux 用户态 WireGuard 客户端**。

当前仓库在 Linux 上已经具备完整协议数据面、TUN、Netlink、UAPI、fwmark、sticky socket、批处理和 GRO/GSO。主要缺口不在协议，而在 `.conf` 编排、systemd 监督、DNS、策略路由、防火墙、失败清理和安装发布。

现代 Linux 内核已经原生支持 WireGuard，官方也明确建议优先使用内核实现。`wireguard-go` 平替只适合以下目标：

- 内核没有 WireGuard。
- 无法加载或升级内核模块。
- 产品明确要求统一使用 Go 数据面。
- 特定测试、兼容或隔离环境。

如果系统已有可用内核 WireGuard，用户态实现通常不是性能和运维上的更优选择。

推荐复用官方 Linux `wg-quick` 的地址、MTU、DNS、策略路由和 nftables 逻辑，但必须修改接口创建流程，强制启动 `wireguard-go`。正式服务不能让 `wireguard-go`自行脱离 systemd，需要使用前台模式并由 systemd 直接监督。

## 2. 首版范围

### 2.1 必须实现

- Ubuntu 24.04 LTS amd64。
- systemd。
- root 管理员 CLI。
- 标准 WireGuard `.conf`。
- 首版只保证单活动隧道。
- 手动启停、状态查询和可选开机启动。
- IPv4、IPv6、双栈、分流和全流量。
- DNS、MTU、路由、fwmark、策略路由和 kill-switch。
- 配置文件 root:root 和 `0600`。
- journald 日志。
- `.deb` 或等价安装包和完整卸载。
- 异常退出后的网络清理。

### 2.2 明确不做

- GUI 和桌面网络管理器插件。
- NetworkManager、systemd-networkd 和 netplan 集成。
- 非 systemd 发行版。
- 容器、网络命名空间和 Kubernetes CNI。
- 多活动隧道冲突编排。
- 生命周期脚本和 `SaveConfig`。
- 自动更新。
- SELinux 和 AppArmor 专用策略。
- arm64、其他发行版和源码包矩阵。
- 云端控制、账号、SSO 和集中管理。
- 遥测和高级诊断平台。

## 3. 当前仓库能力

### 3.1 已具备

| 能力 | 当前状态 | 代码依据 |
|---|---|---|
| WireGuard 协议和 Peer 管理 | 已具备 | `device/` |
| `/dev/net/tun` 创建和收发 | 已具备 | `tun/tun_linux.go` |
| Netlink 接口事件 | 已具备 | `tun/tun_linux.go` |
| TUN TCP/UDP offload | 已具备 | `tun/tun_linux.go` |
| UDP 批处理、GSO/GRO | 已具备 | `conn/`、`tun/offload_linux.go` |
| SO_MARK/fwmark | 已具备 | `conn/mark_unix.go` |
| sticky socket | 已具备 | `device/sticky_linux.go` |
| Unix UAPI socket | 已具备 | `ipc/uapi_linux.go` |
| 前台和后台模式 | 已具备 | `main.go` |
| `wg` UAPI 兼容 | 已具备 | `device/uapi.go` |

### 3.2 缺失

当前入口不会处理：

- Address、DNS、MTU 和 Table。
- AllowedIPs 路由。
- `/0` fwmark 和策略路由。
- nftables/iptables 防泄漏。
- systemd 生命周期和失败清理。
- 配置文件安装和权限。
- DNS 恢复。
- 软件包安装和卸载。

### 3.3 与内核实现的差异

- 数据包需要经过 TUN 和 Go 用户态进程。
- CPU、内存、上下文切换和功耗通常高于内核实现。
- 进程崩溃会导致数据面消失，但路由和防火墙可能仍然存在。
- 当前 Linux 入口会提示应优先使用内核 WireGuard。
- Linux 数据面已有批处理和 offload，性能基础好于当前 Windows 和 macOS TUN 路径。

## 4. 官方 wg-quick 可复用能力

官方 Linux `wg-quick` 已实现：

- Address、DNS、MTU、Table 解析。
- 尝试创建内核 WireGuard，失败时回退到 `wireguard-go`。
- AllowedIPs 路由。
- `/0` 使用 fwmark、独立路由表和 `ip rule`。
- nftables 或 iptables 防泄漏规则。
- resolvconf DNS 设置和恢复。
- systemd `wg-quick@.service`。

但原样使用存在两个问题：

1. 现代 Linux 会成功创建内核 WireGuard，不会进入 userspace 回退，因此不能保证使用 `wireguard-go`。
2. 官方 systemd unit 是 oneshot，`wireguard-go` 默认后台运行后不再由该 unit 直接监督。进程异常退出时，路由、DNS和防火墙可能保持在“服务仍 active”的状态。

因此需要一个强制用户态并由 systemd 直接监督的包装层。

## 5. 最小差距矩阵

| 领域 | 必须补齐的能力 | 当前状态 | 优先级 |
|---|---|---|---|
| 配置 | 解析和校验首版 `.conf` 字段 | 缺失 | P0 |
| 配置安全 | root:root、`0600`、日志脱敏 | 缺失 | P0 |
| 用户态强制 | 内核模块存在时仍启动 wireguard-go | 缺失 | P0 |
| systemd | 前台监督、状态和开机启动 | 缺失 | P0 |
| 生命周期 | 启动、停止、失败回滚和幂等清理 | 缺失 | P0 |
| 地址 | IPv4/IPv6 地址和接口状态 | 缺失 | P0 |
| 路由 | AllowedIPs、Table 和去重 | 缺失 | P0 |
| 全流量 | fwmark、独立路由表和 `ip rule` | 引擎支持 mark，缺编排 | P0 |
| DNS | resolvconf 设置和恢复 | 缺失 | P0 |
| 防火墙 | nftables kill-switch 和清理 | 缺失 | P0 |
| MTU | 显式 MTU 和自动推导 | 引擎只设置接口值 | P0 |
| 故障恢复 | 进程退出后的路由、DNS和规则清理 | 缺失 | P0 |
| CLI | up、down、status、log、enable、disable | 缺失 | P0 |
| 日志 | journald、稳定错误码和密钥脱敏 | 只有进程日志 | P0 |
| 安装 | 二进制、unit、脚本和依赖安装 | 缺失 | P1 |
| 发布 | amd64 包、校验和版本信息 | 缺失 | P1 |
| 测试 | VM、内核冲突、泄漏和恢复测试 | 缺失 | P1 |
| 性能 | 与内核 WireGuard 对比 | 未验证 | P1 |

## 6. 必要设计

### 6.1 配置支持范围

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
- 拒绝 PreUp、PostUp、PreDown、PostDown 和 SaveConfig。
- 支持 `Table=auto`、明确表号、`main` 和 `off`。
- 配置安装到 `/etc/wireguard-go/`。
- 目录 `0700`，配置 root:root 和 `0600`。
- 日志和状态输出不得包含私钥或预共享密钥。

### 6.2 systemd 服务模型

推荐：

```text
systemctl / wg-go-quick CLI
        |
wg-go-quick@.service
        |
wg-go-service run <interface>
        |
wireguard-go -f <interface>
        |
/dev/net/tun
```

`wg-go-service` 包装层负责：

- 强制调用 `wireguard-go -f`，不尝试内核接口。
- 等待 UAPI 可用后应用 WireGuard 配置。
- 配置地址、路由、DNS 和防火墙。
- 保持前台运行并等待 wireguard-go 子进程。
- 子进程退出时清理系统状态并返回失败。
- 接收 SIGTERM，先清理再停止引擎。

systemd unit 应使用：

- `Type=simple` 或 `Type=notify`。
- `Restart=on-failure`，并设置重启频率限制。
- `KillMode=control-group`，确保包装层和 wireguard-go 子进程一起停止。
- `ExecStopPost` 作为最终幂等清理。
- `After=network-online.target nss-lookup.target`。
- 日志输出到 journald。

### 6.3 网络配置事务

启动顺序：

1. 读取和校验配置。
2. 启动 `wireguard-go -f`。
3. 等待 TUN 和 UAPI。
4. 使用 `wg setconf` 或 UAPI 设置协议参数。
5. 设置地址和 MTU。
6. 添加普通 AllowedIPs 路由。
7. 配置 DNS。
8. 全流量时设置 fwmark、路由表和 `ip rule`。
9. 安装 nftables kill-switch。
10. 向 systemd 报告运行状态。

任何一步失败必须反向回滚。

### 6.4 全流量和防泄漏

全流量模式应复用官方 `wg-quick` 语义：

- 为接口设置 fwmark。
- 建立独立 IPv4/IPv6 路由表。
- 使用 `ip rule` 将未带 mark 的流量导入隧道路由表。
- 抑制 main 表默认路由。
- 使用 nftables 阻止非隧道接口访问隧道地址。
- 保存和恢复 conntrack mark。
- 删除时按产品专用表名和注释精确清理。

首版只支持 nftables。iptables 回退不进入首版。

### 6.5 DNS

首版依赖 `resolvconf` 兼容命令：

- 启动时为接口添加 DNS 和搜索域。
- 停止和失败时删除对应接口 DNS。
- 安装程序检查依赖，缺失时明确失败。

不在首版中直接适配 NetworkManager、systemd-resolved D-Bus 或不同发行版 DNS 管理器。

### 6.6 CLI

建议：

```text
wg-go-quick up <interface>
wg-go-quick down <interface>
wg-go-quick status <interface>
wg-go-quick log <interface>
wg-go-quick enable <interface>
wg-go-quick disable <interface>
wg-go-quick list
```

内部可直接映射到 `systemctl`、`journalctl` 和 `wg show`，不需要独立管理守护进程。

## 7. 可直接转需求的清单

### 7.1 P0 功能

- `REQ-LNX-CONF-001`：解析首版 `.conf` 字段并拒绝脚本。
- `REQ-LNX-STORE-001`：配置目录 `0700`，配置 root:root 和 `0600`。
- `REQ-LNX-ENGINE-001`：无论内核模块是否存在都启动 `wireguard-go`。
- `REQ-LNX-SVC-001`：systemd 直接监督前台 wireguard-go。
- `REQ-LNX-SVC-002`：支持手动启停和可选开机启动。
- `REQ-LNX-SVC-003`：进程失败时执行幂等清理。
- `REQ-LNX-NET-001`：配置 IPv4/IPv6 地址和 MTU。
- `REQ-LNX-NET-002`：根据 AllowedIPs 管理路由。
- `REQ-LNX-NET-003`：支持 Table 和 `Table=off`。
- `REQ-LNX-NET-004`：全流量配置 fwmark、路由表和 `ip rule`。
- `REQ-LNX-DNS-001`：通过 resolvconf 设置和恢复 DNS。
- `REQ-LNX-FW-001`：通过 nftables 实现 kill-switch。
- `REQ-LNX-CLI-001`：提供 up、down、status、log、enable、disable 和 list。
- `REQ-LNX-LOG-001`：使用 journald 且不得记录密钥。
- `REQ-LNX-RECOVER-001`：开机和启动前清理孤儿 TUN、路由和规则。

### 7.2 P1 发布和质量

- `REQ-LNX-PKG-001`：提供 Ubuntu 24.04 amd64 安装包。
- `REQ-LNX-UNINSTALL-001`：卸载后不残留 unit、TUN、路由、DNS 或 nftables 规则。
- `REQ-LNX-TEST-001`：建立 Ubuntu VM 自动化测试。
- `REQ-LNX-TEST-002`：建立进程崩溃和流量泄漏测试。
- `REQ-LNX-PERF-001`：与同机内核 WireGuard 对比性能。

## 8. 分阶段交付

### 阶段 0：技术验证

- 修改或包装官方 wg-quick，强制用户态实现。
- 验证 Address、Route、DNS、MTU、fwmark 和 nftables。
- 验证内核模块已加载时仍使用 TUN。
- 建立与内核 WireGuard 的性能基线。

退出条件：

- 分流和全流量均可通信。
- `ip link show` 能明确区分 TUN 与内核 WireGuard。
- 停止后无路由、DNS和 nftables 残留。

### 阶段 1：systemd 产品化

- 前台监督包装层。
- systemd unit、CLI 和 journald。
- 失败回滚、孤儿资源清理和开机启动。

退出条件：

- 强制终止 wireguard-go 后 systemd 检测失败并完成清理。
- 1000 次启停无资源残留。
- 系统重启后启动行为正确。

### 阶段 2：安装和测试

- Ubuntu 24.04 amd64 安装包。
- 依赖检查、升级和完整卸载。
- VM 自动化、泄漏和性能测试。

退出条件：

- 全新安装、覆盖升级和卸载通过。
- 无内核模块、有内核模块两种环境均通过。
- 24/72 小时稳定性测试通过。

### 阶段 3：正式验收

- 功能、性能、安全、稳定性和兼容性报告。
- 与内核 WireGuard 的已知差异。
- 运维和迁移文档。

## 9. 验收指标

### 9.1 功能

- 支持 IPv4、IPv6、双栈、分流、全流量和多个 Peer。
- 标准配置具有与官方 wg-quick 一致的首版字段语义。
- 内核 WireGuard 存在时仍确认使用 wireguard-go。
- 停止或失败后恢复地址、路由、DNS 和 nftables。

### 9.2 稳定性

- 1000 次启停。
- wireguard-go 随机终止。
- systemd 重启和系统重启。
- 24/72 小时持续传输。
- DHCP 地址、默认路由和 DNS 变化。

### 9.3 安全

- 配置和日志不向普通用户暴露密钥。
- 只有 root 可以控制服务和访问 UAPI。
- 全流量启动、运行、失败和停止阶段无明文泄漏。
- nftables 清理不删除用户已有规则。

### 9.4 性能

与同机内核 WireGuard 对比：

- TCP、UDP、IPv4、IPv6。
- 小包和大包。
- CPU、内存、上下文切换和吞吐。
- 单 Peer 和多个 Peer。

## 10. 主要风险

### 10.1 使用价值

现代 Linux 已有成熟内核 WireGuard。若没有明确的用户态要求，该项目会得到更差性能和更多故障模式。

### 10.2 systemd 监督

直接复用默认 daemon 模式会让 systemd 只看到启动脚本，不直接看到数据面进程。必须使用 `-f` 并让包装层等待子进程。

### 10.3 内核接口误用

原版 wg-quick 会优先创建内核 WireGuard。测试只验证“隧道可用”可能误判为 wireguard-go 成功，必须验证接口类型和进程。

### 10.4 DNS 依赖

不同发行版的 DNS 管理差异较大。首版固定依赖 resolvconf，可以减少实现，但限制支持范围。

### 10.5 GPLv2

官方 wg-quick 属于 GPLv2。直接修改和分发需要遵守 GPLv2。若新增产品层必须保持 MIT，需要重新实现最小编排逻辑。

### 10.6 进程崩溃

用户态数据面消失后，策略路由和防火墙可能继续阻断网络。`ExecStopPost`、启动前清理和失败注入测试是发布阻塞项。

## 11. 粗略工作量

假设：

- 复用官方 Linux wg-quick 行为。
- 只支持 Ubuntu 24.04、systemd、amd64、resolvconf 和 nftables。
- 无 GUI、NetworkManager、容器、自动更新和脚本。

| 范围 | 人月 |
|---|---:|
| 阶段 0 用户态强制和网络验证 | 1-2 |
| systemd、CLI 和故障恢复 | 1-2 |
| 安装和自动化测试 | 1-2 |
| 性能和稳定性收敛 | 1-2 |
| 合计 | 4-8 |

如果不复用 wg-quick，或需要支持更多发行版、DNS 管理器和防火墙后端，工作量会显著增加。

## 12. 下一步

优先验证：

1. 内核 WireGuard 已加载时仍强制运行 wireguard-go。
2. systemd 能直接检测 wireguard-go 退出。
3. 全流量 fwmark、策略路由和 nftables 无泄漏。
4. 强制终止后系统网络自动恢复。
5. 与内核 WireGuard 的性能差距是否可接受。

如果阶段 0 的性能和稳定性明显不满足目标，应停止继续投入，而不是先开发更多产品功能。

## 13. 官方参考资料

- [官方 wireguard-go README](https://github.com/WireGuard/wireguard-go/blob/master/README.md)
- [官方 Linux wg-quick](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash)
- [官方 wg-quick systemd unit](https://git.zx2c4.com/wireguard-tools/tree/src/systemd/wg-quick%40.service)
- [wg-quick 手册](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)
- [wireguard-tools 源码](https://git.zx2c4.com/wireguard-tools/tree/src)
- [官方 Linux TUN 实现](https://github.com/WireGuard/wireguard-go/blob/master/tun/tun_linux.go)
