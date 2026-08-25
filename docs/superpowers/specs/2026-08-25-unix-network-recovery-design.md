# Linux 与 macOS 网络变化恢复设计

## 目标

为非 Windows 主程序补充宿主网络变化恢复能力：

- Linux 使用 `NETLINK_ROUTE` 监听接口、地址和路由变化。
- macOS 使用 `AF_ROUTE` 监听接口、地址和路由变化。
- 将短时间内的系统通知合并后，对所有成功启动的 WireGuard Device 调用 `device.HandleNetworkChange()`。
- 恢复效果与 Windows 一致，不要求平台事件字段或底层 API 完全一致。

## 范围

### 纳入范围

- Linux 和 macOS 的宿主网络变化监听。
- 过滤由当前 WireGuard TUN/utun 接口产生的直接接口和地址通知。
- 对有效事件进行防抖，避免一次网络切换重复刷新 UDP 绑定。
- 调用现有 `device.HandleNetworkChange()`，刷新 UDP socket 并唤醒 Peer。
- 记录监视启动、网络变化、恢复成功、恢复失败和监视关闭日志。
- 进程退出时关闭监视 socket 并等待监听 goroutine 结束。
- 为 FreeBSD、OpenBSD 等其它非 Windows 构建提供无操作实现，保持现有编译能力。

### 不纳入范围

- 不修改 Windows 网络变化监视实现。
- 不修改 `device.HandleNetworkChange()` 的恢复步骤。
- 不增加第三方依赖。
- 不实现自动重建失败的 TUN 接口。
- 不重新应用配置文件、系统 IP 地址、DNS 或路由规则。
- 不要求 Linux/macOS 输出与 Windows 完全相同的事件详情。
- 不把已有 Device 内部粘性路由监听改造成主流程监视器。

## 主流程集成

`main.go` 在完成所有配置启动后处理宿主网络监视：

1. 如果没有接口成功启动，不创建网络监视器，仅等待终止信号。
2. 如果至少一个接口成功启动，收集其实际接口名称或接口索引作为排除集合。
3. 调用平台实现创建宿主网络监视器。
4. 监视器启动失败属于非致命错误：记录错误，接口继续运行。
5. 监视器回调触发时，按当前 `running` 顺序逐个调用 `ri.device.HandleNetworkChange()`。
6. 单个接口恢复失败不阻止其它接口继续恢复。
7. 主流程关闭时先关闭监视器，再关闭 UAPI listener 和 Device。

恢复日志至少包含：

```text
检测到本地网络变化，开始刷新 WireGuard UDP 绑定
[接口名] 网络变化恢复完成
[接口名] 网络变化恢复失败: <错误>
Linux/macOS 网络变化监视已启动
Linux/macOS 网络变化监视已关闭
```

## 公共监视接口

主程序只依赖一个最小接口：

```go
type hostNetworkMonitor interface {
	Close()
}
```

平台启动函数接收：

- 网络变化后的回调函数；
- 当前 WireGuard 接口索引排除集合。

Linux、macOS 和其它非 Windows 平台分别通过 build tag 提供实现。主程序不使用 `runtime.GOOS` 分支解析平台事件。

## 防抖

网络切换通常会连续产生多条接口、地址和路由消息。监视器使用一次可重置定时器合并事件：

- 每收到一条有效通知就重置定时器。
- 连续 8 秒没有新通知后执行一次恢复回调，与当前 Windows 防抖时间保持一致。
- 通知通道满时允许丢弃额外详情，但必须保留至少一次待处理恢复。
- `Close()` 必须停止定时器并退出 goroutine，关闭期间不得再触发回调。

防抖循环与平台 socket 读取分离，使用普通通道传递简化事件，以便在当前 Windows 开发机上进行单元测试。

## Linux 实现

Linux 创建 `AF_NETLINK`、`SOCK_RAW|SOCK_CLOEXEC`、`NETLINK_ROUTE` socket，订阅：

- `RTMGRP_LINK`
- `RTMGRP_IPV4_IFADDR`
- `RTMGRP_IPV6_IFADDR`
- `RTMGRP_IPV4_ROUTE`
- `RTMGRP_IPV6_ROUTE`

处理以下消息：

- `RTM_NEWLINK`、`RTM_DELLINK`
- `RTM_NEWADDR`、`RTM_DELADDR`
- `RTM_NEWROUTE`、`RTM_DELROUTE`

过滤规则：

- 忽略当前 WireGuard 接口自身的 Link 和 Address 消息，防止虚拟接口配置变化触发自身恢复。
- Route 消息保留，因为默认路由或出口接口变化是网络切换恢复的主要信号。
- 忽略请求响应、错误消息和不相关消息类型。
- socket 读取错误时，如果是正常关闭则退出；否则记录错误并停止该监视器，不终止 WireGuard 主进程。

## macOS 实现

macOS 创建 `AF_ROUTE`、`SOCK_RAW`、`AF_UNSPEC` socket，处理：

- `RTM_IFINFO`
- `RTM_NEWADDR`、`RTM_DELADDR`
- `RTM_ADD`、`RTM_DELETE`、`RTM_CHANGE`

过滤规则：

- 忽略当前 WireGuard utun 接口自身的 `RTM_IFINFO`、`RTM_NEWADDR` 和 `RTM_DELADDR`。
- 路由新增、删除和修改消息保留。
- 严格校验消息长度和版本，无法安全解析的消息直接跳过。
- socket 读取错误时，如果是正常关闭则退出；否则记录错误并停止该监视器，不终止 WireGuard 主进程。

现有 `tun/tun_darwin.go` 的 `AF_ROUTE` socket 继续只负责 utun 自身 Up、Down 和 MTU 事件，新监视器使用独立 socket 负责宿主网络变化，两者职责不合并。

## 其它非 Windows 平台

由于 `main.go` 的 build tag 是 `!windows`，FreeBSD、OpenBSD 等平台必须提供同名启动函数。该实现返回空监视器或明确的“不支持”结果，主流程记录调试信息后继续运行，不能导致这些平台编译失败。

## 错误和资源处理

- 创建或绑定监视 socket 失败：记录错误，WireGuard 接口继续运行。
- 监听期间发生非关闭错误：记录一次错误，停止监视器，WireGuard 接口继续运行。
- `device.HandleNetworkChange()` 失败：记录对应接口错误，继续处理其它接口。
- `Close()` 必须可重复调用。
- `Close()` 必须中断阻塞读取、关闭 socket 并等待 goroutine 结束。
- 监视器不得持有或关闭 Device；Device 生命周期仍由 `main.go` 管理。

## 测试

通用单元测试：

- 连续通知只触发一次恢复回调。
- 分离通知分别触发恢复回调。
- 关闭监视器后不再触发回调。
- 事件通道满时仍保留一次恢复机会。
- 排除接口的 Link/Address 消息不会触发恢复。
- 非排除接口或 Route 消息会触发恢复。

平台解析测试：

- Linux 正确识别 Link、Address、Route 消息类型和接口索引。
- Linux 忽略截断、错误和不相关 netlink 消息。
- macOS 正确识别接口、地址和路由消息类型。
- macOS 忽略截断、版本错误和不相关 `AF_ROUTE` 消息。

构建验证：

```powershell
go test .
go test ./device
go test ./tun
go build .
$env:GOOS='linux'; $env:GOARCH='amd64'; go build .
$env:GOOS='darwin'; $env:GOARCH='amd64'; go build .
$env:GOOS='darwin'; $env:GOARCH='arm64'; go build .
```

真实网络切换验证必须分别在 Linux 和 macOS 上执行。Windows 交叉编译只能证明平台代码可编译，不能证明 `NETLINK_ROUTE` 或 `AF_ROUTE` 在断网、切换 Wi-Fi、切换默认路由后的实际恢复效果。

## 预计文件变更

- 修改 `main.go`，接入监视器生命周期和恢复回调。
- 新增非 Windows 公共防抖实现及测试。
- 新增 Linux `NETLINK_ROUTE` 监视实现及解析测试。
- 新增 macOS `AF_ROUTE` 监视实现及解析测试。
- 新增其它非 Windows 平台的兼容实现。
- 不修改 `main_windows.go`、`netmon_windows.go` 和 `device.HandleNetworkChange()`。
