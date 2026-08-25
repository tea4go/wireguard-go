# Unix 网络变化恢复实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 subagent-driven-development（推荐）或 executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 在 Linux 和 macOS 上监听宿主接口、地址和路由变化，防抖后调用所有运行中 WireGuard Device 的 `HandleNetworkChange()`，并让非 Windows 在全部接口启动失败时保持进程运行等待终止信号。

**架构：** `netmon_common.go` 提供平台无关事件模型、防抖循环和接口排除规则；Linux/macOS 原始消息解析器也保持纯 Go，以便在 Windows 开发机执行测试。`netmon_linux.go` 和 `netmon_darwin.go` 只负责平台 socket 生命周期，`main.go` 负责监视器启动、恢复回调和关闭顺序。

**技术栈：** Go 1.23、`golang.org/x/sys/unix`、Linux `NETLINK_ROUTE`、macOS `AF_ROUTE`、现有 `device.HandleNetworkChange()`。

---

## 文件结构

- 创建：`netmon_common.go` — 公共事件模型、防抖循环、接口排除和监视器接口。
- 创建：`netmon_common_test.go` — 防抖、关闭、排除和通道拥塞测试。
- 创建：`netmon_linux_messages.go` — 纯 Go Linux netlink 消息解析。
- 创建：`netmon_linux_messages_test.go` — Linux Link/Address/Route、截断和无关消息测试。
- 创建：`netmon_linux.go` — Linux `NETLINK_ROUTE` socket 创建、读取和关闭。
- 创建：`netmon_darwin_messages.go` — 纯 Go macOS routing socket 消息解析。
- 创建：`netmon_darwin_messages_test.go` — macOS Interface/Address/Route、版本和截断测试。
- 创建：`netmon_darwin.go` — macOS `AF_ROUTE` socket 创建、读取和关闭。
- 创建：`netmon_other.go` — 其它非 Windows 平台兼容实现。
- 修改：`main.go` — 接入监视器、恢复回调、关闭顺序和零接口等待策略。

### 任务 1：公共事件与防抖循环

**文件：**
- 创建：`netmon_common.go`
- 创建：`netmon_common_test.go`

- [ ] **步骤 1：编写失败测试**

定义测试期望的公共 API：

```go
func TestRunHostNetworkChangeLoopCoalescesBurst(t *testing.T)
func TestRunHostNetworkChangeLoopSeparatesEvents(t *testing.T)
func TestRunHostNetworkChangeLoopStopsWithoutCallback(t *testing.T)
func TestHostNetworkEventFiltersExcludedInterface(t *testing.T)
func TestEnqueueHostNetworkEventKeepsPendingRecoveryWhenFull(t *testing.T)
```

核心断言：

```go
events <- hostNetworkEvent{kind: hostNetworkEventLink, ifIndex: 7, detail: "Link@eth0"}
events <- hostNetworkEvent{kind: hostNetworkEventAddress, ifIndex: 7, detail: "Address@eth0"}
// 一个防抖窗口只调用一次，count == 2。
```

排除规则：

```go
excluded := map[int]string{9: "wgtun0"}
if hostNetworkEvent{kind: hostNetworkEventLink, ifIndex: 9}.actionable(excluded) {
    t.Fatal("expected excluded link event to be ignored")
}
if !hostNetworkEvent{kind: hostNetworkEventRoute, ifIndex: 9}.actionable(excluded) {
    t.Fatal("expected route event to remain actionable")
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```powershell
go test . -run '^Test(RunHostNetworkChangeLoop|HostNetworkEvent|EnqueueHostNetworkEvent)'
```

预期：FAIL，`hostNetworkEvent`、`runHostNetworkChangeLoop` 或相关函数未定义。

- [ ] **步骤 3：实现最少公共代码**

在 `netmon_common.go` 中定义：

```go
const hostNetworkChangeDebounce = 8 * time.Second

type hostNetworkEventKind uint8

const (
    hostNetworkEventLink hostNetworkEventKind = iota + 1
    hostNetworkEventAddress
    hostNetworkEventRoute
)

type hostNetworkEvent struct {
    kind    hostNetworkEventKind
    ifIndex int
    detail  string
}

type hostNetworkMonitor interface {
    Close()
}

func (event hostNetworkEvent) actionable(excluded map[int]string) bool
func enqueueHostNetworkEvent(events chan<- hostNetworkEvent, event hostNetworkEvent)
func runHostNetworkChangeLoop(events <-chan hostNetworkEvent, stop <-chan struct{}, debounce time.Duration, excluded map[int]string, onChange func(int, []string))
```

`runHostNetworkChangeLoop` 必须在 timer 触发后再次检查 `stop`，保证 `Close()` 与 timer 同时就绪时不调用恢复回调。

- [ ] **步骤 4：运行测试验证通过**

运行：

```powershell
go test . -run '^Test(RunHostNetworkChangeLoop|HostNetworkEvent|EnqueueHostNetworkEvent)'
```

预期：PASS。

### 任务 2：Linux netlink 解析和监视器

**文件：**
- 创建：`netmon_linux_messages.go`
- 创建：`netmon_linux_messages_test.go`
- 创建：`netmon_linux.go`

- [ ] **步骤 1：编写 Linux 消息解析失败测试**

使用 `encoding/binary.NativeEndian` 构造 Linux ABI 消息：

```go
func linuxNetlinkMessage(messageType uint16, payload []byte) []byte {
    message := make([]byte, 16+len(payload))
    binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
    binary.NativeEndian.PutUint16(message[4:6], messageType)
    copy(message[16:], payload)
    return message
}
```

测试消息：

- `RTM_NEWLINK`/`RTM_DELLINK`：从 `ifinfomsg` 偏移 4 读取接口索引。
- `RTM_NEWADDR`/`RTM_DELADDR`：从 `ifaddrmsg` 偏移 4 读取接口索引。
- `RTM_NEWROUTE`/`RTM_DELROUTE`：生成 Route 事件。
- 截断 header、非法长度和无关类型返回空事件。

- [ ] **步骤 2：运行 Linux 解析测试验证失败**

运行：

```powershell
go test . -run '^TestParseLinuxNetlink'
```

预期：FAIL，`parseLinuxNetlinkEvents` 未定义。

- [ ] **步骤 3：实现纯 Go Linux 消息解析**

在 `netmon_linux_messages.go` 中定义 Linux ABI 常量和：

```go
func parseLinuxNetlinkEvents(data []byte) []hostNetworkEvent
```

逐条校验：

- header 至少 16 字节；
- `messageLength >= 16`；
- `messageLength <= len(remain)`；
- Link payload 至少 16 字节；
- Address payload 至少 8 字节；
- 使用 4 字节对齐跳到下一条消息。

- [ ] **步骤 4：运行 Linux 解析测试验证通过**

运行：

```powershell
go test . -run '^TestParseLinuxNetlink'
```

预期：PASS。

- [ ] **步骤 5：实现 Linux socket 层**

`netmon_linux.go` 使用 `//go:build linux`，定义：

```go
type linuxHostNetworkMonitor struct {
    fd        int
    events    chan hostNetworkEvent
    stop      chan struct{}
    done      chan struct{}
    closeOnce sync.Once
    onChange  func(int, []string)
    excluded  map[int]string
}

func startHostNetworkMonitor(onChange func(int, []string), excluded map[int]string) (hostNetworkMonitor, error)
func (monitor *linuxHostNetworkMonitor) Close()
```

socket：

```go
unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
```

订阅组：

```go
unix.RTMGRP_LINK |
    unix.RTMGRP_IPV4_IFADDR |
    unix.RTMGRP_IPV6_IFADDR |
    unix.RTMGRP_IPV4_ROUTE |
    unix.RTMGRP_IPV6_ROUTE
```

读取 goroutine 调用 `parseLinuxNetlinkEvents`，将事件放入公共防抖循环。`Close()` 先关闭 `stop`，再 `Shutdown`/`Close` socket，最后等待 `done`。

- [ ] **步骤 6：Linux 交叉编译检查**

运行：

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; go test -c -o .gotmp\wireguard-linux.test .
```

预期：成功生成 Linux 测试二进制。

### 任务 3：macOS route socket 解析和监视器

**文件：**
- 创建：`netmon_darwin_messages.go`
- 创建：`netmon_darwin_messages_test.go`
- 创建：`netmon_darwin.go`

- [ ] **步骤 1：编写 macOS 消息解析失败测试**

构造公共 routing message 头：

```go
func darwinRouteMessage(messageType uint8, ifIndex uint16, length int) []byte {
    message := make([]byte, length)
    binary.NativeEndian.PutUint16(message[0:2], uint16(length))
    message[2] = darwinRouteMessageVersion
    message[3] = messageType
    binary.NativeEndian.PutUint16(message[12:14], ifIndex)
    return message
}
```

测试：

- `RTM_IFINFO`、`RTM_NEWADDR`、`RTM_DELADDR` 读取偏移 12 的接口索引。
- `RTM_ADD`、`RTM_DELETE`、`RTM_CHANGE` 生成 Route 事件，接口索引从偏移 4 读取。
- 错误版本、长度小于 4、声明长度超过缓冲区和无关类型返回空事件。

- [ ] **步骤 2：运行 macOS 解析测试验证失败**

运行：

```powershell
go test . -run '^TestParseDarwinRoute'
```

预期：FAIL，`parseDarwinRouteEvents` 未定义。

- [ ] **步骤 3：实现纯 Go macOS 消息解析**

在 `netmon_darwin_messages.go` 中定义稳定的 Darwin routing socket ABI 常量：

```go
const (
    darwinRouteMessageVersion = 0x5
    darwinRTMAdd              = 0x1
    darwinRTMDelete           = 0x2
    darwinRTMChange           = 0x3
    darwinRTMNewAddr          = 0xc
    darwinRTMDelAddr          = 0xd
    darwinRTMIfInfo           = 0xe
)

func parseDarwinRouteEvents(data []byte) []hostNetworkEvent
```

逐条按 `msglen` 前进；接口/地址消息至少 14 字节，路由消息至少 6 字节。

- [ ] **步骤 4：运行 macOS 解析测试验证通过**

运行：

```powershell
go test . -run '^TestParseDarwinRoute'
```

预期：PASS。

- [ ] **步骤 5：实现 macOS socket 层**

`netmon_darwin.go` 使用 `//go:build darwin`，结构和生命周期与 Linux 一致，socket 为：

```go
unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.AF_UNSPEC)
```

读取使用 `unix.Read`，解析后送入公共防抖循环。`Close()` 中使用 `unix.Shutdown(fd, unix.SHUT_RDWR)` 中断阻塞读取，再关闭 fd 并等待 goroutine。

- [ ] **步骤 6：macOS 双架构交叉编译检查**

运行：

```powershell
$env:GOOS='darwin'; $env:GOARCH='amd64'; go test -c -o .gotmp\wireguard-darwin-amd64.test .
$env:GOOS='darwin'; $env:GOARCH='arm64'; go test -c -o .gotmp\wireguard-darwin-arm64.test .
```

预期：两个测试二进制均生成成功。

### 任务 4：其它非 Windows 平台兼容

**文件：**
- 创建：`netmon_other.go`

- [ ] **步骤 1：实现兼容入口**

使用 build tag：

```go
//go:build !windows && !linux && !darwin
```

实现：

```go
func startHostNetworkMonitor(func(int, []string), map[int]string) (hostNetworkMonitor, error) {
    return nil, nil
}
```

- [ ] **步骤 2：检查 FreeBSD/OpenBSD 编译**

运行：

```powershell
$env:GOOS='freebsd'; $env:GOARCH='amd64'; go test -c -o .gotmp\wireguard-freebsd.test .
$env:GOOS='openbsd'; $env:GOARCH='amd64'; go test -c -o .gotmp\wireguard-openbsd.test .
```

预期：没有因缺失 `startHostNetworkMonitor` 导致编译失败；若出现仓库既有平台错误，单独记录。

### 任务 5：接入非 Windows 主流程

**文件：**
- 修改：`main.go`

- [ ] **步骤 1：修改零接口启动策略**

把：

```go
if len(running) == 0 {
    logs.Error("所有接口均启动失败")
    os.Exit(ExitSetupFailed)
}
```

改为：

```go
if len(running) == 0 {
    logs.Warning("当前没有成功启动的接口，进程将保持运行并等待终止信号")
}
```

主流程继续创建 signal channel 并进入现有 `select`。

- [ ] **步骤 2：启动宿主网络监视器**

仅在 `len(running) > 0` 时：

```go
excluded := make(map[int]string, len(running))
for _, ri := range running {
    iface, err := net.InterfaceByName(ri.name)
    if err == nil {
        excluded[iface.Index] = ri.name
    }
}

networkMonitor, err = startHostNetworkMonitor(func(changeCount int, details []string) {
    logs.Notice("检测到本地网络变化(%d 个事件)，开始刷新 WireGuard UDP 绑定", changeCount)
    for _, ri := range running {
        if err := ri.device.HandleNetworkChange(); err != nil {
            logs.Error("[%s] 网络变化恢复失败: %v", ri.name, err)
            continue
        }
        logs.Notice("[%s] 网络变化恢复完成", ri.name)
    }
}, excluded)
```

启动失败只记录错误，不退出。

- [ ] **步骤 3：调整关闭顺序**

在关闭 UAPI listener 前：

```go
if networkMonitor != nil {
    networkMonitor.Close()
    logs.Notice("%s 网络变化监视已关闭", runtime.GOOS)
}
```

- [ ] **步骤 4：格式化并编译根包**

运行：

```powershell
gofmt -w main.go netmon_common.go netmon_common_test.go netmon_linux_messages.go netmon_linux_messages_test.go netmon_linux.go netmon_darwin_messages.go netmon_darwin_messages_test.go netmon_darwin.go netmon_other.go
go test . -run '^Test(RunHostNetworkChangeLoop|HostNetworkEvent|EnqueueHostNetworkEvent|ParseLinuxNetlink|ParseDarwinRoute)'
```

预期：所有平台无关测试 PASS。

### 任务 6：完整验证和差异检查

**文件：**
- 仅修复本任务引入的测试、格式或编译问题。

- [ ] **步骤 1：运行根包测试**

运行：

```powershell
$env:GOCACHE='C:\MyWork\GitCode\wireguard-go\.gocache'
$env:GOTMPDIR='C:\MyWork\GitCode\wireguard-go\.gotmp'
go test .
```

预期：PASS。

- [ ] **步骤 2：运行 Device 和 TUN 定向测试**

运行：

```powershell
go test ./device -run 'Test.*NetworkChange'
go test ./tun
```

预期：相关测试 PASS；既有平台限制单独记录。

- [ ] **步骤 3：跨平台构建**

运行：

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; go build -o .gotmp\wireguard-linux-amd64 .
$env:GOOS='darwin'; $env:GOARCH='amd64'; go build -o .gotmp\wireguard-darwin-amd64 .
$env:GOOS='darwin'; $env:GOARCH='arm64'; go build -o .gotmp\wireguard-darwin-arm64 .
```

预期：三个目标均构建成功。

- [ ] **步骤 4：检查工作区差异**

运行：

```powershell
git diff --check
git status --short
git diff --stat
```

确认：

- 未修改 `main_windows.go` 和 `netmon_windows.go`。
- 未修改 `device.HandleNetworkChange()`。
- 未覆盖用户已有的 `runlinux.cmd` 改动。
- `.gotmp` 构建产物不进入提交。

- [ ] **步骤 5：记录真实环境限制**

最终报告明确说明：Windows 主机上的单元测试和交叉构建不能代替 Linux/macOS 上真实断网、Wi-Fi 切换和默认路由切换测试。
