# Linux 主程序功能对齐实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 将非 Windows 主程序完全切换为与 Windows 一致的配置驱动、多接口启动模式，并在 Linux 上应用 MTU、地址和链路状态。

**架构：** `main.go` 负责 Unix 参数、同步、守护和多接口生命周期编排，复用现有配置解析与同步服务。新增 `linux_netconfig.go` 隔离 `ip` 命令生成和执行，通过函数注入进行无特权单元测试；Unix UAPI 继续使用 `ipc.UAPIOpen` 与 `ipc.UAPIListen`。

**技术栈：** Go 1.23+、pflag、log4go、现有 WireGuard `tun/device/ipc/conn` 包、Linux iproute2。

---

## 文件结构

- 修改：`main.go` — 非 Windows 配置驱动入口、单接口启动、多接口生命周期、帮助和版本输出。
- 创建：`linux_netconfig.go` — 非 Windows `ip` 命令模型、命令生成与网络配置执行。
- 创建：`linux_netconfig_test.go` — Linux 网络命令生成、顺序、参数隔离和错误测试。
- 修改：`daemon_test.go` — 补充 Linux/macOS 默认配置路径断言。

### 任务 1：Linux 网络配置命令

**文件：**
- 创建：`linux_netconfig.go`
- 创建：`linux_netconfig_test.go`

- [ ] **步骤 1：编写失败测试**

测试 `buildLinuxNetworkCommands("wg-test", 1380, []string{"10.0.0.2/24", "fd00::2/64"})` 精确返回：

```go
[]systemCommand{
    {exe: "ip", args: []string{"link", "set", "dev", "wg-test", "mtu", "1380"}},
    {exe: "ip", args: []string{"address", "replace", "10.0.0.2/24", "dev", "wg-test"}},
    {exe: "ip", args: []string{"address", "replace", "fd00::2/64", "dev", "wg-test"}},
    {exe: "ip", args: []string{"link", "set", "dev", "wg-test", "up"}},
}
```

同时测试 MTU 为 0 且地址为空时仅生成链路 UP；测试 `applyLinuxNetworkConfigWithRunner` 按顺序执行并汇总包含命令与底层错误的警告。

- [ ] **步骤 2：运行测试验证失败**

运行：`go test . -run '^Test(BuildLinuxNetworkCommands|ApplyLinuxNetworkConfig)'`

预期：FAIL，函数或类型尚未定义。

- [ ] **步骤 3：实现最少代码**

在 `linux_netconfig.go` 中定义仅编译于 `!windows` 的：

```go
type systemCommand struct {
    exe  string
    args []string
}

func (c systemCommand) String() string
func buildLinuxNetworkCommands(interfaceName string, mtu int, addresses []string) []systemCommand
func applyLinuxNetworkConfig(interfaceName string, mtu int, addresses []string) []string
func applyLinuxNetworkConfigWithRunner(interfaceName string, mtu int, addresses []string, run func(systemCommand) error) []string
func runLinuxSystemCommand(command systemCommand) error
```

`runLinuxSystemCommand` 使用 `exec.Command(command.exe, command.args...).CombinedOutput()`，失败时附加非空输出，不使用 shell，不重试。

- [ ] **步骤 4：运行目标测试**

运行：`go test . -run '^Test(BuildLinuxNetworkCommands|ApplyLinuxNetworkConfig)'`

预期：PASS。

### 任务 2：重写 Unix 配置驱动入口

**文件：**
- 修改：`main.go`

- [ ] **步骤 1：先建立可编译的入口结构**

从 `main_windows.go` 对齐以下公共行为：

```go
var appName = "WireGuard"
var appVer = "0.0.1"
var IsBeta = ""
var BuildTime = ""

type runningInterface struct {
    name   string
    device *device.Device
    uapi   net.Listener
}
```

删除 `ENV_WG_TUN_FD`、`ENV_WG_UAPI_FD`、`ENV_WG_PROCESS_FOREGROUND`、位置接口名解析和 FD 构造分支。更新帮助文本为 Unix 路径和配置模式。

- [ ] **步骤 2：实现 Unix 单接口启动**

增加：

```go
func startConfiguredInterface(cfg *tunnelConfig) (*runningInterface, error)
```

执行顺序：确定有效 MTU → `tun.CreateTUN` → 实际名称 → `device.NewDevice` → `dev.IpcSet` → `dev.Up` → `applyLinuxNetworkConfig` → `ipc.UAPIOpen` → `ipc.UAPIListen`。任一步失败时关闭此前资源。

- [ ] **步骤 3：实现参数与同步流程**

注册并处理 Windows 已有参数：`confile`、`foreground`、`quit`、`status`、`daemon`、六个同步参数。同步模式优先执行；位置参数统一输出错误并以 `ExitSetupFailed` 退出。配置路径使用：

```go
confile := logs.GetParamString("confile", *pconfile, getDefaultConfilePath())
```

- [ ] **步骤 4：实现日志、守护与多接口生命周期**

对齐 Windows 日志初始化、自更新、`-q/-S`、默认守护和 PID 文件。读取所有配置后逐个启动；零个有效配置或零个成功接口以失败码退出。每个成功接口启动 UAPI Accept 和 Device Wait goroutine。

主循环监听 `os.Interrupt`、`unix.SIGTERM`、UAPI 错误和 Device 退出。通过关闭状态通道/原子状态阻止 listener 主动关闭产生的 Accept 错误阻塞；关闭顺序为所有 listener 后所有 Device。

- [ ] **步骤 5：检查 Linux 编译**

运行：`GOOS=linux GOARCH=amd64 go test . -run '^$'`

预期：根包编译成功。

### 任务 3：默认配置路径测试

**文件：**
- 修改：`daemon_test.go`

- [ ] **步骤 1：增加平台测试**

Linux 断言 `/etc/wireguard/wgtun.conf`；darwin 根据 `runtime.GOARCH` 断言 Homebrew 默认路径（仅在对应平台运行，避免依赖当前 Windows）。保留 Windows 测试。

- [ ] **步骤 2：运行测试**

运行：`go test . -run '^TestGetDefaultConfilePath'`

预期：当前平台相关断言 PASS。

### 任务 4：格式、全量测试与交叉构建

**文件：**
- 修改：仅修复本任务引入的格式或编译问题。

- [ ] **步骤 1：格式化改动 Go 文件**

运行：`gofmt -w main.go linux_netconfig.go linux_netconfig_test.go daemon_test.go`

- [ ] **步骤 2：运行网络配置测试**

运行：`go test . -run '^Test(BuildLinuxNetworkCommands|ApplyLinuxNetworkConfig|GetDefaultConfilePath)'`

预期：PASS。

- [ ] **步骤 3：运行全部测试**

运行：`go test ./...`

预期：PASS。

- [ ] **步骤 4：运行格式测试**

运行：`go test . -run '^TestFormatting$'`

预期：PASS。

- [ ] **步骤 5：交叉构建 Linux amd64**

运行：`GOOS=linux GOARCH=amd64 go build ./...`

预期：成功生成/编译 Linux amd64 目标，无编译错误。

- [ ] **步骤 6：审查差异**

运行：`git diff --check`、`git status --short`、`git diff --stat`。

确认没有修改 `main_windows.go`，没有引入 DNS、路由、钩子、netlink 或旧 FD 兼容逻辑。

- [ ] **步骤 7：真实环境限制说明**

若未在 Linux root 环境运行真实 TUN，最终结果明确标注：自动测试与 Linux 交叉构建通过，但真实 TUN/IP/UAPI 端到端启动尚未验证。
