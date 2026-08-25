# Linux 主程序对齐 Windows 功能设计

## 目标

以 `main_windows.go` 当前业务行为为基准改造非 Windows 入口 `main.go`，使 Linux/macOS 构建采用配置文件驱动的启动方式，支持单个 `.conf`、包含多个配置的 `.zip` 和配置目录，同时保留 Unix 平台必需的 TUN、UAPI、信号和守护进程实现。

本次完全移除旧的单接口位置参数和继承文件描述符模式。程序只能通过 `-c/--confile`、`confile` 环境变量或平台默认配置路径启动接口。

## 范围

### 纳入范围

- 对齐 Windows 入口的帮助、版本、配置、同步、日志、守护进程和多接口生命周期流程。
- 支持 `-c/--confile` 指定 `.conf`、`.zip` 或配置目录。
- 支持 `--sync-provider`、`--sync-action`、`--sync-token`、`--sync-gist-id`、`--sync-file` 和 `--sync`。
- 支持 `-f/--foreground`、`-q/--quit`、`-S/--status` 和内部 `--daemon`。
- 在 Linux 上创建多个 TUN，应用 WireGuard UAPI、MTU 和接口地址。
- 使用 Linux `ip` 命令设置接口 MTU、Address 和链路 UP。
- 保留 Unix UAPI socket、`SIGINT/SIGTERM`、Linux 守护进程和内核原生 WireGuard 提示。

### 不纳入范围

- 不支持旧用法 `wireguard <接口名>`。
- 不支持 `WG_TUN_FD`、`WG_UAPI_FD` 和 `WG_PROCESS_FOREGROUND`。
- 不处理 `DNS`、`Table`、`PreUp`、`PostUp`、`PreDown`、`PostDown`、`SaveConfig`。
- 不根据 `AllowedIPs` 添加系统路由。
- 不移植 Wintun 检查、Windows LUID、Windows token 权限、IPv6 绑定关闭或 Windows 网络变化监视。
- 不重构 `main_windows.go`，不改变 Windows 行为。
- 不引入 netlink 依赖。

## 入口流程

`main.go` 采用以下控制流：

1. 在 pflag 解析前处理 `-h/--help` 和 `--version`，输出完整信息后退出。
2. 注册配置、运行模式和同步参数，隐藏内部 `--daemon`。
3. 优先处理同步模式；同步命令不能携带额外位置参数。
4. 解析配置路径，优先级为命令行 `--confile`、`confile` 环境变量、平台默认路径。
5. 初始化应用版本、文件日志和自更新。
6. 处理 `--quit` 和 `--status`。
7. 默认启动守护子进程；`--foreground` 或内部 `--daemon` 直接进入运行流程。
8. 守护子进程写入 PID 文件，并在退出时移除。
9. 拒绝所有位置参数。
10. 读取 `.conf`、`.zip` 或目录中的配置，按现有解析规则生成一个或多个 `tunnelConfig`。
11. 逐个启动接口，保留成功接口并记录失败接口。
12. 至少一个接口成功后进入事件循环；所有接口失败则返回失败码。
13. 监听 `SIGINT/SIGTERM`、非预期 UAPI 监听退出或 Device 退出。
14. 关闭所有 UAPI listener 和 Device，结束进程。

Linux 内核原生 WireGuard 提示只在进入实际 VPN 启动流程时显示，不影响帮助、版本、同步、状态查询和停止命令。

## 接口启动

每个 `tunnelConfig` 独立启动：

1. 使用配置文件名派生的 `InterfaceName` 创建 TUN。
2. 配置中存在 MTU 时传给 `tun.CreateTUN`；否则使用 `device.DefaultMTU`。
3. 读取 TUN 返回的实际接口名，后续日志、UAPI 和网络配置均使用实际名称。
4. 创建 `device.Device`。
5. 使用 `dev.IpcSet(cfg.UAPI)` 应用 PrivateKey、ListenPort、FwMark 和 Peer 配置。
6. 调用 `dev.Up()`。
7. 使用 Linux 网络配置适配器应用 MTU、Address 和链路 UP。
8. 使用 Unix `ipc.UAPIOpen` 与 `ipc.UAPIListen` 创建控制 socket。
9. 启动 UAPI Accept 循环和 Device Wait 监听。

接口创建、UAPI 应用、Device Up 或 UAPI listener 创建失败属于接口启动失败，必须关闭已创建资源。单个接口失败不阻止其他配置继续启动。

## Linux 网络配置适配

新增 Linux/Unix 平台网络配置文件，将命令构造与命令执行分离，以便单元测试。

命令通过 `exec.Command` 的独立参数调用，不经过 shell：

```text
ip link set dev <interface> mtu <mtu>
ip address replace <cidr> dev <interface>
ip link set dev <interface> up
```

规则：

- MTU 只在配置显式提供时执行设置命令；创建 TUN 时仍使用有效默认 MTU。
- Address 按配置顺序逐条执行 `address replace`。
- 无论是否配置 Address，均执行链路 UP。
- `ip` 不存在或任一命令失败时记录包含接口、完整参数和错误输出的警告。
- 网络配置失败不撤销已启动的 WireGuard Device，与 Windows 当前地址配置的非致命行为一致。
- 关闭时不单独删除地址；TUN 销毁后由内核清理。

## 生命周期与并发

使用 `runningInterface` 保存接口名、Device 和 UAPI listener。

每个 UAPI Accept 循环把非预期错误发送到带缓冲事件通道。关闭 listener 后产生的 Accept 错误属于正常关闭过程，不应覆盖既有关闭原因或阻塞 goroutine。

主事件循环等待：

- `SIGINT` 或 `SIGTERM`；
- 任一运行接口的 Device Wait 返回；
- 任一 UAPI listener 非预期退出。

关闭顺序为：

1. 标记进入关闭阶段；
2. 关闭所有 UAPI listener；
3. 关闭所有 Device；
4. 等待必要的 goroutine 结束；
5. 记录关闭完成。

## 错误处理

- 配置源无法读取、没有有效配置或全部接口启动失败：记录错误并以 `ExitSetupFailed` 退出。
- 配置解析警告逐条记录，但有效配置仍可启动。
- 单个接口启动失败：记录错误并继续处理其他接口。
- Linux 网络命令失败：记录警告，接口保持运行。
- PID 文件写入失败：守护子进程不继续运行。
- 同步失败：输出错误并以失败码退出。
- 位置参数存在：输出用法和明确错误并以失败码退出。

## 帮助与版本信息

Linux 帮助内容对齐 Windows 功能，但示例使用 Unix 路径：

- `-c /etc/wireguard/wgtun.conf`
- `--confile /etc/wireguard`
- `confile=/path/to/conf wireguard`
- 同步 upload/download 和 JSON5 配置示例

版本信息统一展示 `appName`、`appVer`、`BuildTime` 和 `runtime.GOOS/runtime.GOARCH`。构建系统继续通过 ldflags 注入 `appVer`、`BuildTime` 和 `IsBeta`。

## 测试

新增 Linux 网络配置单元测试，至少覆盖：

- 配置 MTU、多个 IPv4/IPv6 Address 时生成的命令和顺序。
- 未配置 MTU 或 Address 时只生成链路 UP 命令。
- 接口名与地址作为独立参数传递，不产生 shell 拼接。
- 命令执行失败时返回可用于日志的错误信息。

必要时把参数校验提取为小型辅助函数，测试：

- 位置参数被拒绝。
- 配置路径优先级保持命令行、环境变量、默认路径。
- 同步模式优先于 VPN 启动流程。

验证命令：

```bash
go test ./...
go test . -run '^TestFormatting$'
GOOS=linux GOARCH=amd64 go build ./...
```

真实 TUN、地址设置和 UAPI 启动需要 Linux root 环境。若本地环境不具备条件，最终报告必须明确区分自动化验证和未执行的端到端验证。

## 预计文件变更

- 修改 `main.go`。
- 新增 Linux 网络配置实现文件及对应测试。
- 仅删除由旧 Unix FD 模式产生的无用常量和 import。
- 不修改 Windows 入口和 Windows 网络配置行为。
