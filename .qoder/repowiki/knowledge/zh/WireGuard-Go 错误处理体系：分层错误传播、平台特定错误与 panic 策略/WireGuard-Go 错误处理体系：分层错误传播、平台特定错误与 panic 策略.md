---
kind: error_handling
name: WireGuard-Go 错误处理体系：分层错误传播、平台特定错误与 panic 策略
category: error_handling
scope:
    - '**'
source_files:
    - conn/conn.go
    - conn/errors_default.go
    - tun/errors.go
    - ipc/uapi_linux.go
    - ipc/uapi_windows.go
    - device/device.go
    - device/allowedips.go
    - device/receive.go
    - device/send.go
    - main.go
---

## 1. 整体方法

wireguard-go 采用 Go 标准库的 `error` 接口作为统一的错误表示，没有引入自定义错误类型或第三方错误库。错误在包边界通过返回值向上冒泡，由调用方决定是记录日志、退出进程还是继续处理。对于不可恢复的内部状态不一致（如 allowedips 中遇到未知地址类型），使用 `panic` 作为“绝不应发生”的哨兵信号；对于外部资源初始化失败（如 Windows UAPI 安全描述符解析）也在 `init()` 中直接 `panic`。

## 2. 关键文件与包

- **conn/conn.go**：定义包级哨兵错误 `ErrBindAlreadyOpen`、`ErrWrongEndpointType`，用于 Bind/Endpoint 类型不匹配等可预期业务错误。
- **tun/errors.go**：定义 `ErrTooManySegments`，明确该错误不会导致读取终止，供上层区分可恢复与不可恢复错误。
- **ipc/uapi_linux.go / ipc/uapi_windows.go**：UAPI 监听器将底层 accept/inotify/kqueue 错误通过 channel 回传给 `Accept()`，实现非阻塞的错误传播。
- **device/device.go**：设备状态机 `changeState` 在 up/down 失败时自动回滚到 down 状态并返回错误；所有运行时异常统一通过 `device.log.Errorf` 记录。
- **main.go**：进程入口定义 `ExitSetupFailed`/`ExitSetupSuccess` 退出码，TUN/UAPI 初始化失败后记录日志并 `os.Exit(ExitSetupFailed)`。

## 3. 架构与约定

### 3.1 错误分类

| 类别 | 处理方式 | 示例 |
|---|---|---|
| 可恢复 I/O 错误 | 返回 error，由调用方重试或降级 | UDP send/receive、TUN read/write |
| 业务语义错误 | 返回包级哨兵 `errors.New(...)` | `ErrBindAlreadyOpen`、`ErrWrongEndpointType` |
| 内部不变量破坏 | `panic(errors.New(...))` | allowedips 中未知地址类型 |
| 启动期不可恢复错误 | `panic(err)`（init 中） | Windows UAPI 安全描述符解析失败 |
| 进程级配置错误 | 记录日志 + `os.Exit(ExitSetupFailed)` | TUN/UAPI 打开失败 |

### 3.2 分层传播路径

- **设备层**：`Device.Up()/Down()` → `changeState()` → `upLocked()/downLocked()`，任何阶段失败都会回滚状态并返回 error。
- **网络层**：`conn.Bind` 接口的 `Open/Send/Close` 均返回 error；Windows RIO 实现中 ring full 等极端情况直接 `panic`。
- **IPC 层**：`UAPIListener.Accept()` 通过 select 从 `connNew`/`connErr` channel 返回连接或错误，使上层无需轮询。
- **进程层**：`main()` 集中处理 TUN/UAPI 初始化错误，统一以 `ExitSetupFailed` 退出。

### 3.3 日志与错误分离

设备内部使用 `device.Logger` 的 `Verbosef`/`Errorf` 记录运行期问题，但日志不影响控制流——错误仍通过返回值传递。例如 MTU 获取失败仅记录日志并回退到默认值，不中断启动。

## 4. 约定与约束

- **包级哨兵错误**：跨包可见的业务错误必须定义为包级 `var ErrXxx = errors.New(...)`，便于调用方做精确判断（见 conn、tun 包）。
- **错误包装**：使用 `%w` 进行错误链包装（如 `fmt.Errorf("...: %w", err)`），保持错误上下文可追溯。
- **panic 仅限内部不变量**：仅在绝对不可能到达的路径使用 `panic`（allowedips 未知地址类型、Windows RIO 队列损坏、ring full），这些被视为编程错误而非运行时错误。
- **UAPI 错误编码**：Windows 端定义 `IpcErrorIO/IpcErrorProtocol/IpcErrorInvalid/IpcErrorPortInUse/IpcErrorUnknown` 负整数常量，用于向用户态工具返回结构化错误码。
- **关闭语义**：`Bind.Close()` 后所有 ReceiveFunc 必须返回 `net.ErrClosed`，确保协程能优雅退出。
- **错误即正常流程**：`tun.ErrTooManySegments` 被文档化为“不应导致读取停止”，体现 WireGuard 对部分数据丢失的容忍设计。
- **进程退出码**：仅定义 `ExitSetupSuccess=0` 和 `ExitSetupFailed=1`，无更细粒度退出码。

## 5. 观察到的模式总结

1. **错误上抛优先于吞掉**：几乎所有 I/O 操作都返回 error，由上层决定是否记录日志或退出。
2. **平台差异通过错误函数封装**：如 `errShouldDisableUDPGSO` 在 Linux 与非 Linux 平台有不同实现，隐藏平台特定的错误语义。
3. **goroutine 内错误通过 channel 上报**：UAPI 监听器、inotify 监控等后台 goroutine 将错误发送到专用 channel，由主循环消费。
4. **panic 是最后手段**：仅用于违反内部不变量的场景，且集中在少数几个核心数据结构操作中。
5. **日志与错误解耦**：`Logger.Errorf` 用于诊断，不改变函数返回值语义，保证 API 稳定性。