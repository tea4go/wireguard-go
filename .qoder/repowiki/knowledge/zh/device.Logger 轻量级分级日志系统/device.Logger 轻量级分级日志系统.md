---
kind: logging_system
name: device.Logger 轻量级分级日志系统
category: logging_system
scope:
    - '**'
source_files:
    - device/logger.go
    - main.go
    - device/device.go
    - conn/winrio/rio_windows.go
---

## 1. 使用的系统与框架

本仓库没有引入第三方日志库，而是基于 Go 标准库 `log` 实现了一个极简的、面向 WireGuard Device 的分级日志器。核心定义在 `device/logger.go`，通过 `device.NewLogger(level, prepend)` 构造，输出到 `os.Stdout`，格式为 `LEVEL: prefix + prepend`（例如 `DEBUG: (wg0) Starting wireguard-go version ...`），并自动附加日期和时间前缀。

## 2. 关键文件与位置

- `device/logger.go`：定义 `Logger` 结构体、日志级别常量、`NewLogger` 构造器以及 `DiscardLogf` 空操作函数。
- `main.go`：进程入口，读取环境变量 `LOG_LEVEL` 决定日志级别，创建 `device.Logger` 并注入到 `device.NewDevice`。
- `device/device.go`：持有 `*Logger` 字段，所有设备层日志通过 `device.log.Verbosef / device.log.Errorf` 调用。
- `conn/winrio/rio_windows.go`：使用标准 `log.Printf` 记录 Windows Registered I/O 不可用的提示（非结构化，仅调试用途）。
- 测试文件（如 `device/device_test.go`、`device/noise_test.go`）通过 `NewLogger(LogLevelError, "")` 等构造 logger 以抑制或启用日志。

## 3. 架构与约定

### 3.1 日志级别
`device/logger.go` 定义了三个级别（自增 iota）：
- `LogLevelSilent = 0`：静默，不输出任何内容（Verbosef 与 Errorf 均指向 `DiscardLogf`）。
- `LogLevelError = 1`：仅输出错误信息。
- `LogLevelVerbose = 2`：输出调试与错误信息。

级别由 `main.go` 中的 `LOG_LEVEL` 环境变量解析：`verbose`/`debug` → `LogLevelVerbose`，`error` → `LogLevelError`，`silent` → `LogLevelSilent`，未设置时默认 `LogLevelError`。

### 3.2 Logger 接口设计
`Logger` 结构体只暴露两个方法：
```go
type Logger struct {
    Verbosef func(format string, args ...any)
    Errorf   func(format string, args ...any)
}
```
注释明确要求：
- 必须是并发安全的（safe for concurrent use）。
- 不需要换行符结尾（do not require a trailing newline）。
- 如果某个级别的函数为 nil，则该级别静默。

这种设计让调用方（`device/device.go` 等）无需判断日志级别，直接调用即可——低级别被丢弃，高级别正常输出。

### 3.3 输出格式与上下文
`NewLogger` 使用 `log.New(os.Stdout, prefix, log.Ldate|log.Ltime)` 创建底层 logger，其中 `prefix` 固定为 `"DEBUG"` 或 `"ERROR"`，再拼接传入的 `prepend`（通常是 `"(wg0) "` 这样的接口名）。因此输出形如：
```
2025/01/01 12:00:00 DEBUG: (wg0) Interface state was ..., requested ..., now ...
2025/01/01 12:00:00 ERROR: (wg0) Unable to update bind: ...
```

### 3.4 守护进程模式下的 stdout/stderr 处理
当不在前台运行时（daemonize），`main.go` 根据 `LOG_LEVEL` 是否静默来决定子进程的 stdin/stdout/stderr：
- 若 `LOG_LEVEL != silent`：stdin→`/dev/null`，stdout→原 stdout，stderr→原 stderr。
- 若 `LOG_LEVEL == silent`：三者全部重定向到 `/dev/null`。
这保证了后台模式下不会意外产生输出。

### 3.5 使用约定
- 设备层（`device/device.go`、`device/noise-protocol.go` 等）统一通过 `device.log.Verbosef / device.log.Errorf` 输出，不直接使用 `fmt.Println` 或 `log.Print`。
- 非设备层（如 `conn/winrio`）因属于平台绑定层且仅用于一次性诊断，直接使用标准库 `log.Printf`。
- 测试中通过传入 `LogLevelError` 或 `LogLevelSilent` 来抑制日志干扰断言。

## 4. 约定与约束

- **无结构化字段**：日志是纯文本 Printf 风格，不包含 JSON、KV 对或结构化字段；上下文（如接口名）通过 `prepend` 参数拼入前缀。
- **无全局 logger**：每个 `Device` 持有自己的 `*Logger`，通过构造函数注入，避免全局状态。
- **并发安全要求**：`Logger` 的方法注释明确标注必须线程安全，当前实现委托给标准库 `log`，天然满足。
- **级别开关通过环境变量**：`LOG_LEVEL` 是唯一配置项，取值限定为 `verbose/debug/error/silent`，其他值回退到 `LogLevelError`。
- **Daemon 模式输出受控**：后台进程仅在 `LOG_LEVEL != silent` 时保留 stdout/stderr，否则全量重定向到 `/dev/null`。
- **Windows 绑定层例外**：`conn/winrio/rio_windows.go` 使用标准 `log.Printf` 而非 `device.Logger`，因为该代码路径仅在 Registered I/O 不可用时作为降级诊断输出，不属于设备运行期主路径。

## 5. 总结

这是一个极简、内嵌于 `device` 包的分级日志子系统：仅支持 DEBUG/ERROR/SILENT 三级，输出到 stdout，格式固定，通过环境变量控制级别，并通过依赖注入的方式将 logger 传给 Device。它不追求结构化、不引入外部依赖，符合 wireguard-go 整体“最小化、可移植”的设计哲学。