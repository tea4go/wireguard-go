# buildapp.ps1 双参数构建实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 subagent-driven-development（推荐）或 executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 让 `buildapp.ps1` 通过两个参数控制目标操作系统和架构，默认构建 `windows/amd64`。

**架构：** 保留现有版本号、`ldflags`、本地 Go 缓存和构建日志逻辑，只在脚本入口增加参数解析，并把 `GOOS/GOARCH` 与输出文件名统一收敛到一个平台映射分支。Windows 继续生成 `.exe`，Linux/macOS 生成无扩展名二进制。

**技术栈：** PowerShell 5.1、Go toolchain、现有仓库构建约定

---

### 任务 1：参数化目标平台

**文件：**
- 修改：`buildapp.ps1`

- [ ] **步骤 1：添加脚本参数**

在 `param()` 中增加：

```powershell
[ValidateSet('windows', 'linux', 'macos')]
[string]$OS = 'windows',

[ValidateSet('amd64', 'arm64')]
[string]$Arch = 'amd64'
```

- [ ] **步骤 2：把平台参数映射为 Go 目标**

在构建前根据 `$OS` 解析 `$TargetGOOS`，其中 `macos -> darwin`，并生成输出文件名：

```powershell
switch ($OS) {
    'windows' { $TargetGOOS = 'windows'; $OUT_BIN_NAME = 'wireguard.exe' }
    'linux'   { $TargetGOOS = 'linux';   $OUT_BIN_NAME = 'wireguard-go' }
    'macos'   { $TargetGOOS = 'darwin';  $OUT_BIN_NAME = 'wireguard-go' }
}
```

- [ ] **步骤 3：更新构建与展示信息**

把 banner 中的目标平台改为参数值，把输出路径改为新的 `$OUT_BIN_NAME`，并在 `go build` 前临时设置：

```powershell
$env:GOOS = $TargetGOOS
$env:GOARCH = $Arch
```

- [ ] **步骤 4：保留仅 Windows 的运行逻辑**

仅当 `$OS -eq 'windows'` 时执行旧的停止进程、管理员提权和运行二进制逻辑；Linux/macOS 目标构建完成后直接退出。

### 任务 2：验证默认值和跨平台参数

**文件：**
- 修改：`buildapp.ps1`
- 测试：命令行手工验证

- [ ] **步骤 1：验证默认 Windows 构建**

运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\buildapp.ps1
```

预期：脚本显示目标平台为 `windows/amd64`，并生成 `wireguard.exe`。

- [ ] **步骤 2：验证 Linux 参数构建**

运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\buildapp.ps1 -OS linux -Arch amd64
```

预期：脚本显示目标平台为 `linux/amd64`，并生成 `wireguard-go`，且不尝试提权运行。

- [ ] **步骤 3：验证 macOS 参数构建**

运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\buildapp.ps1 -OS macos -Arch arm64
```

预期：脚本显示目标平台为 `macos/arm64`，内部使用 `GOOS=darwin`，并生成 `wireguard-go`，且不尝试运行。
