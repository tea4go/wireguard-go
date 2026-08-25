# Errors

Command failures and integration errors.

---

## [ERR-20260825-001] exec_command

**Logged**: 2026-08-25T00:00:00+08:00
**Priority**: low
**Status**: resolved
**Area**: backend

### Summary

读取 Go 模块源码时使用了未设置的 `$env:GOPATH`，导致模块路径被错误解析到 `C:\pkg\mod`。

### Error

```text
Cannot find path 'C:\pkg\mod\golang.org\x\sys@v0.32.0\unix\...'
```

### Context

- 为 Linux netlink 和 macOS route socket 解析器核对 `x/sys/unix` 常量及结构布局。
- `go env GOMODCACHE` 实际返回 `C:\Users\Admin\go\pkg\mod`。

### Suggested Fix

构造 Go 模块源码路径时使用 `go env GOMODCACHE` 的绝对结果，不依赖当前 PowerShell 是否导出了 `$env:GOPATH`。

### Metadata

- Reproducible: yes
- Related Files: go.mod

### Resolution

- **Resolved**: 2026-08-25T00:00:00+08:00
- **Notes**: 改用 `C:\Users\Admin\go\pkg\mod` 后成功读取目标常量和结构定义。

---

## [ERR-20260823-006] inspect-build-artifact

**Logged**: 2026-08-23T15:50:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

检查 Wintun 部署目录时假定根目录存在 `wireguard-go.exe`，但当前工作区没有该构建产物。

### Error

```text
Cannot find path 'wireguard-go.exe' because it does not exist.
```

### Context

- 目标是确认 `wintun.dll` 是否已随可执行文件部署。
- 源码和 Go 绑定检查不依赖现有 EXE。

### Suggested Fix

检查可选构建产物前先使用 `Test-Path`，不存在时提示需要构建。

### Metadata

- Reproducible: yes
- Related Files: wireguard-go.exe

### Resolution

- **Resolved**: 2026-08-23T15:50:00+08:00
- **Notes**: 改为在教程中提供构建和部署步骤。

---

## [ERR-20260823-005] git-diff-check

**Logged**: 2026-08-23T15:40:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

Markdown 头部使用双空格换行，未通过 `git diff --cached --check`。

### Error

```text
trailing whitespace
```

### Context

- 三份报告的日期、分析对象和对标对象行末包含两个空格。

### Suggested Fix

提交前运行暂存区空白检查，并避免使用行末双空格换行。

### Metadata

- Reproducible: yes
- Related Files: docs/

### Resolution

- **Resolved**: 2026-08-23T15:40:00+08:00
- **Notes**: 已移除九处行末空格。

---

## [ERR-20260823-004] git-add

**Logged**: 2026-08-23T15:35:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

沙箱只读挂载 `.git`，首次 `git add` 无法创建索引锁。

### Error

```text
fatal: Unable to create '.git/index.lock': Permission denied
```

### Context

- 用户要求提交并推送三份分析报告。
- 工作区文件可写，但 Git 元数据需要提升权限。

### Suggested Fix

对需要写入 `.git` 的 `git add`、`git commit` 和 `git push` 使用授权执行。

### Metadata

- Reproducible: yes
- Related Files: .git/index

### Resolution

- **Resolved**: 2026-08-23T15:35:00+08:00
- **Notes**: 授权后成功暂存三份报告。

---

## [ERR-20260823-003] rg

**Logged**: 2026-08-23T15:25:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

使用 `rg` 验证“不存在禁用模式”时，零匹配返回退出码 1，被工具显示为失败。

### Error

```text
Process exited with code 1
```

### Context

- 检查报告中是否残留 GUI 等需求。
- 零匹配正是期望结果。

### Suggested Fix

否定检查应显式将 `rg` 的退出码 1 转换为成功，并输出“无匹配”。

### Metadata

- Reproducible: yes
- Related Files: docs/

### Resolution

- **Resolved**: 2026-08-23T15:25:00+08:00
- **Notes**: 使用 PowerShell 检查 `$LASTEXITCODE` 并规范化退出码。

---

## [ERR-20260823-002] exec_command

**Logged**: 2026-08-23T15:15:00+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

分析 Linux 平台文件时引用了不存在的 `conn/bind_linux.go`。

### Error

```text
Cannot find path 'conn\bind_linux.go' because it does not exist.
```

### Context

- 并行读取 macOS 和 Linux 平台实现。
- Linux UDP 批处理位于 `conn/bind_std.go`，平台特有逻辑分布在 `conn/*_linux.go`。

### Suggested Fix

先使用 `rg --files conn` 确认平台文件名，再读取实际文件。

### Metadata

- Reproducible: yes
- Related Files: conn/

### Resolution

- **Resolved**: 2026-08-23T15:15:00+08:00
- **Notes**: 后续改用文件清单和模式搜索定位 Linux 实现。

---

## [ERR-20260823-001] apply_patch

**Logged**: 2026-08-23T15:08:31+08:00
**Priority**: low
**Status**: resolved
**Area**: docs

### Summary

同一补丁不能先删除文件再以相同路径重新添加。

### Error

```text
apply_patch verification failed: invalid patch: multiple operations target the same file
```

### Context

- 尝试整体重写现有 Markdown 报告。
- 在一个补丁中同时使用 Delete File 和 Add File，并指向同一路径。

### Suggested Fix

使用两个独立补丁，先删除旧文件，再添加新文件。

### Metadata

- Reproducible: yes
- Related Files: docs/wireguard-go-replace-wireguard-windows-analysis.md

### Resolution

- **Resolved**: 2026-08-23T15:08:31+08:00
- **Notes**: 改为两个独立补丁操作。

---
