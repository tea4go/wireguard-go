---
kind: dependency_management
name: Go 模块依赖管理（go.mod/go.sum + 私有仓库版本锁定）
category: dependency_management
scope:
    - '**'
source_files:
    - go.mod
    - go.sum
---

## 1. 使用的系统/方法

本项目采用 Go Modules 作为唯一的依赖管理机制，通过根目录的 `go.mod` 声明模块名与直接依赖，通过 `go.sum` 锁定每个依赖的精确哈希值。未使用 vendor 目录、GOPATH 模式或第三方包管理器。

## 2. 关键文件

- `go.mod`：定义模块 `golang.zx2c4.com/wireguard`，指定 Go 版本 `1.23.1`，并列出全部直接依赖与间接依赖。
- `go.sum`：为每个依赖记录源码压缩包与 go.mod 的 SHA256 校验和，用于构建时完整性验证。

## 3. 架构与约定

### 3.1 依赖范围极小且稳定
项目仅引入两类依赖：
- **官方 x 系列库**：`golang.org/x/crypto`（密码学原语）、`golang.org/x/net`（网络工具）、`golang.org/x/sys`（操作系统 syscall 封装）、`golang.org/x/time`（时间工具，间接依赖）。
- **zx2c4 自持库**：`golang.zx2c4.com/wintun`（Windows TUN 驱动桥接），由同一作者维护，便于快速迭代。
- **可选内核栈**：`gvisor.dev/gvisor` 以 commit hash 形式引入，用于内置纯 Go 网络协议栈（tun/netstack），仅在特定平台/构建标签下启用。

所有依赖均为单一来源、无重复版本冲突，体现“最小依赖集”的设计原则。

### 3.2 版本锁定策略
- 直接依赖使用语义化版本号（如 `v0.37.0`、`v0.39.0`、`v0.32.0`），便于在官方发布周期内升级。
- `wintun` 与 `gvisor` 使用 `v0.0.0-YYYYMMDDHHMMSS-<commit>` 形式的 pseudo-version，指向具体 git commit，确保可重现构建，同时避免上游发布节奏带来的不可控变更。
- `go.sum` 中每个依赖均包含 `h1:` 源码哈希与 `/go.mod` 哈希双重校验，禁止任何未经 `go mod verify` 通过的替换。

### 3.3 间接依赖管理
`github.com/google/btree` 作为 `gvisor` 的间接依赖被自动纳入，但标记为 `// indirect`，表明它不是本项目的直接 API 使用者，仅随传递依赖出现。

### 3.4 无私有仓库/GOPRIVATE 配置
仓库中未发现 `.gitignore`、`.env`、`Makefile` 或 CI 脚本中对 `GOPRIVATE`、`GONOSUMDB`、`GONOPROXY` 或自定义 GOPROXY 的配置。这意味着依赖拉取完全走公共 Go Proxy / 直连 golang.org 与 github.com 等公开源。

### 3.5 无 vendoring
根目录不存在 `vendor/` 文件夹，也不存在任何 `go mod vendor` 相关脚本。构建产物依赖外部下载，适合容器镜像或 CI 缓存场景。

## 4. 约定与约束

- **Go 版本约束**：`go.mod` 顶部固定 `go 1.23.1`，要求构建环境与 CI 使用该版本或兼容版本。
- **依赖最小化**：仅引入 WireGuard 实现所必需的系统调用、加密算法和网络抽象，不引入通用框架。
- **可重现构建**：通过 `go.sum` 锁定到具体哈希，配合 pseudo-version 的 commit 级依赖，保证任意时间重建得到相同二进制。
- **升级流程**：应通过 `go get -u ./...` 或 `go mod tidy` 更新依赖，随后提交新的 `go.mod`/`go.sum`；对 `wintun`、`gvisor` 这类 pseudo-version 依赖需显式指定目标 commit 后再运行 `go mod tidy`。
- **安全校验**：CI 或本地构建前应执行 `go mod verify`，确保 `go.sum` 与实际下载内容一致。

## 5. 置信度

high — 仓库采用标准 Go Modules 方案，`go.mod`/`go.sum` 完整且清晰，依赖数量少、版本策略明确，证据充分。