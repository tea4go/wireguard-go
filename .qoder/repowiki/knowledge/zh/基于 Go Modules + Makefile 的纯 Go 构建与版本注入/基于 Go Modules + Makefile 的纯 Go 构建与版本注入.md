---
kind: build_system
name: 基于 Go Modules + Makefile 的纯 Go 构建与版本注入
category: build_system
scope:
    - '**'
source_files:
    - Makefile
    - go.mod
    - go.sum
    - version.go
    - main.go
    - main_windows.go
    - CLAUDE.md
---

## 1. 使用的构建系统与方法

该项目采用 **Go Modules（go.mod/go.sum）** 作为依赖管理，使用 **GNU Make** 作为顶层构建入口。整个项目是纯 Go 实现（无 C/C++ 代码），因此不需要 CGO；Makefile 中通过 `export GO111MODULE := on` 显式启用模块模式，并直接调用 `go build -v -o wireguard-go` 生成单一可执行文件。

## 2. 关键文件

- `Makefile`：顶层构建目标，定义 `all`、`wireguard-go`、`install`、`test`、`clean` 等目标。
- `go.mod`：声明 module 路径为 `golang.zx2c4.com/wireguard`，要求 Go 1.23.1，列出所有直接/间接依赖（`golang.org/x/crypto`、`golang.org/x/net`、`golang.org/x/sys`、`gvisor.dev/gvisor`、`golang.zx2c4.com/wintun` 等）。
- `version.go`：由构建过程自动生成，包含 `const Version = "..."`，被 `main.go` 在启动时打印。
- `main.go` / `main_windows.go`：平台入口，读取 `Version` 常量输出帮助信息。
- `CLAUDE.md`：文档说明跨平台差异通过 build tags 和 `_GOOS.go` 文件隔离，并发测试需加 `-race`，格式检查走根 package 的 `TestFormatting`。

## 3. 架构与约定

### 3.1 版本注入流程
`make all` → `generate-version-and-build` 目标会：
1. 通过 `git describe --dirty` 获取 Git tag（含 dirty 标记）。
2. 用 `printf 'package main\n\nconst Version = "%s"\n' "$tag"` 动态生成 `version.go`。
3. 如果生成的内容与现有 `version.go` 不同则覆盖写入，并通过 `git update-index --assume-unchanged version.go` 让 git 忽略该文件的后续变更。
4. 最后递归调用 `$(MAKE) wireguard-go` 执行编译。

这意味着二进制中的版本号始终来源于 Git tag，且不会被开发者手动修改——它是构建产物的一部分。

### 3.2 交叉编译
Makefile 本身没有内置交叉编译规则，但因为是纯 Go 项目，遵循 Go 标准做法：设置 `GOOS` / `GOARCH` 环境变量后直接运行 `go build` 即可生成对应平台的二进制。项目中大量使用 `runtime.GOOS` 分支（如 `conn/bind_std.go`、`device/queueconstants_*_*.go`、`tun/tun_*_*.go`、`ipc/uapi_*_*.go`）以及同名后缀文件（`*_linux.go`、`*_windows.go`、`*_default.go`、`*_unix.go`）来隔离平台差异，这是 Go 社区标准的 build-tag 替代方案（按文件名后缀选择编译单元）。

### 3.3 安装与测试
- `make install`：将 `wireguard-go` 安装到 `$(PREFIX)/bin`（默认 `/usr/bin`），可通过 `DESTDIR` 做 staging 安装。
- `make test`：执行 `go test ./...`，覆盖全部子包。
- `make clean`：仅删除 `wireguard-go` 二进制。

## 4. 约定与约束

- **Go 版本锁定**：`go.mod` 顶部固定 `go 1.23.1`，构建必须使用该版本或兼容版本。
- **依赖锁定**：所有第三方依赖通过 `go.sum` 锁定精确版本，不允许浮动依赖。
- **版本来源唯一**：`version.go` 不得手工编辑；它由 `git describe` 结果生成并被 `--assume-unchanged` 标记，防止意外提交。
- **平台隔离方式**：不使用显式 `// +build` 标签，而是通过文件名后缀（`_linux.go`、`_windows.go`、`_default.go`、`_unix.go`、`_android.go`、`_ios.go`、`_bsd.go`、`_wasm.go`）让 Go 编译器自动选择编译单元，接口契约在各文件中保持一致。
- **CGO 禁用**：Makefile 未设置 `CGO_ENABLED`，结合项目无 C 源码的事实，构建默认以纯 Go 模式进行，便于容器化与静态链接。
- **CI/发布脚本**：仓库根目录未发现 `.github/workflows`、`.circleci`、`Dockerfile`、`build*.sh` 等 CI 或打包脚本；这些可能位于父仓库（Makefile 中 `GIT_CEILING_DIRECTORIES` 指向 `$(CURDIR)/..` 即上游仓库）。本仓库仅提供基础构建目标，完整流水线由外部维护。
- **测试约定**：并发相关改动需额外运行 `go test -race ./...`；格式化检查通过根 package 的 `TestFormatting` 完成（见 `format_test.go` 与 `CLAUDE.md` 说明）。

## 5. 总结

这是一个极简的 Go 项目构建体系：一个 Makefile 负责版本注入与调用 `go build`，`go.mod` 锁定语言与依赖版本，平台差异通过 Go 的文件名后缀机制自然分发。构建产物是单一静态可执行文件 `wireguard-go`，适合嵌入到更大的发布流程中（由父仓库的 CI 负责交叉编译与打包）。