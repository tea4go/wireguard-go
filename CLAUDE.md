# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 开发命令

项目要求 Go 1.23.1 或更高版本。

```bash
# 生成基于 git describe 的 version.go 并构建当前平台二进制
make

# 仅构建，不更新版本字符串
go build ./...

# 运行全部测试；make test 等价于此命令
go test ./...

# 运行单个 package
go test ./device

# 运行单个测试
go test ./device -run '^TestAllowedIPs$'

# 启用竞态检测
go test -race ./...

# 格式化改动的 Go 文件
gofmt -w path/to/file.go

# 检查 gofmt；根 package 的 TestFormatting 会递归检查所有 Go 文件
go test . -run '^TestFormatting$'
```

Makefile 没有独立 lint 目标；不要声称仓库配置了额外 linter。`make` 会改写 `version.go`，并将其标记为 `assume-unchanged`；需要排查版本生成问题时留意这一点。

## 架构概览

这是 WireGuard 的跨平台 Go userspace 实现。根目录的 `main.go`（Unix）和 `main_windows.go`（Windows）负责创建 TUN、UDP bind 和 UAPI listener，然后把配置连接交给 `device.Device`。Unix 入口还负责前后台运行及继承 TUN/UAPI 文件描述符；Windows 入口主要用于调试，正式 Windows 客户端将本仓库作为模块使用。

### 核心边界

- `tun.Device` 是虚拟网卡抽象；`tun/tun_*.go` 提供各平台实现，`tun/netstack` 提供基于 gVisor 的用户态网络栈适配。
- `conn.Bind` 是 UDP 传输抽象；`conn` 包处理 IPv4/IPv6 socket、endpoint、批处理，以及 Linux GSO/GRO、fwmark、路由变化等平台能力。
- `ipc` 包创建平台控制端点（Unix socket 或 Windows named pipe）；`device/uapi.go` 解析 WireGuard cross-platform UAPI 的 `get=1` / `set=1` 协议并更新 Device、Peer、endpoint 和 AllowedIPs。
- `device.Device` 聚合 TUN、Bind、peer 表、密钥索引、AllowedIPs、握手限速、对象池和全局工作队列；其状态机只有 down、up、closed，关闭时必须先停止 peer，再关闭共享队列。

### 数据路径与并发模型

发送路径位于 `device/send.go`：TUN 批量读取 → 按目标地址通过 AllowedIPs 选择 peer → 无可用会话时暂存并触发握手 → 为每个 peer 顺序分配 nonce → 全局 worker 并行加密 → 每个 peer 的 sequential sender 保序并经 `conn.Bind` 批量发送。

接收路径位于 `device/receive.go`：Bind 的接收 goroutine 按消息类型分流 → 握手消息进入全局 handshake worker → transport 消息按 receiver index 找到 keypair/peer → 全局 worker 并行解密 → 每个 peer 的 sequential receiver 做 replay 检查、源地址 AllowedIPs 校验和 endpoint roaming 更新 → 写回 TUN。

队列容器的 mutex 是阶段屏障：顺序消费者先拿锁，parallel worker 完成加解密后解锁，从而兼顾并行计算与每 peer 有序提交。修改队列、WaitGroup、Peer Start/Stop 或 Device Close 时，必须保持生产者引用计数和关闭顺序一致，避免向已关闭队列写入或阻塞退出。

### 协议与路由状态

- `device/noise-protocol.go` 实现 Noise_IKpsk2 握手状态机、消息编解码、会话密钥派生及 current/previous/next keypair 轮换；`cookie.go` 与 `ratelimiter` 负责负载下的 MAC2 cookie 和握手限速。
- `device/allowedips.go` 使用独立的 IPv4/IPv6 压缩前缀 trie 做最长前缀匹配。发送时用目标地址选择 peer；接收时用源地址确认数据确实属于该 peer，因此更改它同时影响路由和反欺骗校验。
- `device/timers.go` 管理握手重传、keepalive、重协商和密钥清零；数据路径中的 authenticated packet/data 事件会驱动这些定时器。
- `device/indexTable` 把握手或 transport receiver index 映射到 peer/keypair；会话建立时会把握手索引原子地替换为 keypair 索引。

## 平台与测试注意事项

平台差异主要通过 build tags 和 `*_GOOS.go` 文件隔离。改动 `tun`、`conn`、`ipc` 或入口代码时，应检查对应平台文件与接口契约，而不是假定 Unix 行为适用于 Windows。涉及并发数据路径时，除目标 package 测试外应运行 `go test -race ./...`；涉及格式时运行根 package 的 `TestFormatting`。
