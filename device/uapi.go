/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tea4go/gh/utils"
	"golang.zx2c4.com/wireguard/ipc"
)

// IPCError 是 WireGuard UAPI（用户空间 API）返回的结构化错误类型。
// 同时携带 WireGuard 规范的数字错误码（对应 ipc.IpcErrorXXX 常量）与底层 Go error。
// 通过支持 errors.As / errors.Is 可以进行错误分类、链检查（unwrap）。
type IPCError struct {
	code int64 // UAPI 规范定义的数字错误码（0表示成功）
	err  error // 底层/被包装的实际错误
}

// Error 实现 Go error 接口，按 WireGuard UAPI 约定的统一格式输出："IPC error N: 原因。
func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

// Unwrap 支持 Go 1.13+ 错误链支持，允许 errors.Is / errors.As 穿透到包装的底层错误。
func (s IPCError) Unwrap() error {
	return s.err
}

// ErrorCode 返回该 UAPI 错误对应的数字错误码（0表示成功，其它值见 ipc 包常量）。
func (s IPCError) ErrorCode() int64 {
	return s.code
}

// ipcErrorf 以格式化方式构造一个带错误码的 IPCError。
// 所有 UAPI（设置/查询 失败的统一出口都走该函数。
func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

// byteBufferPool 复用 bytes.Buffer 以减少 IPC Get 操作时的内存分配。
var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation 实现 WireGuard 跨平台配置协议的 "get" 操作，
// 将当前 Device 的完整运行时状态（私钥/监听端口/fwmark/所有 Peer/AllowedIPs 等）按
// 以 "key=value\n" 行格式序列化为文本并写入 w。
// 协议规范见：https://www.wireguard.com/xplatform/#configuration-protocol
func (device *Device) IpcGetOperation(w io.Writer) error {
	// 以读锁保护：防止 get 期间并发的并发修改（ipcMutex.RLock 与 IpcSetOperation 互斥）
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	// 从复用池中获取 bytes.Buffer，序列化完毕后整块写回 io.Writer
	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	// sendf 为辅助：写一行 "key=value"
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	// keyf 为辅助：写一行十六进制密钥字段（64 个十六进制字符的32字节密钥），避免一次 hex.Encode 分配
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		// 逐字节转十六进制（无需临时分配内存）
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	// 闭包内集中拿所需所有读锁，锁的目的：
	// 序列化时一次性拿快照，完成后释放避免长时间锁
	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values
		// 先写设备级字段（未配置过的字段跳过）：零值表示未设置）

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		// 逐个写 Peer 状态
		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			// 先写远程静态公钥与预共享密钥（需 handshake 读锁）
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			// 扩展字段：Peer（name（WireGuard Go 实现的扩展）
			if peer.Name != "" {
				sendf("name=%s", peer.Name)
			}
			sendf("protocol_version=1")
			// 写端点（按 host:port 字符串
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
			}
			peer.endpoint.Unlock()

			// 上次握手时间拆分为秒+纳秒
			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval.Load())

			// 遍历 AllowedIPs 表中本 Peer 的所有前缀
			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	// 锁释放后再整块写回（io.Writer 可能慢，不持有锁写回用户）
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output, %w", err)
	}

	return nil
}

// IpcSetOperation 实现 WireGuard 跨平台配置协议的 "set" 操作。
// 从 r 逐行读取 "key=value\n" 指令，按顺序修改 Device 与 Peer 的配置。
// 语法规则：
//   - 空行表示结束本次 set 操作；
//   - 遇到 "public_key=..." 切到 Peer 级配置（此前是 device 级），
//     且在切到下一个 public_key 或结束前都是该 Peer 的配置。
//
// 见 https://www.wireguard.com/xplatform/#configuration-protocol
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	// 写锁：与 IpcGetOperation/其他 set 互斥，保证一次 set 的整体一致性
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("UAPI 设置操作失败, %v", err)
		}
	}()

	// 当前正在处理的 Peer 上下文
	peer := new(ipcSetPeer)
	// deviceConfig 为 true 表示当前正在解析 device 级字段；首个 public_key 出现后切为 false
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			// 空行：结束本次 set 操作前应用最后一个 Peer 上待启动（若启动 Peer 未启动则 Start）
			peer.handlePostConfig()
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			// public_key 是 Peer 段开始
			if deviceConfig {
				deviceConfig = false
			}
			// 切换 Peer 前先应用上一个 Peer 的后处理（启动等）
			peer.handlePostConfig()
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			// 仍在 device 级（尚未出现任何 public_key 前）处理 device 字段
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	peer.handlePostConfig()

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input, %w", err)
	}
	return nil
}

// handleDeviceLine 处理 set 操作中 device 级的一行 key=value（尚未出现过任何 public_key 前）。
// 支持：private_key / listen_port / fwmark / replace_peers。
func (device *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		// ：64 字符十六进制，可接受全 0 表示清空私钥（FromMaybeZeroHex 处理清空）
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key, %w", err)
		}
		device.log.Debug("UAPI：正在更新私钥 (%s)", utils.GetShowKey(hex.EncodeToString(sk[:])))
		// 重量级操作：会移除与自己冲突的 Peer、重新 DH 预共享、所有 Peer 失效当前 keypairs
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port, %w", err)
		}

		// update port and rebind
		device.log.Debug("UAPI：正在更新监听端口 (%d)", port)

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		// 立即应用新端口：（关闭旧+开新）
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port, %w", err)
		}

	case "fwmark":
		// 防火墙标记，用于策略路由（SO_MARK）
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark, %w", err)
		}

		device.log.Debug("UAPI：正在更新 fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark, %w", err)
		}

	case "replace_peers":
		// replace_peers=true 为 "set 操作语义：先移除全部 Peer，接下来的 public_key 表示全新 Peer 列表（wg setconf（）
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
		device.log.Debug("UAPI：正在移除所有对端")
		device.RemoveAllPeers()

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// ipcSetPeer 是一次 IpcSetOperation 调用期间对单个 Peer 的配置过程上下文（工作状态。
// 每遇到一个 public_key 就新建一个该结构，用于跟踪是否新创建、是否 dummy（不实际存在 Peer 等临时状态，
// handlePostConfig 在 Peer配置段落结束后应用（启动 Peer、打日志）。
type ipcSetPeer struct {
	*Peer                   // 当前操作的 Peer（可能为 dummy Peer 表示不操作）
	dummy              bool // dummy 为 true 表示 Peer.Peer 是占位 Peer{}空壳，不实际操作（例如公钥等于设备自己的公钥（自己，或者 update_only=true 时未找到时）
	created            bool // 为 true 表示该 Peer 是本次 set 中刚创建的（而不是已有）
	pkaOn              bool // 为 true 表示本次 set 中刚把持久保活从 0→ 切为非 0（启动后需要立即发送一次保活
	pendingCreationLog bool // 延迟到 name 时打 created log 时打了后打一条创建成功的 Notice 日志（若无 name，则 handlePostConfig 打）
}

// handlePostConfig 在一个 Peer 配置段落结束（下一个 public_key 出现、或空行结束 set、结束执行。
// 责任：
//   - 打创建成功 Notice 日志
//   - 新创建设备 brokenRoaming 标记 disableRoaming（
//   - 设备 up 启动 Peer（持久保活则立即发一次保活、并推入 staged 队列发送
func (peer *ipcSetPeer) handlePostConfig() {
	if peer.Peer == nil || peer.dummy {
		return
	}
	if peer.pendingCreationLog {
		peer.device.log.Notice("%v - UAPI：已创建", peer.Peer)
		peer.pendingCreationLog = false
	}
	// 新建 Peer brokenRoaming：若系统标记网络漫游 broken（某些平台），且已有固定 endpoint，则禁用自动漫游 endpoint 学习 disabled（禁止内核根据入包根据入站）
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	// 设备在运行态启动 Peer（协程（可能尚未 Start）
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			// 刚开持久保活立即发一包保活打通隧道
			peer.SendKeepalive()
		}
		// 唤醒 staged 队列（若配置 AllowedIP 流量前就可以先启动发送（
		peer.SendStagedPackets()
	}
}

// handlePublicKeyLine 处理 set 操作中 "public_key=xxx" 行：
//   - 解析 64 十六进制公钥；
//   - 若是 Device 自己公钥 dummy（禁止作为 Peer（ dummy；
//   - 不存在就查找现有 Peer，没有时创建新 Peer 记下 created 标志。
func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key, %w", err)
	}

	// Ignore peer with the same public key as this device.
	// WireGuard 协议：不允许公钥，这会引发 DH 自己公钥作为 remoteStatic
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		// 占位空壳：后续所有 Peer 字段（skip）
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	// created ：不存在则创建（）
	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer, %w", err)
		}
		// 延迟打创建日志（怕 name 行还到来时打日志 含有 name 更友好日志）
		peer.pendingCreationLog = true
	}
	return nil
}

// handlePeerLine 处理 set 操作中 Peer 级的一行 key=value（当前已处于某个 public_key 的上下文）。
// 支持字段：update_only / remove / preshared_key / name / endpoint / persistent_keepalive_interval /
// replace_allowed_ips / allowed_ip / protocol_version。
func (device *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		// update_only=true：语义仅修改已有 Peer（没有找到则本次创建，把新创建的则 移除并打 dummy（update_only=true 未找到时不要创建新 Peer）
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		// 本次公钥不存在就刚创建（created=true&!dummy 意味着刚创建的新）：移除并 dummy 化
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		// remove=true：从 Device 中删除当前 Peer
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Notice("%v - UAPI：正在移除", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Debug("%v - UAPI：正在更新预共享密钥", peer.Peer)

		// PSK（32字节：PSK（）
		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key, %w", err)
		}

	case "name":
		// 扩展 Peer.Name 字段（wg(非 WireGuard 官方协议，仅 Go 实现的扩展）
		peer.Name = value
		// 有 name 先打创建日志（没有 name 时打创建日志更可读）
		if peer.pendingCreationLog {
			device.log.Notice("%v - UAPI：已创建", peer.Peer)
			peer.pendingCreationLog = false
		}
		device.log.Debug("%v - UAPI：正在更新名称", peer.Peer)

	case "endpoint":
		device.log.Debug("%v - UAPI：正在更新端点", peer.Peer)
		// 字符串 host:port（DNS 解析等由 bind.ParseEndpoint 做）
		endpoint, err := device.net.bind.ParseEndpoint(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v, %w", value, err)
		}
		peer.endpoint.Lock()
		defer peer.endpoint.Unlock()
		peer.endpoint.val = endpoint

	case "persistent_keepalive_interval":
		// 持久保活间隔（秒）0 表示关闭（wg-quick PersistentKeepalive = 常用 25sNAT 常用
		device.log.Debug("%v - UAPI：正在更新保活", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval, %w", err)
		}

		// 原子更新值 Swap 返回旧值
		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		// 刚切为 true：0→非 0（表示刚打开保活 handlePostConfig 启动后立即发一次包
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		// replace_allowed_ips=true：语义清空当前 Peer（替换 AllowedIPs，接下来一行行追加（行 allowed_ip（setconf）
		device.log.Debug("%v - UAPI：正在移除所有 allowed_ip", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		// 单条 AllowedIP 前缀：无前缀表示添加；"-" 前缀表示删除（如 "192.168.0.0/24" 为添加，"-10.0.0.0/8" 为删除）
		add := true
		verb := "添加"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "移除"
			value = value[1:]
		}
		device.log.Debug("%v - UAPI：正在%s allowed_ip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip, %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		// 仅版本 1（当前 IKpsk2 仅实现版本 1）
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

// IpcGet 是 IpcGetOperation 的便捷封装，返回字符串形式的包装（方便测试/调试）。
func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// IpcSet 是 IpcSetOperation 的字符串便捷包装（传入 uapiConf 字符串形式的 set 指令集）。
func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

// IpcHandle 通过 Unix socket/命名管道 句柄句柄一次 UAPI 连接的连接循环。
// WireGuard 规范：每个连接循环读取一行 "get=1\n" / "set=1\n" 操作指令，
// 调用对应的 IpcGetOperation / IpcSetOperation，执行后回写 "errno=N\n\n" 状态行。
func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	// 用带缓冲的读写器：读写 Reader 提升性能
	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		// 读取操作行 "get=1\n" 或 "set=1\n"
		op, err := buffered.ReadString('\n')
		if err != nil {
			// 对端关闭连接或 IO 错误：退出循环
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			// set：接下来多行 key=value，直到空行结束（由 IpcSetOperation 内部消耗剩余字节）
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			// get：按协议 get 行必须紧接着一个空行（下一个字节必须 '\n'）
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			// 写序列化后的 get 结果到写缓冲
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("无效的 UAPI 操作, %v", op)
			return
		}

		// write status
		// 将 err 转换为 IPCError（若尚未是）
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			// 所有内部路径返回错误应包装 IPCError
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error, %w", err)
		}
		if status != nil {
			device.log.Errorf("UAPI 操作返回错误状态, %v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}
