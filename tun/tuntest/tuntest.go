/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// tuntest 包提供了 WireGuard TUN 设备的测试辅助工具
// 包含 ICMPv4 报文构造、校验和计算以及基于通道的内存 TUN 模拟实现
package tuntest

import (
	"encoding/binary"
	"io"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// Ping 构造一个 ICMPv4 Echo Request (Ping) 报文
// 参数:
//   - dst: 目标 IP 地址
//   - src: 源 IP 地址
//
// 实现细节:
//   - 默认使用本地端口 1337 作为标识，序列号 seq=0
//   - 将 4 字节的 payload (2字节端口 + 2字节序列号) 打包进 ICMPv4 数据部分
//   - 调用 genICMPv4 完成完整的 IPv4 + ICMPv4 报文封装
func Ping(dst, src netip.Addr) []byte {
	localPort := uint16(1337) // 自定义标识端口，默认 1337
	seq := uint16(0)          // ICMP 序列号，默认 0

	// 构造 4 字节的 ICMP payload: [端口(大端2B)][序列号(大端2B)]
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:], localPort)
	binary.BigEndian.PutUint16(payload[2:], seq)

	return genICMPv4(payload, dst, src)
}

// checksum 实现 RFC 1071 定义的"因特网校验和"算法
// 参考: https://tools.ietf.org/html/rfc1071
//
// 参数:
//   - buf: 需要计算校验和的字节切片
//   - initial: 累加器初始值（用于链式计算，如分段校验和）
//
// 算法步骤（朴素参考实现）:
//  1. 以 16 位为单位（大端字节序）对 buf 进行累加，结果存入 32 位变量 v
//  2. 如果 buf 长度为奇数，将最后一个字节作为高位（左移 8 位）填充进 16 位后累加
//  3. 对累加结果反复进行"折叠进位"：将高 16 位与低 16 位相加，直到结果不超过 0xFFFF
//  4. 对最终 16 位结果按位取反，得到校验和
//
// 注意: RFC1071 校验和用于 IP、ICMP、UDP、TCP 等多种网络协议头
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial) // 使用 32 位累加器防止溢出
	// 步骤1: 按 16 位大端序逐字累加
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	// 步骤2: 处理奇数长度尾部，单字节填充至 16 位高位（低字节补零）
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	// 步骤3: 折叠进位 — 将溢出的高 16 位重新加到低 16 位上，直到无进位
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}
	// 步骤4: 按位取反得到最终校验和
	return ^uint16(v)
}

// genICMPv4 生成一个完整的 IPv4 + ICMPv4 Echo 报文
// 参数:
//   - payload: ICMP 载荷数据
//   - dst: 目标 IPv4 地址
//   - src: 源 IPv4 地址
//
// 报文结构 (从低地址到高地址):
//   +---------------------+
//   | IPv4 Header (20B)   |  IHL=5 (5*4=20B), TTL=65, Protocol=1 (ICMP)
//   +---------------------+
//   | ICMPv4 Header (8B)  |  Type=8 (Echo Request) / 0 (Echo Reply), Code=0
//   +---------------------+
//   | ICMP Payload (变长) | 用户数据
//   +---------------------+
//
// 校验和计算顺序（重要，一前一后）:
//  1. 先计算 ICMPv4 校验和（此时 IPv4 头尚未填完，互不影响）
//     ICMP 校验和覆盖范围：ICMP头(8B) + ICMP载荷
//  2. 再计算 IPv4 头校验和（此时 ICMP 部分已就绪）
//     IPv4 头校验和覆盖范围：仅 IPv4 头(20B)
func genICMPv4(payload []byte, dst, src netip.Addr) []byte {
	const (
		icmpv4ProtocolNumber = 1     // IPv4 协议号: 1 = ICMP
		icmpv4Echo           = 8     // ICMPv4 Type: 8 = Echo Request (回显请求)
		icmpv4ChecksumOffset = 2     // ICMP 头中校验和字段的偏移量 (Type=1B, Code=1B, 之后是 Checksum=2B)
		icmpv4Size           = 8     // ICMPv4 头部固定长度: 8 字节
		ipv4Size             = 20    // IPv4 头部固定长度 (IHL=5): 5*4=20 字节
		ipv4TotalLenOffset   = 2     // IPv4 头中 Total Length 字段偏移
		ipv4ChecksumOffset   = 10    // IPv4 头中 Header Checksum 字段偏移
		ttl                  = 65    // Time To Live 存活跳数，默认 65
		headerSize           = ipv4Size + icmpv4Size // 总头长 = IP头 + ICMP头
	)

	// 分配完整报文内存: 头部 + 载荷
	pkt := make([]byte, headerSize+len(payload))

	// 划分切片引用，便于分别操作
	ip := pkt[0:ipv4Size]                 // IPv4 头区域
	icmpv4 := pkt[ipv4Size : ipv4Size+icmpv4Size] // ICMPv4 头区域

	// ========== 先填 ICMPv4 头并计算 ICMP 校验和 ==========
	// ICMPv4 报文格式: https://tools.ietf.org/html/rfc792
	icmpv4[0] = icmpv4Echo // Type = 8 (Echo Request，回显请求)；Reply 时为 0
	icmpv4[1] = 0          // Code = 0 (Echo 的子类型始终为 0)
	// ICMP 校验和计算：先对 payload 计算，再以该结果为初始值对 ICMP 头(前8B)计算
	// checksum 返回的是"累加折叠后的值"，外面再取反才是最终要写入字段的校验和
	chksum := ^checksum(icmpv4, checksum(payload, 0))
	binary.BigEndian.PutUint16(icmpv4[icmpv4ChecksumOffset:], chksum)

	// ========== 再填 IPv4 头并计算 IP 头校验和 ==========
	// IPv4 报文格式: https://tools.ietf.org/html/rfc760 section 3.1
	length := uint16(len(pkt)) // 整个 IP 数据报的总长度（含头）
	// Version(高4位)=4(IPv4)，IHL(低4位)=5(表示头部 5*4=20 字节)
	ip[0] = (4 << 4) | (ipv4Size / 4)
	// Total Length: 16 位大端，总长度
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl                // TTL = 65 跳
	ip[9] = icmpv4ProtocolNumber // Protocol = 1，表示上层协议是 ICMP
	copy(ip[12:], src.AsSlice()) // Source Address (12~15 字节)
	copy(ip[16:], dst.AsSlice()) // Destination Address (16~19 字节)
	// IPv4 头校验和：仅覆盖 IP 头部 20 字节（不包含载荷和 ICMP）
	chksum = ^checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	// 最后拷贝 payload 到报文尾部
	copy(pkt[headerSize:], payload)
	return pkt
}

// ChannelTUN 是一个基于 Go channel 实现的内存 TUN 设备模拟器
// 用于 WireGuard 单元测试，无需真实的操作系统 TUN 设备
//
// 双端通道设计 — 模拟真实 TUN 设备的「入站/出站」双方向数据流：
//   - Inbound  (chan []byte): 入站通道。WireGuard 从 TUN 读取的"要路由出去"的报文会进入此处
//     真实场景：用户态程序 write(TUN fd) → 内核收包 → WireGuard 加密 → 发往网络
//     测试场景：WireGuard.Write() → 报文被送入 Inbound → 测试代码从 Inbound 取出验证
//
//   - Outbound (chan []byte): 出站通道。测试方把要"进入 WireGuard 解封装"的报文推入此处
//     真实场景：网络收包 → WireGuard 解密 → write(TUN fd) → 内核协议栈收包
//     测试场景：测试代码写入 Outbound → WireGuard.Read() 从 Outbound 取出 → 解密处理
type ChannelTUN struct {
	Inbound  chan []byte // 入站报文通道，TUN 关闭时关闭；WireGuard 写入的待路由报文
	Outbound chan []byte // 出站报文通道，TUN 关闭后写入会永久阻塞；供 WireGuard 读取的待处理报文

	closed chan struct{}   // 关闭信号通道，用于广播 TUN 已关闭状态
	events chan tun.Event  // TUN 事件通道（如 Up/Down 等），缓冲 1
	tun    chTun           // 内嵌私有 chTun 结构体，实现 tun.Device 接口
}

// NewChannelTUN 创建并初始化一个新的 ChannelTUN 测试桩
//
// 初始化流程:
//  1. 创建 Inbound、Outbound 无缓冲通道（同步收发）
//  2. 创建 closed 信号通道（用于 close 广播）
//  3. 创建 events 事件通道（缓冲 1）
//  4. 将自身指针赋给 chTun.c，建立反向引用
//  5. 立即向 events 写入 tun.EventUp — 模拟网卡已启用、链路已 UP
//     这是必要的，因为 WireGuard Device 启动时会等待 TUN Up 事件才开始工作
func NewChannelTUN() *ChannelTUN {
	c := &ChannelTUN{
		Inbound:  make(chan []byte),
		Outbound: make(chan []byte),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
	c.tun.c = c       // 反向引用，让内部 chTun 能访问外层 ChannelTUN 的字段
	c.events <- tun.EventUp // 模拟网卡已启用，发出 EventUp 事件
	return c
}

// TUN 返回实现了 tun.Device 接口的内部 chTun 实例
// 这样外部只能拿到接口视图，无法直接访问私有字段
func (c *ChannelTUN) TUN() tun.Device {
	return &c.tun
}

// chTun 是真正实现 tun.Device 接口的私有内嵌结构体
//
// 单独存在的设计原因（封装隔离）：
//   - 避免外部通过 tun.Device 接口向上类型断言后，直接访问 ChannelTUN 的私有字段
//     (如 closed、events 通道和 Inbound/Outbound 的内部状态)
//   - chTun 仅持有一个 *ChannelTUN 指针 c，所有接口方法都通过 c 反向访问外层数据
//   - 这是一种"桥接模式 + 私有封装"的惯用 Go 写法：
//     外层 ChannelTUN 暴露给测试代码用（In/Out channel 可直接读写），
//     内层 chTun 暴露给 WireGuard 用（只暴露 tun.Device 接口方法）
type chTun struct {
	c *ChannelTUN // 反向引用外层 ChannelTUN，访问其通道与状态
}

// File 返回底层操作系统文件描述符，纯内存模拟故返回 nil
func (t *chTun) File() *os.File { return nil }

// Read 实现 tun.Device.Read 接口，供 WireGuard 调用读取"从 TUN 设备收到的报文"
//
// 数据流方向: Outbound 通道 → bufs[0][offset:] → sizes[0]
//
// 参数:
//   - packets: 二维切片，WireGuard 分配好的接收缓冲区数组；当前实现只用到 packets[0]
//   - sizes:   对应每个包的实际长度；sizes[0] 填入本次读取的字节数
//   - offset:  packets[i] 中的起始偏移（VirtIO / GSO / 信息头预留）；数据从 offset 开始写
//
// 行为:
//   - 使用 select 同时监听 closed（关闭信号）和 Outbound（数据到达）
//   - 若 closed 先触发 → 返回 (0, os.ErrClosed) 语义：TUN 已关闭，读取终止
//   - 若 Outbound 有数据 → 从 Outbound 读出 msg，copy 到 packets[0][offset:]，
//     sizes[0] = n（实际拷贝字节数），返回 (1, nil) 表示成功读了 1 个包
func (t *chTun) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.c.closed: // TUN 关闭广播
		return 0, os.ErrClosed
	case msg := <-t.c.Outbound: // 从 Outbound 取出测试方推入的待处理报文
		n := copy(packets[0][offset:], msg) // 按偏移写入 WireGuard 缓冲区
		sizes[0] = n                        // 记录实际长度
		return 1, nil
	}
}

// Write 实现 tun.Device.Write 接口，供 WireGuard 调用向"TUN 设备写入路由报文"
//
// 数据流方向: packets[i][offset:] → 新切片 → Inbound 通道
//
// 参数:
//   - packets: WireGuard 准备写入 TUN 的报文数组
//   - offset:  每个 packet 的起始偏移（跳过头部元数据）
//
// 特殊 Hack: offset == -1 作为关闭信号
//   - 由来: tun.Device 接口没有独立的 Shutdown/Stop 方法来优雅地双向关闭通道，
//     因此复用 Write 方法的 offset 参数，用魔法值 -1 表示"请关闭 TUN"。
//     当 Close() 被调用时，内部调用 Write(nil, -1) 触发此分支。
//   - 行为: 关闭 t.c.closed（广播所有阻塞的 Read/Write），关闭 t.c.events，返回 (0, io.EOF)
//
// 正常写流程 (offset >= 0):
//   - 对每个 packet: 分配新切片 msg（去掉 offset 前缀），copy 数据
//   - 用 select 发送 msg 到 Inbound，同时监听 closed 避免关闭后永久阻塞
//   - 若在发送中途 closed 被触发 → 返回已成功写入的包数 i 和 os.ErrClosed
//   - 全部成功 → 返回 len(packets) 和 nil
//
// Write is called by the wireguard device to deliver a packet for routing.
func (t *chTun) Write(packets [][]byte, offset int) (int, error) {
	if offset == -1 {
		// offset=-1 是约定的关闭信号 Hack：关闭广播通道和事件通道
		close(t.c.closed)
		close(t.c.events)
		return 0, io.EOF
	}
	for i, data := range packets {
		// 去掉 offset 偏移，生成独立的新切片（避免 WireGuard 后续复用缓冲区）
		msg := make([]byte, len(data)-offset)
		copy(msg, data[offset:])
		// 用 select 非阻塞式发送：若 TUN 已关闭则立即返回已发送数量
		select {
		case <-t.c.closed:
			return i, os.ErrClosed
		case t.c.Inbound <- msg: // 送入 Inbound，测试代码从该端取出验证
		}
	}
	return len(packets), nil
}

// BatchSize 返回单次批量读写的最大包数，测试桩固定为 1（无批量优化）
func (t *chTun) BatchSize() int {
	return 1
}

// DefaultMTU 是 ChannelTUN 的默认最大传输单元，模拟常见 WireGuard 隧道 MTU
// WireGuard 通常使用 1420 = 1500(以太网) - 20(IPv4头) - 8(UDP头) - 52(WireGuard头) ≈ 1420
const DefaultMTU = 1420

// MTU 返回接口 MTU 值，固定为 DefaultMTU = 1420
func (t *chTun) MTU() (int, error) { return DefaultMTU, nil }

// Name 返回 TUN 设备名，测试桩固定返回 "loopbackTun1"（虚拟回环设备名）
func (t *chTun) Name() (string, error) { return "loopbackTun1", nil }

// Events 返回 TUN 事件只读通道，WireGuard Device 通过它监听 Up/Down 等状态变化
func (t *chTun) Events() <-chan tun.Event { return t.c.events }

// Close 关闭 TUN 设备：通过 Write(nil, -1) 的 offset=-1 Hack 触发真正的关闭流程
func (t *chTun) Close() error {
	t.Write(nil, -1)
	return nil
}
