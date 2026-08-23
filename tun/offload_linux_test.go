/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// offset 常量的来由：
//
//	= virtioNetHdrLen = struct virtio_net_hdr 的字节长度（通常 10 或 12 字节，
//	  取决于是否启用 hash 报告）。
//	WireGuard 的 tun 设备使用 virtio-net 风格的 offload 元数据协议：
//	从内核 TUN 读取的每个 skb 都以 virtio_net_hdr 开头，其后才是真正的
//	IP 报文（L3 及以上）。因此所有对 IP/TCP/UDP 头部的访问都必须跳过
//	这一段头部偏移，即"offset = virtioNetHdrLen"是测试数据构造的基准偏移。
const (
	offset = virtioNetHdrLen
)

// ip4/6PortA/B/C 测试地址选择：
//   - A/B/C 三元组：A 为源主机，B 为目的主机#1，C 为目的主机#2。
//     三个两两不同的 AddrPort（地址+端口）用于构造"不同流"场景：
//     A→B 是流 1，A→C 是流 2，用来验证 GRO（Generic Receive Offload，
//     接收端合并）只合并同一四元组（srcAddr:srcPort → dstAddr:dstPort）
//     的连续包，不跨流合并。
//   - IP 地址段：192.0.2.0/24 是 RFC 5737 规定的"TEST-NET-1"文档专用网段，
//     2001:db8::/32 是 RFC 3849 规定的 IPv6 文档专用前缀，
//     不会与真实公网/内网地址冲突，测试代码可放心硬编码。
//   - 端口号均为 1：最小合法端口，确保四元组唯一区分因素只有 IP 地址本身。
var (
	ip4PortA = netip.MustParseAddrPort("192.0.2.1:1")
	ip4PortB = netip.MustParseAddrPort("192.0.2.2:1")
	ip4PortC = netip.MustParseAddrPort("192.0.2.3:1")
	ip6PortA = netip.MustParseAddrPort("[2001:db8::1]:1")
	ip6PortB = netip.MustParseAddrPort("[2001:db8::2]:1")
	ip6PortC = netip.MustParseAddrPort("[2001:db8::3]:1")
)

// udp4PacketMutateIPFields 构造一个完整的 IPv4+UDP 测试报文，允许
// 通过 ipFn 回调在 IPv4 header Encode 之前修改任意 IP 字段
// （TTL、ToS、Flags、TotalLength 等），用于构造"IP 字段不一致导致
// GRO 不合并"的负向测试用例。
//
// 报文内存布局：
//
//	[0..offset-1]     : 预留给 virtio_net_hdr（后续由 virtioNetHdr.encode 写入）
//	[offset..offset+19] : IPv4 header（20 字节固定头，无 option）
//	[offset+20..offset+27] : UDP header（8 字节 = udphLen）
//	[offset+28..offset+28+payloadLen-1] : UDP payload（payloadLen 字节，全零）
//
// 校验和计算流程：
//
//	① IPv4 header checksum：由 ipv4H.CalculateChecksum() 先算反码和，
//	  再取反（^）后通过 SetChecksum 写入第 10-11 字节。
//	② UDP checksum：分两步：
//	  a) header.PseudoHeaderChecksum() 计算 UDP 伪首部（srcIP+dstIP+protocol+UDP_len）
//	     的反码和作为基础值；
//	  b) udpH.CalculateChecksum(pseudoCsum) 在伪首部基础上叠加 UDP header+payload
//	     的校验和，再取反写入 UDP header 第 6-7 字节。
//
// 参数：
//   - srcIPPort: 源 IP+UDP 端口
//   - dstIPPort: 目的 IP+UDP 端口
//   - payloadLen: UDP payload 长度（0 即可）
//   - ipFn: 可选回调，在 IPv4 编码前修改 header.IPv4Fields，传 nil 用默认值
//
// 返回值：含预留 virtio_net_hdr 区的完整报文字节切片（cap=65535，便于后续扩大包体）
func udp4PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, payloadLen int, ipFn func(*header.IPv4Fields)) []byte {
	// IPv4(20) + UDP(8) + payloadLen = 28 + payloadLen 字节
	totalLen := 28 + payloadLen
	// 头部 offset 起，cap 放大到 65535 方便后续修改包体
	b := make([]byte, offset+int(totalLen), 65535)
	// gvisor IPv4 header 视图（从 offset 处起）
	ipv4H := header.IPv4(b[offset:])
	// netip.Addr 转 4 字节数组，再转 tcpip.Addr 给 gvisor 用
	srcAs4 := srcIPPort.Addr().As4()
	dstAs4 := dstIPPort.Addr().As4()
	// 组装默认 IPv4 字段（20 字节固定头、UDP 协议、TTL=64、总长度等）
	ipFields := &header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(srcAs4[:]),
		DstAddr:     tcpip.AddrFromSlice(dstAs4[:]),
		Protocol:    unix.IPPROTO_UDP,
		TTL:         64,
		TotalLength: uint16(totalLen),
	}
	// 回调修改 IP 字段（用于构造不一致的测试数据）
	if ipFn != nil {
		ipFn(ipFields)
	}
	// 将 IPv4Fields 编码写入 b[offset:offset+20]
	ipv4H.Encode(ipFields)
	// UDP header 视图：IPv4 header 之后（offset+20）
	udpH := header.UDP(b[offset+20:])
	// 编码 UDP header（src/dst port + length=payloadLen+8，checksum 占位为 0）
	udpH.Encode(&header.UDPFields{
		SrcPort: srcIPPort.Port(),
		DstPort: dstIPPort.Port(),
		Length:  uint16(payloadLen + udphLen), // udphLen = 8（UDP 头长度常量）
	})
	// 计算并写回 IPv4 header checksum（取反后写入）
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	// 计算 UDP 伪首部校验和（srcIP+dstIP+protocol+UDP_total_length）
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(udphLen+payloadLen))
	// 在伪首部基础上，计算并写回 UDP 整包校验和
	udpH.SetChecksum(^udpH.CalculateChecksum(pseudoCsum))
	return b
}

// udp6Packet 简写：构造标准 IPv6+UDP 测试报文，不修改 IP 字段
func udp6Packet(srcIPPort, dstIPPort netip.AddrPort, payloadLen int) []byte {
	return udp6PacketMutateIPFields(srcIPPort, dstIPPort, payloadLen, nil)
}

// udp6PacketMutateIPFields 构造 IPv6+UDP 测试报文，允许修改 IPv6 字段
// （HopLimit、TrafficClass、PayloadLength 等），结构与 udp4PacketMutateIPFields
// 对称，差异仅在：
//   - IPv6 固定头 40 字节（无 checksum 字段，IPv6 不做 L3 header checksum）
//   - UDP header 位于 offset+40
//   - 总长度 totalLen = 40 (IPv6) + 8 (UDP) + payloadLen = 48 + payloadLen
//   - 仅 UDP checksum 要算（IPv6 L3 无校验和）
func udp6PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, payloadLen int, ipFn func(*header.IPv6Fields)) []byte {
	// IPv6(40) + UDP(8) + payloadLen = 48 + payloadLen
	totalLen := 48 + payloadLen
	b := make([]byte, offset+int(totalLen), 65535)
	ipv6H := header.IPv6(b[offset:])
	srcAs16 := srcIPPort.Addr().As16()
	dstAs16 := dstIPPort.Addr().As16()
	ipFields := &header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(srcAs16[:]),
		DstAddr:           tcpip.AddrFromSlice(dstAs16[:]),
		TransportProtocol: unix.IPPROTO_UDP,
		HopLimit:          64,
		PayloadLength:     uint16(payloadLen + udphLen), // UDP header(8) + payload
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv6H.Encode(ipFields)
	// UDP header 在 IPv6 header 之后（offset+40）
	udpH := header.UDP(b[offset+40:])
	udpH.Encode(&header.UDPFields{
		SrcPort: srcIPPort.Port(),
		DstPort: dstIPPort.Port(),
		Length:  uint16(payloadLen + udphLen),
	})
	// IPv6 没有 L3 header checksum，只算 UDP checksum
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(udphLen+payloadLen))
	udpH.SetChecksum(^udpH.CalculateChecksum(pseudoCsum))
	return b
}

// udp4Packet 简写：构造标准 IPv4+UDP 测试报文，不修改 IP 字段
func udp4Packet(srcIPPort, dstIPPort netip.AddrPort, payloadLen int) []byte {
	return udp4PacketMutateIPFields(srcIPPort, dstIPPort, payloadLen, nil)
}

// tcp4PacketMutateIPFields 构造 IPv4+TCP 测试报文，支持修改 IP 字段、
// TCP flags、segment payload 大小、起始 seq 序列号。
//
// 内存布局（L3=offset 起）：
//
//	[offset..offset+19]  : IPv4 header 20 字节
//	[offset+20..offset+39] : TCP header 20 字节（DataOffset=5 即 5*4=20，无 option）
//	[offset+40..offset+40+segmentSize-1] : TCP payload（segmentSize 字节，全零）
//
// 参数：
//   - flags: TCP 标志位组合（如 TCPFlagAck|TCPFlagPsh、TCPFlagAck 等）。
//     PSH 位存在时 GRO 通常不合并到当前段（push 语义要求立即上送），
//     这是 "PSH interleaved" 用例的测试点。
//   - segmentSize: TCP payload 字节数（不含头）
//   - seq: TCP 序号（第一个字节的 SEQ）。GRO 合并的关键条件之一是
//     "下一段 seq == 上一段 seq + segmentSize" 即字节连续。
func tcp4PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv4Fields)) []byte {
	// IPv4(20) + TCP(20) + segmentSize = 40 + segmentSize
	totalLen := 40 + segmentSize
	b := make([]byte, offset+int(totalLen), 65535)
	ipv4H := header.IPv4(b[offset:])
	srcAs4 := srcIPPort.Addr().As4()
	dstAs4 := dstIPPort.Addr().As4()
	ipFields := &header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(srcAs4[:]),
		DstAddr:     tcpip.AddrFromSlice(dstAs4[:]),
		Protocol:    unix.IPPROTO_TCP,
		TTL:         64,
		TotalLength: uint16(totalLen),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv4H.Encode(ipFields)
	// TCP header 视图：IPv4 header 之后 offset+20
	tcpH := header.TCP(b[offset+20:])
	// 编码 TCP 头（端口、SEQ、ACK、DataOffset=20 字节、flags、窗口 3000）
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	// IPv4 header checksum
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	// TCP 伪首部（srcIP+dstIP+protocol+TCP_total_length）
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(20+segmentSize))
	// TCP 整包（header+payload）+ 伪首部 校验和
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return b
}

// tcp4Packet 简写：标准 IPv4+TCP 报文，不修改 IP 字段
func tcp4Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) []byte {
	return tcp4PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

// tcp6PacketMutateIPFields 构造 IPv6+TCP 测试报文，支持修改 IPv6 字段。
// 布局：IPv6 40 + TCP 20 + segmentSize = 60 + segmentSize
func tcp6PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv6Fields)) []byte {
	// IPv6(40) + TCP(20) + segmentSize = 60 + segmentSize
	totalLen := 60 + segmentSize
	b := make([]byte, offset+int(totalLen), 65535)
	ipv6H := header.IPv6(b[offset:])
	srcAs16 := srcIPPort.Addr().As16()
	dstAs16 := dstIPPort.Addr().As16()
	ipFields := &header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(srcAs16[:]),
		DstAddr:           tcpip.AddrFromSlice(dstAs16[:]),
		TransportProtocol: unix.IPPROTO_TCP,
		HopLimit:          64,
		PayloadLength:     uint16(segmentSize + 20), // TCP header(20) + payload
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv6H.Encode(ipFields)
	tcpH := header.TCP(b[offset+40:])
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	// IPv6 无 L3 checksum，只算 TCP checksum
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(20+segmentSize))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return b
}

// tcp6Packet 简写：标准 IPv6+TCP 报文，不修改 IP 字段
func tcp6Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) []byte {
	return tcp6PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

// Test_handleVirtioRead 验证 handleVirtioRead 对 GSO（Generic Segmentation Offload，
// 发送端硬件分段）大包的正确拆分（接收方向的 GSO 解包）。
// 四组典型用例：TCPv4 / TCPv6 / UDPv4 / UDPv6，每组构造一个"超 MTU 大小"的包，
// 通过 virtio_net_hdr 指定 gsoType / gsoSize / hdrLen 让 handleVirtioRead
// 把它切成若干个"每段 payload = gsoSize 字节"的小包，验证：
//
//	① 输出包数 = 预期段数（len(wantLens)）
//	② 每段的总长度（IP head + transport head + payload）= wantLens[i]
//
// wantLens 计算说明（以 tcp4 为例）：
//   - tcp4Packet payloadLen=200、gsoSize=100 → 共分 200/100 = 2 段
//   - 每段 payload 100，加上 IPv4 头 20 + TCP 头 20 = 140 字节 → wantLens=[140, 140]
//   - tcp6：IPv6 头 40 + TCP 头 20 + 100 payload = 160 → [160, 160]
//   - udp4：IPv4 20 + UDP 8 + 100 payload = 128 → [128, 128]
//   - udp6：IPv6 40 + UDP 8 + 100 payload = 148 → [148, 148]
//
// virtio_net_hdr 各字段含义：
//   - flags: VIRTIO_NET_HDR_F_NEEDS_CSUM 告诉接收方"传输层 checksum 占位还没算，
//     由接收端按 csumStart/csumOffset 指示的位置补填"
//   - gsoType: GSO 类型（TCPV4 / TCPV6 / UDP_L4）
//   - gsoSize: 每段最大 payload 字节数（不含传输/IP 头）
//   - hdrLen: L3 起算"每段都相同的固定头长度"（IP head + transport head，
//     分段时不变化的部分，整段复制到每个小包包头）
//   - csumStart: L3 起算多少字节后开始是需要算 checksum 的区域起始
//     （对 TCP/UDP 都是传输层 head 的起始）
//   - csumOffset: csumStart 起算多少字节后是 checksum 字段位置
//     （TCP checksum 在 TCP head 内偏移 16；UDP checksum 在 UDP head 偏移 6）
//
// 回归防护的性质：
//
//	保证 virtio 读路径的 GSO 拆分逻辑在四种主流（TCP/UDP × v4/v6）协议组合下
//	段数、段长、段头复制、每段 checksum 补全均正确。
//	防止 handleVirtioRead 中 gsoSize 取整、hdrLen 边界、offset 计算错误
//	导致拆分段多或少、payload 截断或越界。
func Test_handleVirtioRead(t *testing.T) {
	tests := []struct {
		name     string       // 用例名
		hdr      virtioNetHdr // 输入的 virtio_net_hdr（GSO 参数）
		pktIn    []byte       // 输入大包（整体报文，含预留 virtio 区+L3+数据）
		wantLens []int        // 期望拆分后每段长度（不含 virtio hdr，仅 L3 起）
		wantErr  bool         // 是否期望返回错误
	}{
		{
			// TCPv4 GSO：payload=200, gsoSize=100 → 分 2 段，每段 140(20+20+100)
			"tcp4",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV4,
				gsoSize:    100,
				hdrLen:     40, // IPv4(20) + TCP(20) = 每段固定头大小
				csumStart:  20, // L3 起 20 字节到 TCP head 起始
				csumOffset: 16, // TCP head 内偏移 16 字节是 TCP checksum
			},
			tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{140, 140},
			false,
		},
		{
			// TCPv6 GSO：每段 = IPv6(40) + TCP(20) + 100 payload = 160
			"tcp6",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
				gsoSize:    100,
				hdrLen:     60, // IPv6(40) + TCP(20)
				csumStart:  40, // L3 起 40 字节到 TCP head
				csumOffset: 16,
			},
			tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{160, 160},
			false,
		},
		{
			// UDPv4 GSO (UDP_L4)：每段 = IPv4(20) + UDP(8) + 100 payload = 128
			"udp4",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
				gsoSize:    100,
				hdrLen:     28, // IPv4(20) + UDP(8)
				csumStart:  20, // L3 起 20 到 UDP head
				csumOffset: 6,  // UDP head 内偏移 6 是 UDP checksum
			},
			udp4Packet(ip4PortA, ip4PortB, 200),
			[]int{128, 128},
			false,
		},
		{
			// UDPv6 GSO：每段 = IPv6(40) + UDP(8) + 100 payload = 148
			"udp6",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
				gsoSize:    100,
				hdrLen:     48, // IPv6(40) + UDP(8)
				csumStart:  40,
				csumOffset: 6,
			},
			udp6Packet(ip6PortA, ip6PortB, 200),
			[]int{148, 148},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 分配 conn.IdealBatchSize 个输出缓冲（每个大小 65535）
			out := make([][]byte, conn.IdealBatchSize)
			sizes := make([]int, conn.IdealBatchSize)
			for i := range out {
				out[i] = make([]byte, 65535)
			}
			// 把 hdr 编码写入 pktIn[0..virtioNetHdrLen-1]（之前是预留的）
			tt.hdr.encode(tt.pktIn)
			// 核心函数：执行 GSO 拆分
			n, err := handleVirtioRead(tt.pktIn, out, sizes, offset)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("got err: %v", err)
			}
			// 断言段数 = len(wantLens)
			if n != len(tt.wantLens) {
				t.Fatalf("got %d packets, wanted %d", n, len(tt.wantLens))
			}
			// 逐段断言长度
			for i := range tt.wantLens {
				if tt.wantLens[i] != sizes[i] {
					t.Fatalf("wantLens[%d]: %d != outSizes: %d", i, tt.wantLens[i], sizes[i])
				}
			}
		})
	}
}

// flipTCP4Checksum 对 IPv4+TCP 报文的 TCP checksum 字段做"全 8 位 XOR 翻转"：
//
//	checksum 两字节每个 bit 取反（0xFF XOR 等价 bitwise NOT），
//	用来将一个合法 checksum 破坏成"明显非法"，用于构造
//	coalesceItemInvalidCSum / Test_handleGRO_invalidItemCsumClearsVirtioNetHdr
//	等"校验和错误路径"测试数据。
//
// 翻转位置计算：
//
//	[virtioNetHdrLen] = L3 起点 = IPv4 header 起始
//	+20 跳过 IPv4 头 → TCP header 起始
//	+16 TCP header 内第 16 字节开始是 TCP checksum（16 位）
//
// 设计思路：XOR 取反是"可复原"的对称操作，同一片报文调用两次 flipTCP4Checksum
//
//	即恢复合法 checksum；但在测试里我们只调一次来破坏。
func flipTCP4Checksum(b []byte) []byte {
	at := virtioNetHdrLen + 20 + 16 // 20 byte ipv4 header; tcp csum offset is 16
	b[at] ^= 0xFF
	b[at+1] ^= 0xFF
	return b
}

// flipUDP4Checksum 对称于 flipTCP4Checksum，但破坏的是 UDPv4 checksum：
//
//	UDP header 起始在 IPv4 之后（+20），UDP checksum 在 UDP header 偏移 6
func flipUDP4Checksum(b []byte) []byte {
	at := virtioNetHdrLen + 20 + 6 // 20 byte ipv4 header; udp csum offset is 6
	b[at] ^= 0xFF
	b[at+1] ^= 0xFF
	return b
}

// Fuzz_handleGRO 是 handleGRO 的模糊测试（fuzz test），用于在大量随机输入下
// 验证 handleGRO 的三个结构不变量（structural invariants），抓出边界 bug。
//
// 种子数据包（seed corpus）：f.Add 注册的 12 个样本包，覆盖：
//
//	pkt0/1/2: TCPv4 流 1 两段(seq 1+100, seq 101+100)、TCPv4 流 2（A→C）
//	pkt3/4/5: TCPv6 对应
//	pkt6/7/8: UDPv4 两个相同包（流1）、UDPv4 流 2（A→C）
//	pkt9/10/11: UDPv6 对应
//	最后两个参数：canUDPGRO（是否启用 UDP GRO 开关）、offset（固定值）
//	模糊引擎会基于这些种子做 byte-level mutation 生成更杂乱/畸形的输入。
//
// 断言的三个不变量（永远必须成立，任何输入都不能违反）：
//
//	① len(toWrite) ≤ len(pkts)：
//	  handleGRO 只是把"要写出去的包的索引"选出来，不可能比输入包数更多
//	  （每合 N 个包 → 写 1 个包，总数 ≤ 输入）。
//	② 所有 toWrite 索引 ∈ [0, len(pkts)-1]：
//	  不得出现负数、不得越界（防止 slice panic）。
//	③ toWrite 中索引不重复：
//	  同一个输入包不会被写两次（否则上层会看到重复报文、TCP 字节流错乱）。
//
// 回归防护的性质：
//
//	在模糊引擎生成的各种畸形数据（任意字节内容、任意长度、任意组合顺序、
//	canUDPGRO 开关开/关）下，handleGRO 永远不产生越界索引和重复索引，
//	保证函数行为是"结构安全"的（即使语义错了也不能崩、不能索引越界）。
func Fuzz_handleGRO(f *testing.F) {
	// 种子：12 个典型包，覆盖 TCP/UDP × v4/v6 × 同流/异流组合
	pkt0 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)
	pkt1 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101)
	pkt2 := tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201)
	pkt3 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1)
	pkt4 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101)
	pkt5 := tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201)
	pkt6 := udp4Packet(ip4PortA, ip4PortB, 100)
	pkt7 := udp4Packet(ip4PortA, ip4PortB, 100)
	pkt8 := udp4Packet(ip4PortA, ip4PortC, 100)
	pkt9 := udp6Packet(ip6PortA, ip6PortB, 100)
	pkt10 := udp6Packet(ip6PortA, ip6PortB, 100)
	pkt11 := udp6Packet(ip6PortA, ip6PortC, 100)
	f.Add(pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11, true, offset)
	f.Fuzz(func(t *testing.T, pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11 []byte, canUDPGRO bool, offset int) {
		pkts := [][]byte{pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11}
		toWrite := make([]int, 0, len(pkts))
		handleGRO(pkts, offset, newTCPGROTable(), newUDPGROTable(), canUDPGRO, &toWrite)
		// 不变量 ①：选出的写回索引数 ≤ 输入包数
		if len(toWrite) > len(pkts) {
			t.Errorf("len(toWrite): %d > len(pkts): %d", len(toWrite), len(pkts))
		}
		seenWriteI := make(map[int]bool)
		for _, writeI := range toWrite {
			// 不变量 ②：索引不越界 [0, len(pkts)-1]
			if writeI < 0 || writeI > len(pkts)-1 {
				t.Errorf("toWrite value (%d) outside bounds of len(pkts): %d", writeI, len(pkts))
			}
			// 不变量 ③：索引不重复
			if seenWriteI[writeI] {
				t.Errorf("duplicate toWrite value: %d", writeI)
			}
			seenWriteI[writeI] = true
		}
	})
}

// Test_handleGRO 是 handleGRO 通用接收端合并（GRO）主逻辑的端到端表驱动测试，
// 覆盖 10 组典型场景（正向合并 + 负向不合并）。
//
// 断言的两个核心输出：
//   - wantToWrite []int：期望 handleGRO 最终"哪些输入包索引需要写回给上层"的列表。
//     合并后的"超包"只保留第一个被合并的索引（其他被合并进来的包不再单独上送）。
//   - wantLens []int：与 wantToWrite 对应，期望每一个要写回的包在
//     L3 起的总字节数（即 len(pkts[pktI][offset:])）。
//     当一个大包被合并了 N 段时，它的 len 会是所有段的 payload 累加后的总值。
//
// 10 组用例逐组说明：
// ─────────────────────────────────────────────────────────────────────────────
// ①  "multiple protocols and flows"（多协议多流 + UDP GRO 开启）
//
//	输入 11 包：
//	  #0 TCP4 A→B seq=1 len100  ──┐
//	  #1 UDP4 A→B                  ├─UDP4流1
//	  #2 UDP4 A→C (异流，不合并)  ──┘
//	  #3 TCP4 A→B seq=101 len100 ← 与#0同流且连续，合并进#0
//	  #4 TCP4 A→C (异流)
//	  #5 TCP6 A→B seq=1 len100  ──┐
//	  #6 TCP6 A→B seq=101 len100 ← 合并进#5
//	  #7 TCP6 A→C (异流)
//	  #8 UDP4 A→B ← 与#1同流且同大小，合并进#1（UDP GRO on）
//	  #9 UDP6 A→B  ──┐
//	  #10 UDP6 A→B ← 合并进#9
//	预期 7 个包需要写回：wantToWrite=[0,1,2,4,5,7,9]
//	对应合并后 len：
//	  #0 合并了 #0(140)+#3(140 TCP)=240
//	  #1 合并了 #1(128 UDP)+#8(128)=228
//	  #2 独立 128
//	  #4 独立 140
//	  #5 合并 140+140=280？ wait 不对 是 TCP6，TCP6 头长60 → 单包 60+100=160？
//	      #5=160 + #6=160 = 320？ 但 wantLens 写的是 260？重新核对 wantLens：
//	      让我们重新计算 wantLens = [240, 228, 128, 140, 260, 160, 248]：
//	        idx0 是 pkt0，tcp4Packet(segmentSize=100, seq=1) → L3 起 40+100=140，
//	          合并 pkt3 segmentSize=100 → 总 140+100=240 ✓
//	        idx1 是 pkt1，udp4Packet(payload=100) → L3 起 28+100=128，
//	          合并 pkt8 payload 100 → 128+100=228 ✓
//	        idx2 是 pkt2 独立 udp4(A→C) = 128 ✓
//	        idx4 是 pkt4 独立 tcp4(A→C) = 140 ✓
//	        idx5 是 pkt5 tcp6Packet(segmentSize=100, seq=1) → L3起 60+100=160
//	          合并 pkt6 segmentSize=100 → 160+100 = 260 ✓
//	        idx7 是 pkt7 独立 tcp6(A→C) = 160 ✓
//	        idx9 是 pkt9 udp6(payload=100) → 48+100=148
//	          合并 pkt10 payload 100 → 148+100 = 248 ✓
//	回归：验证同流合并、跨协议不互扰、异流（A→C）不合并、UDP GRO 合并逻辑。
//
// ─────────────────────────────────────────────────────────────────────────────
// ②  "multiple protocols and flows no UDP GRO"（同①，但 canUDPGRO=false 关闭 UDP GRO）
//
//	差异：UDP 不再合并，所以 #1/#8/#9/#10 都独立上送 → wantToWrite 多了 8,9,10
//	wantLens 中 idx1 不再合并，还是 128；idx8 独立 128；idx9/10 各独立 148
//	回归：确保 canUDPGRO=false 时 UDP 合并分支完全不触发。
//
// ─────────────────────────────────────────────────────────────────────────────
// ③  "PSH interleaved"（PSH 位交错：TCP PSH 标志会打断 GRO 合并链）
//
//	包序列（seq 连续 1,101,201,301）：
//	  v4: #0(ACK,seq1) → #1(ACK|PSH,seq101) → #2(ACK,seq201) → #3(ACK,seq301)
//	      #0 可以和 #1 合并吗？#1 带 PSH，GRO 遇到 PSH 的段通常作为"当前合并链的最后一段"，
//	      后续不能继续合并。所以：
//	        #0 合并 #1 → 作为链 1（PSH 收尾） ，写回索引 0
//	        #2 合并 #3 → 作为链 2，写回索引 2
//	      v6 同理（#4+#5 → 写 4；#6+#7 → 写 6）
//	wantToWrite=[0,2,4,6] ✓
//	wantLens=[240, 240, 260, 260] ✓（每条链合并 2 段 100 payload，大小翻倍）
//	回归：确保 TCP PSH 位正确终止当前 GRO 链、链与链之间不跨 PSH 合并。
//
// ─────────────────────────────────────────────────────────────────────────────
// ④  "coalesceItemInvalidCSum"（被合并的候选包 checksum 非法 → 不合并）
//
//	序列：
//	  #0 TCP4 flipCSum（seq1, csum 坏）— 它是"首包"，首次入表时 csum 非法
//	       → 不进 GRO 表 → 会被立即上送（同时需清零其 virtio hdr，见另一个测试）
//	  #1 TCP4 seq101（csum 好）→ 本来应该和 #0 合并，但 #0 不在表里，
//	       → 只能作为新的链首入表
//	  #2 TCP4 seq201（csum 好）→ 与 #1 同流连续 → 合并进 #1
//	  同理 UDP：#3 flipCSum（坏，独立上送）；#4 csum 好，#5 合并进 #4
//	wantToWrite=[0,1,3,4]（首包非法各自独立上送，好的 #1/#4 再合并后面）
//	wantLens：
//	  idx0 pkt0 = 140（独立，无合并）
//	  idx1 pkt1 = 140 本身 + pkt2 payload 100 = 240
//	  idx3 pkt3 = 128（独立）
//	  idx4 pkt4 = 128 本身 + pkt5 payload 100 = 228
//	回归：确保 csum 校验失败时不进 GRO 表，不会把坏包和好包合并在一起。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑤  "out of order"（乱序：seq 先到 101，再到 1，再到 201）
//
//	GRO 的语义是"只合并字节连续的有序序列"，遇到乱序通常：
//	  策略 A（保守）：将后到但 seq 更早的包作为"prepend 插入到现有链之前"，
//	  先到 seq 更大的包保留为链尾。
//	#0 seq=101（先到，链首）
//	#1 seq=1（后到但更早 → prepend 到 #0 之前）
//	#2 seq=201（+append 到 #0 之后）
//	最终合并成单链 #0（索引 0 写入），总 len=140+100+100=340
//	wantToWrite=[0]，wantLens=[340]
//	回归：确保乱序 pre-pend/append 逻辑正确，不会因为包到达顺序与 seq 顺序不一致
//	      而漏合并或重复计算。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑥  "unequal TTL"（v4 TTL 不一致 → 相同流也不合并）
//
//	#0 TTL=64，#1 TTL=65（TTL++）→ 两段 IP TTL 不一致，GRO 不合并
//	UDP 同理 #2 TTL=64, #3 TTL=65 → 不合并
//	wantToWrite=[0,1,2,3]，wantLens 各 140/140/128/128 独立
//	回归：验证 IP TTL 一致性检查分支。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑦  "unequal ToS"（v4 ToS/DSCP 不一致 → 不合并）
//
//	逻辑同⑥，改字段是 TOS。wantToWrite/wantLens 与⑥完全相同
//	回归：验证 IP ToS 一致性检查分支。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑧  "unequal flags more fragments set"（v4 分片标志 MF=1（更多分片位）
//
//	不一致 → 不合并。IP flags=1 即 MF 位（More Fragments），表示还有后续分片。
//	同流包分片标志不同说明路径上行为不同，GRO 不能合并。
//	wantToWrite/wantLens 同⑥⑦。
//	回归：验证 IPv4 flags MF 位一致性检查。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑨  "unequal flags DF set"（v4 分片标志 DF=2（Don't Fragment 不分片）不一致）
//
//	同样不合并。wantToWrite/wantLens 同上。
//	回归：验证 IPv4 flags DF 位一致性检查。
//
// ─────────────────────────────────────────────────────────────────────────────
// ⑩⑪ 两组 IPv6 版本对应：
//
//	"ipv6 unequal hop limit"（HopLimit 不一致）→ v4 对应 TTL 不一致
//	"ipv6 unequal traffic class"（Traffic Class 不一致）→ v4 对应 ToS 不一致
//	每组 4 个包：TCP6 + UDP6 各两条（两个流量，一个正常，一个改字段）。
//	wantLens 都是 160/160/148/148（v6 对应包长）。
//	回归：验证 IPv6 HopLimit / TrafficClass 一致性检查分支。
//
// 回归防护的总性质：
//
//	这 10 组用例构成了 handleGRO 的"功能完备性矩阵"，覆盖：
//	- 同流合并的正向路径（v4/v6/TCP/UDP × 同大小/追加/prepend）
//	- 协议/四元组维度的"跨流不合并"负向
//	- canUDPGRO=false 的 UDP 不合并
//	- TCP PSH 打断合并链
//	- checksum 非法不入表
//	- 乱序到达时的 pre-pend
//	- IP 层可变字段（TTL/ToS/Flags/HopLimit/TrafficClass）不一致不合并
func Test_handleGRO(t *testing.T) {
	tests := []struct {
		name        string   // 用例名
		pktsIn      [][]byte // 输入包序列（含 virtio hdr 预留区）
		canUDPGRO   bool     // 是否允许 UDP GRO 合并
		wantToWrite []int    // 期望上送的包索引（合入的不出现）
		wantLens    []int    // 期望对应索引包的 L3 起大小
		wantErr     bool     // 是否期望错误
	}{
		{
			"multiple protocols and flows",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // tcp4 flow 1
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp4Packet(ip4PortA, ip4PortC, 100),                         // udp4 flow 2
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // tcp4 flow 1
				tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201), // tcp4 flow 2
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),   // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101), // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201), // tcp6 flow 2
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
			},
			true,
			[]int{0, 1, 2, 4, 5, 7, 9},
			[]int{240, 228, 128, 140, 260, 160, 248},
			false,
		},
		{
			"multiple protocols and flows no UDP GRO",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // tcp4 flow 1
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp4Packet(ip4PortA, ip4PortC, 100),                         // udp4 flow 2
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // tcp4 flow 1
				tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201), // tcp4 flow 2
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),   // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101), // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201), // tcp6 flow 2
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
			},
			false,
			[]int{0, 1, 2, 4, 5, 7, 8, 9, 10},
			[]int{240, 128, 128, 140, 260, 160, 128, 148, 148},
			false,
		},
		{
			"PSH interleaved",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),                     // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                   // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 301),                   // v4 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),                     // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 201),                   // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 301),                   // v6 flow 1
			},
			true,
			[]int{0, 2, 4, 6},
			[]int{240, 240, 260, 260},
			false,
		},
		{
			"coalesceItemInvalidCSum",
			[][]byte{
				flipTCP4Checksum(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)), // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101),                 // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                 // v4 flow 1 seq 201 len 100
				flipUDP4Checksum(udp4Packet(ip4PortA, ip4PortB, 100)),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4Packet(ip4PortA, ip4PortB, 100),
			},
			true,
			[]int{0, 1, 3, 4},
			[]int{140, 240, 128, 228},
			false,
		},
		{
			"out of order",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201), // v4 flow 1 seq 201 len 100
			},
			true,
			[]int{0},
			[]int{340},
			false,
		},
		{
			"unequal TTL",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TTL++
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.TTL++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{140, 140, 128, 128},
			false,
		},
		{
			"unequal ToS",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TOS++
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.TOS++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{140, 140, 128, 128},
			false,
		},
		{
			"unequal flags more fragments set",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 1
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.Flags = 1
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{140, 140, 128, 128},
			false,
		},
		{
			"unequal flags DF set",
			[][]byte{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 2
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.Flags = 2
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{140, 140, 128, 128},
			false,
		},
		{
			"ipv6 unequal hop limit",
			[][]byte{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.HopLimit++
				}),
				udp6Packet(ip6PortA, ip6PortB, 100),
				udp6PacketMutateIPFields(ip6PortA, ip6PortB, 100, func(fields *header.IPv6Fields) {
					fields.HopLimit++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{160, 160, 148, 148},
			false,
		},
		{
			"ipv6 unequal traffic class",
			[][]byte{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.TrafficClass++
				}),
				udp6Packet(ip6PortA, ip6PortB, 100),
				udp6PacketMutateIPFields(ip6PortA, ip6PortB, 100, func(fields *header.IPv6Fields) {
					fields.TrafficClass++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{160, 160, 148, 148},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toWrite := make([]int, 0, len(tt.pktsIn))
			// 执行 GRO 合并
			err := handleGRO(tt.pktsIn, offset, newTCPGROTable(), newUDPGROTable(), tt.canUDPGRO, &toWrite)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("got err: %v", err)
			}
			// 断言 toWrite 长度
			if len(toWrite) != len(tt.wantToWrite) {
				t.Fatalf("got %d packets, wanted %d", len(toWrite), len(tt.wantToWrite))
			}
			// 逐元素断言 toWrite 索引值与对应 pkts[...] L3 起长度
			for i, pktI := range tt.wantToWrite {
				if tt.wantToWrite[i] != toWrite[i] {
					t.Fatalf("wantToWrite[%d]: %d != toWrite: %d", i, tt.wantToWrite[i], toWrite[i])
				}
				if tt.wantLens[i] != len(tt.pktsIn[pktI][offset:]) {
					t.Errorf("wanted len %d packet at %d, got: %d", tt.wantLens[i], i, len(tt.pktsIn[pktI][offset:]))
				}
			}
		})
	}
}

// Test_packetIsGROCandidate 验证 packetIsGROCandidate 函数 — 判定一个
// 输入报文（L3 起，已去 virtio hdr）是否是可以参与 GRO 合并的合法候选。
// 共 14 个用例，覆盖合法 + 不合法维度：
//
// 合法候选（4 个）：
//
//	① tcp4：标准 TCPv4 包 → tcp4GROCandidate
//	② tcp6：标准 TCPv6 → tcp6GROCandidate
//	③ udp4：标准 UDPv4 + canUDPGRO=true → udp4GROCandidate
//	④ udp6：标准 UDPv6 + canUDPGRO=true → udp6GROCandidate
//
// 不合法候选（10 个）：
//
//	⑤ udp4 no support：UDPv4 但 canUDPGRO=false → notGROCandidate
//	⑥ udp6 no support：UDPv6 但 canUDPGRO=false → notGROCandidate
//	⑦ udp4 too short：UDPv4 总长度 < IPv4(20)+UDP(8)=28 字节 → 截断无法解析
//	⑧ udp6 too short：UDPv6 总长度 < IPv6(40)+UDP(8)=48 → 截断
//	⑨ tcp4 too short：TCPv4 总长度 < IPv4(20)+TCP(20)=40 → 截断
//	⑩ tcp6 too short：TCPv6 总长度 < IPv6(40)+TCP(20)=60 → 截断
//	⑪ invalid IP version：首字节高 4 位（IP ver）既非 4 也非 6 → 非 IP 包
//	⑫ invalid IP header len：IPv4 IHL（首字节低 4 位）=6，表示 IP head 6*4=24 字节，
//	   但实际构造的是标准 20 字节 head，解析时 IP head 长度字段与实际不符 → 不合法
//	⑬ ip4 invalid protocol：IPv4 Protocol 字段 = IPPROTO_GRE（既非 TCP=6 也非 UDP=17）
//	⑭ ip6 invalid protocol：IPv6 Next Header = IPPROTO_GRE
//
// 回归防护的性质：
//
//	保证 packetIsGROCandidate 在输入长度不足、IP 版本不对、IP head 长度字段非法、
//	非 TCP/UDP 协议、UDP GRO 关闭等所有"边缘情况"下都正确返回 notGROCandidate，
//	后续 GRO 合并逻辑不会去解析畸形头引发越界。
func Test_packetIsGROCandidate(t *testing.T) {
	// 构造各种"合法/不合法"候选包：所有测试用的切片都是 L3 起（去掉 virtio hdr）
	tcp4 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)[virtioNetHdrLen:]
	// 截断 TCPv4 到 39 字节（比最小 TCP 头 40 少 1）
	tcp4TooShort := tcp4[:39]
	// 把 IPv4 首字节 0x45（ver=4, IHL=5 → 20 字节）改成 0x46：
	//   ver 还是 4，但 IHL=6*4=24 → 头长度字段声称 24 字节，实际长度还是 20，
	//   就是"IP 头长度不合法"测试数据
	ip4InvalidHeaderLen := make([]byte, len(tcp4))
	copy(ip4InvalidHeaderLen, tcp4)
	ip4InvalidHeaderLen[0] = 0x46
	// 把 IPv4 Protocol（偏移 9）改成 IPPROTO_GRE
	ip4InvalidProtocol := make([]byte, len(tcp4))
	copy(ip4InvalidProtocol, tcp4)
	ip4InvalidProtocol[9] = unix.IPPROTO_GRE

	tcp6 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1)[virtioNetHdrLen:]
	// 截断 TCPv6 到 59 字节（最小 60 少 1）
	tcp6TooShort := tcp6[:59]
	// IPv6 Next Header（偏移 6，紧邻 Payload Length 之前）改成 GRE
	ip6InvalidProtocol := make([]byte, len(tcp6))
	copy(ip6InvalidProtocol, tcp6)
	ip6InvalidProtocol[6] = unix.IPPROTO_GRE

	udp4 := udp4Packet(ip4PortA, ip4PortB, 100)[virtioNetHdrLen:]
	// 截断 UDPv4 到 27（最小 28 少 1）
	udp4TooShort := udp4[:27]

	udp6 := udp6Packet(ip6PortA, ip6PortB, 100)[virtioNetHdrLen:]
	// 截断 UDPv6 到 47（最小 48 少 1）
	udp6TooShort := udp6[:47]

	tests := []struct {
		name      string
		b         []byte
		canUDPGRO bool
		want      groCandidateType
	}{
		// 合法 4 例
		{"tcp4", tcp4, true, tcp4GROCandidate},
		{"tcp6", tcp6, true, tcp6GROCandidate},
		{"udp4", udp4, true, udp4GROCandidate},
		// UDP 支持关闭的两例
		{"udp4 no support", udp4, false, notGROCandidate},
		{"udp6", udp6, true, udp6GROCandidate},
		{"udp6 no support", udp6, false, notGROCandidate},
		// 长度截断 4 例
		{"udp4 too short", udp4TooShort, true, notGROCandidate},
		{"udp6 too short", udp6TooShort, true, notGROCandidate},
		{"tcp4 too short", tcp4TooShort, true, notGROCandidate},
		{"tcp6 too short", tcp6TooShort, true, notGROCandidate},
		// IP 版本不对：首字节高 4 位 = 0
		{"invalid IP version", []byte{0x00}, true, notGROCandidate},
		// IPv4 IHL 与实际不符
		{"invalid IP header len", ip4InvalidHeaderLen, true, notGROCandidate},
		// IPv4 协议非 TCP/UDP
		{"ip4 invalid protocol", ip4InvalidProtocol, true, notGROCandidate},
		// IPv6 协议非 TCP/UDP
		{"ip6 invalid protocol", ip6InvalidProtocol, true, notGROCandidate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packetIsGROCandidate(tt.b, tt.canUDPGRO); got != tt.want {
				t.Errorf("packetIsGROCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_udpPacketsCanCoalesce 验证 udpPacketsCanCoalesce 判定逻辑：
//
//	UDP GRO 合并时，一个新候选 UDP 包是否可以 append 合并到现有 GRO 条目。
//
// UDP 的 GRO 条件比 TCP 严格（没有 SEQ 指示字节连续性，只能靠"同大小"或
// "末尾允许小包"的启发式规则）。四种用例：
//
// ① coalesceAppend equal gso：新包与现有条目 gsoSize 完全相等（都是 100）
//
//	→ 满足条件，返回 coalesceAppend（可以合并追加）
//
// ② coalesceAppend smaller gso：新包 payload 比条目 gsoSize 小，但
//
//	现有条目之前追加的都是"恰好 gsoSize"的大包；这是 UDP GRO 的"末尾允许
//	一个小于等于 gsoSize 的小包收尾"规则。
//	→ 可以 append（coalesceAppend）
//
// ③ coalesceUnavailable smaller gso previously appended：
//
//	当前条目里最后一个包的 payload < gsoSize（之前已经追加过一个"小包收尾"），
//	此时再新来任何包都不能再追加了（一条 UDP GRO 链只能以"零或一个小包"结尾，
//	不能出现大包跟小包再跟大包的锯齿形）。
//	bufs=[udp4c (payload 110, 大于 gsoSize=100), udp4b (100)]
//	→ 判定 coalesceUnavailable
//
// ④ coalesceUnavailable larger following smaller：
//
//	条目里已有一个 gsoSize=100 收尾，新来的包 payload=110 比 gsoSize 大。
//	UDP GRO 不允许"后面的段比前面大"（会打乱链长单调约束）。
//	→ coalesceUnavailable
//
// 回归防护的性质：
//
//	保证 UDP 合并的四种边界判定（等大、尾部小包、尾部已收过小包、新来比现有大）
//	的返回值完全符合预期，防止 udpPacketsCanCoalesce 判定过松（合并不该合并的）
//	或过严（漏合并合法的）。
func Test_udpPacketsCanCoalesce(t *testing.T) {
	// 基础 UDP4 报文：payload 100 两个（a,b），payload 110 一个（c，比 gso 大）
	udp4a := udp4Packet(ip4PortA, ip4PortB, 100)
	udp4b := udp4Packet(ip4PortA, ip4PortB, 100)
	udp4c := udp4Packet(ip4PortA, ip4PortB, 110)

	type args struct {
		pkt        []byte     // 新候选包（L3 起，带 IP/UDP header）
		iphLen     uint8      // IP 头长度（v4=20，v6=40）
		gsoSize    uint16     // 新候选包 transport payload 大小（去掉 IP+transport head）
		item       udpGROItem // 当前已在 GRO 表中的条目状态
		bufs       [][]byte   // 完整包数组（含 virtio hdr 区），用于回溯最后一个包大小
		bufsOffset int        // bufs 内 offset（一般 = virtioNetHdrLen）
	}
	tests := []struct {
		name string
		args args
		want canCoalesce
	}{
		{
			// ① 候选包 gsoSize=100，条目 gsoSize=100 → 等大 → 可合并
			"coalesceAppend equal gso",
			args{
				pkt:     udp4a[offset:],
				iphLen:  20,
				gsoSize: 100,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				bufs: [][]byte{
					udp4a,
					udp4b,
				},
				bufsOffset: offset,
			},
			coalesceAppend,
		},
		{
			// ② 候选包 payload 比 gsoSize 小（10），允许作为链尾小包
			"coalesceAppend smaller gso",
			args{
				pkt:     udp4a[offset : len(udp4a)-90], // payload 只剩 10 字节
				iphLen:  20,
				gsoSize: 10,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				bufs: [][]byte{
					udp4a,
					udp4b,
				},
				bufsOffset: offset,
			},
			coalesceAppend,
		},
		{
			// ③ 已有条目内最后一个包比 gsoSize 大（c payload=110>100），新来也等大 100
			//   → 之前末尾非标准，不再允许合并
			"coalesceUnavailable smaller gso previously appended",
			args{
				pkt:     udp4a[offset:],
				iphLen:  20,
				gsoSize: 100,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				bufs: [][]byte{
					udp4c, // bufs 中最后一项 payload > gsoSize，锯齿
					udp4b,
				},
				bufsOffset: offset,
			},
			coalesceUnavailable,
		},
		{
			// ④ 新来包 payload=110 > 条目的 gsoSize=100
			//   → 链上不能出现后续更大 payload
			"coalesceUnavailable larger following smaller",
			args{
				pkt:     udp4c[offset:],
				iphLen:  20,
				gsoSize: 110,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				bufs: [][]byte{
					udp4a,
					udp4c,
				},
				bufsOffset: offset,
			},
			coalesceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := udpPacketsCanCoalesce(tt.args.pkt, tt.args.iphLen, tt.args.gsoSize, tt.args.item, tt.args.bufs, tt.args.bufsOffset); got != tt.want {
				t.Errorf("udpPacketsCanCoalesce() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_handleGRO_invalidItemCsumClearsVirtioNetHdr 验证一个关键不变量（invariant）：
//
//	当一个 TCP/UDP 包"作为某流的首个包，但是 checksum 非法"时：
//	  ① 它不会被加入到 GRO 流表（后续同流包无法与它合并）；
//	  ② 它会被直接加入 toWrite 上送（不能丢包）；
//	  ③ 更关键的 invariant：它的 virtio_net_hdr 区域 [0..virtioNetHdrLen-1]
//	     必须被清零（clear）。因为这个包不会再被 handleVirtioRead 等路径
//	     处理（那些路径负责写 virtio hdr 字段），如果不清零，残留的
//	     poison 值（如测试中填充的 0xAB）会被上层错误地当作真实的
//	     virtio 元数据（例如 gsoSize、needsCsum 等）解读，导致错误分段或崩溃。
//
// 测试流程：
//  1. 构造 3 个 TCP 包：#0 flipCSum（坏）、#1 seq101（好）、#2 seq201（好）
//  2. 手动 poison（毒化）#0 前 virtioNetHdrLen 字节全部为 0xAB
//     （这样如果 handleGRO 忘记清零，测试能通过"有任何字节非 0"捕获）
//  3. 跑 handleGRO；
//  4. 断言 toWrite[0] = 0（#0 被直接上送，且是第一个写回项）；
//  5. 断言 TCP 流表中只有 1 条流（A→B），且该流首包 seq=101（#1，而不是 #0）、
//     numMerged=1（仅合并了 #1 + #2）—— 证明 #0 从未进表；
//  6. 最后关键断言：pkts[0] 的前 virtioNetHdrLen 字节必须全部 == 0，
//     证明 handleGRO 正确调用了 clear 清除了残留的 0xAB poison。
//
// 回归防护的性质：
//
//	保证 csum 失败、不入 GRO 表的"首包"的 virtio_net_hdr 被清零的 invariant，
//	防止"poison 字节残留被上层解读成真实 virtio 标志"引发的错误。
//	（典型症状：gsoType=0xABAB 导致 handleVirtioWrite 走错误分支、
//	needsCsum 位错误导致 checksum 不补、随机崩溃）。
func Test_handleGRO_invalidItemCsumClearsVirtioNetHdr(t *testing.T) {
	pkts := [][]byte{
		flipTCP4Checksum(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)),
		tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101),
		tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),
	}
	// Poison the virtioNetHdr region of pkts[0] so a missing clear() is detectable.
	// 毒化：把首包 virtio 区全填 0xAB，验证是否被清零
	for i := 0; i < virtioNetHdrLen; i++ {
		pkts[0][i] = 0xAB
	}

	table := newTCPGROTable()
	toWrite := make([]int, 0, len(pkts))
	if err := handleGRO(pkts, virtioNetHdrLen, table, newUDPGROTable(), false, &toWrite); err != nil {
		t.Fatal(err)
	}

	// Verify pkts[0] is in toWrite where we expect
	// 期望 pkts[0] 位于 toWrite[0]（直接上送）
	if toWrite[0] != 0 {
		t.Fatal("pkts[0] not found in toWrite at expected, zero index")
	}

	// Verify pkts[0] is not in tcpGROTable
	// 期望 #0 从未进表；表中只有 1 条 A→B 流，且首包是 #1 (seq 101)
	if len(table.itemsByFlow) != 1 {
		t.Fatalf("unexpected tcpGROTable items len: %d", len(table.itemsByFlow))
	}
	for _, v := range table.itemsByFlow {
		if len(v) != 1 {
			t.Fatalf("unexpected tcpGROItems slice len: %d", len(v))
		}
		item := v[0]
		// 首包 seq=101 对应 pkt#1，证明 pkt#0 未进表
		if item.sentSeq != 101 {
			t.Fatalf("unexpected starting seq num in tcpGROTable: %d", item.sentSeq)
		}
		// pkt#1 作为链首，合并了 pkt#2 → numMerged=1（合并次数）
		if item.numMerged != 1 {
			t.Fatalf("unexpected numMerged in tcpGROTable: %d", item.numMerged)
		}
	}

	// pkt 0 is in toWrite and not present in tcpGROTable, so its virtioNetHdr
	// must have been cleared.
	// 关键 invariant：pkts[0] 前 virtioNetHdrLen 字节必须全部为 0
	for i, b := range pkts[0][:virtioNetHdrLen] {
		if b != 0 {
			t.Fatalf("pkts[0] virtioNetHdr[%d] = 0x%x, want 0", i, b)
		}
	}
}
