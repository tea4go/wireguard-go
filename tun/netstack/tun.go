/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// netstack 包基于 gVisor netstack 实现了一个完整的用户态 TCP/UDP/ICMP 协议栈
// + 内置 DNS 解析器，作为 WireGuard 的 TUN 设备后端。
// 相比 tuntest 的纯通道模拟，netstack 能够真正理解和处理三层/四层协议，
// 支持在用户态发起 TCP/UDP/Ping 连接及 DNS 查询，无需操作系统网络栈参与。
package netstack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netTun 是基于 gVisor netstack 的 TUN 设备核心结构体
// 它同时扮演两个角色：
//  1. 实现 tun.Device 接口，作为 WireGuard 的 TUN 后端
//  2. 承载 gVisor 协议栈实例，通过 Net 别名对外暴露 Dial/Listen/Lookup 等网络能力
//
// 字段说明:
//   - ep:             gvisor link/channel Endpoint，是 WireGuard 与协议栈之间的报文收发桥梁
//     WireGuard Write() 的报文通过 ep.InjectInbound 注入协议栈；
//     协议栈发出的报文通过 ep.Read() 读出交给 WriteNotify
//   - stack:          gVisor 协议栈（*stack.Stack），集成 IPv4/IPv6/TCP/UDP/ICMP 的完整实现
//   - events:         TUN 事件通道（EventUp 等），容量 10
//   - notifyHandle:   channel.Endpoint 的写通知句柄，协议栈有包要发时通过 WriteNotify 回调通知
//   - incomingPacket: 协议栈待发给 WireGuard 的报文缓冲通道（元素为 *buffer.View）
//     WriteNotify 写入，Read 读出，模拟 TUN "read" 方向
//   - mtu:            最大传输单元
//   - dnsServers:     上游 DNS 服务器地址列表，供内置 DNS 解析器使用
//   - hasV4/hasV6:    标记本地是否已绑定 IPv4/IPv6 地址（双栈能力标志）
type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
	hasV4, hasV6   bool
}

// Net 是 netTun 的公开别名类型
// 作用：让 netTun 结构体既能作为 tun.Device 接口的内部实现，
// 又能通过 *Net 对外暴露 Dial/Listen/LookupHost 等高层网络 API。
// （因为 CreateNetTUN 同时返回 (tun.Device, *Net)，两者内部指向同一内存）
type Net netTun

// CreateNetTUN 创建并初始化一个基于 gVisor netstack 的 TUN 设备
//
// 参数:
//   - localAddresses: 本地要绑定的 IP 地址列表（可以是 IPv4/IPv6 混合）
//   - dnsServers:     DNS 解析时使用的上游服务器列表
//   - mtu:            接口 MTU 值
//
// 返回:
//   - tun.Device: 实现了 TUN 接口的 netTun 实例（供 WireGuard 使用）
//   - *Net:       公开网络能力句柄（供应用层 Dial/Listen/Resolve 等）
//   - error:      初始化失败原因
//
// 初始化步骤:
//  1. 构造 stack.Options：
//     - NetworkProtocols:   注册 IPv4 + IPv6 网络层协议
//     - TransportProtocols: 注册 TCP + UDP + ICMPv4 + ICMPv6 传输层协议
//     - HandleLocal=true:   允许协议栈处理本地回环/本地目标地址的流量
//  2. 创建 channel.Endpoint(队列深度 1024, mtu, "") 作为 link 层端点
//  3. 创建 gVisor Stack 实例
//  4. 开启 TCP SACK（Selective Acknowledgment，默认在 gVisor 中是关闭的，显式开启提升性能）
//  5. AddNotify 注册写通知回调（协议栈有包要出 TUN 时回调 WriteNotify）
//  6. CreateNIC(nicID=1) 把 channel.EP 绑定为编号 1 的网卡
//  7. 逐个绑定 localAddresses：根据 v4/v6 选择协议号，AddProtocolAddress 绑定到 nic 1，
//     同时标记 hasV4 / hasV6 双栈标志
//  8. 若 hasV4 则加入 IPv4 默认路由 (0.0.0.0/0 → NIC 1)；同理 IPv6
//  9. 写入 tun.EventUp 事件，模拟网卡启用
func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error) {
	opts := stack.Options{
		// 注册网络层协议：IPv4 和 IPv6
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		// 注册传输层协议：TCP、UDP、ICMPv6、ICMPv4
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true, // 允许处理目的地址为本地的报文（本地回环）
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""), // channel EP: 队列深度1024, MTU, 空MAC
		stack:          stack.New(opts),                    // 创建 gVisor 协议栈
		events:         make(chan tun.Event, 10),           // TUN 事件缓冲通道
		incomingPacket: make(chan *buffer.View),            // 协议栈→WireGuard 的报文通道
		dnsServers:     dnsServers,
		mtu:            mtu,
	}
	// TCP SACK 支持在 gVisor 中默认关闭，这里显式开启以优化 TCP 性能
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	// 注册写通知回调：当协议栈有报文要从 EP 发出时，回调 dev.WriteNotify
	dev.notifyHandle = dev.ep.AddNotify(dev)
	// 创建编号为 1 的 NIC，将 channel.EP 绑定为该网卡的 link 层
	tcpipErr = dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	// 逐个绑定本地 IP 地址到 NIC 1
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		// 记录双栈能力标志
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	// 加入默认路由表项：让协议栈知道非本地报文都走 NIC 1
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1}) // 0.0.0.0/0
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1}) // ::/0
	}

	dev.events <- tun.EventUp // TUN Up 事件，通知 WireGuard 可以开始收发
	return dev, (*Net)(dev), nil
}

// Name 返回 TUN 设备名，用户态 netstack 固定返回 "go"
func (tun *netTun) Name() (string, error) {
	return "go", nil
}

// File 返回底层 OS 文件描述符，用户态实现无 fd 故返回 nil
func (tun *netTun) File() *os.File {
	return nil
}

// Events 返回 TUN 事件只读通道，供 WireGuard 监听 Up/Down 状态
func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

// Read 实现 tun.Device.Read：从协议栈读取"要交给 WireGuard 加密/转发"的报文
//
// 数据流: incomingPacket 通道 → view 读入 buf[0][offset:] → sizes[0]=n
//
// 行为:
//   - 阻塞等待 incomingPacket 有数据（由 WriteNotify 写入）
//   - 若通道已关闭 → 返回 (0, os.ErrClosed)
//   - view.Read 把报文数据读入 WireGuard 缓冲区的偏移位置
//   - sizes[0] 填入实际字节数，返回 1 个包
func (tun *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write 实现 tun.Device.Write：WireGuard 解密后的路由报文通过此函数注入协议栈
//
// 数据流: buf[i][offset:] → 识别 v4/v6 → ep.InjectInbound(proto, pkt)
//
// 行为:
//   - 对每个 packet，跳过 offset 前缀得到实际的 IP 报文
//   - 通过 packet[0] 高 4 位（IP 版本号）识别 IPv4(4)/IPv6(6)
//   - 调用 ep.InjectInbound 把包注入 gVisor 协议栈的对应网络层
//   - 不支持的协议族返回 syscall.EAFNOSUPPORT
func (tun *netTun) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 { // IP 版本号在第 1 字节高 4 位
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

// WriteNotify 是 channel.Endpoint 的写通知回调（通过 AddNotify 注册）
// 当 gVisor 协议栈有报文要经 TUN 发出（如 TCP 握手包、UDP 数据报、Ping Reply）时触发。
//
// 流程:
//  1. ep.Read() 从 link 层 channel 读出一个 PacketBuffer（协议栈产出的包）
//  2. 若 nil 表示无包则直接返回（被 drain 掉了）
//  3. pkt.ToView() 把 PacketBuffer 转换为可顺序读取的 buffer.View
//  4. pkt.DecRef() 减少引用计数（协议栈不再持有）
//  5. view 写入 incomingPacket 通道，等待 Read() 被 WireGuard 取走
func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

// Close 关闭 TUN 设备，按顺序释放 gVisor 资源 + 关闭 Go 通道
//
// 关闭顺序（重要，避免竞态）:
//  1. stack.RemoveNIC(1)      从协议栈摘除 NIC，停止路由
//  2. stack.Close()           关闭整个协议栈实例，释放其内部 goroutine
//  3. ep.RemoveNotify()       取消 WriteNotify 回调注册（防止关闭后仍触发）
//  4. ep.Close()              关闭 channel Endpoint
//  5. close(events)           关闭事件通道（若存在）
//  6. close(incomingPacket)   关闭报文通道，让阻塞的 Read() 立即返回 ErrClosed
func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)
	tun.stack.Close()
	tun.ep.RemoveNotify(tun.notifyHandle)
	tun.ep.Close()

	if tun.events != nil {
		close(tun.events)
	}

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

// MTU 返回接口最大传输单元
func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

// BatchSize 返回批量读写包数；netstack 实现一次只处理 1 个包
func (tun *netTun) BatchSize() int {
	return 1
}

// convertToFullAddr 把标准库的 netip.AddrPort 转换为 gVisor 需要的
// (tcpip.FullAddress, tcpip.NetworkProtocolNumber) 二元组
//
// 转换规则:
//   - NIC 固定为 1（CreateNetTUN 中创建的网卡编号）
//   - 根据 Addr().Is4() 判断协议号：IPv4 或 IPv6
//   - Port 直接透传
func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

// ========== 以下 4 个是 TCP 相关 Dial/Listen 函数 ==========
// 它们都通过 gonet.Adapter（gVisor 对标准库 net.Conn/net.Listener 的适配层）
// 把 gVisor 协议栈的原生端点包装成标准库风格的 *gonet.TCPConn / *gonet.TCPListener

// DialContextTCPAddrPort 使用 netip.AddrPort 发起带 context 的 TCP 拨号
func (net *Net) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, net.stack, fa, pn)
}

// DialContextTCP 接受 *net.TCPAddr 形式，转换后转调 DialContextTCPAddrPort
// 若 addr==nil 则使用零值 AddrPort（相当于未指定地址，一般会失败）
func (net *Net) DialContextTCP(ctx context.Context, addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialContextTCPAddrPort(ctx, netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(addr.Port)))
}

// DialTCPAddrPort 使用 netip.AddrPort 发起无 context 的 TCP 拨号
func (net *Net) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialTCP(net.stack, fa, pn)
}

// DialTCP 接受 *net.TCPAddr 形式，转换后转调 DialTCPAddrPort
func (net *Net) DialTCP(addr *net.TCPAddr) (*gonet.TCPConn, error) {
	if addr == nil {
		return net.DialTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.DialTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

// ListenTCPAddrPort 在指定 netip.AddrPort 上开启 TCP 监听
func (net *Net) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.ListenTCP(net.stack, fa, pn)
}

// ListenTCP 接受 *net.TCPAddr 形式，转换后转调 ListenTCPAddrPort
func (net *Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	if addr == nil {
		return net.ListenTCPAddrPort(netip.AddrPort{})
	}
	ip, _ := netip.AddrFromSlice(addr.IP)
	return net.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(addr.Port)))
}

// ========== 以下是 UDP 相关 Dial/Listen 函数 ==========

// DialUDPAddrPort 使用两个 netip.AddrPort（本端 laddr / 对端 raddr）创建 UDP "已连接"端点
// UDP 的 "Dial" 语义：绑定本地地址 + 记住对端地址，后续 Write 自动发往该对端，
// Read 只接收来自该对端的数据。
//
// laddr/raddr 任一地址合法(IsValid)或端口>0 即参与构造 FullAddress
// 返回的 *gonet.UDPConn 可通过标准 net.Conn 接口使用
func (net *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	var lfa, rfa *tcpip.FullAddress
	var pn tcpip.NetworkProtocolNumber
	if laddr.IsValid() || laddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(laddr)
		lfa = &addr
	}
	if raddr.IsValid() || raddr.Port() > 0 {
		var addr tcpip.FullAddress
		addr, pn = convertToFullAddr(raddr)
		rfa = &addr
	}
	return gonet.DialUDP(net.stack, lfa, rfa, pn)
}

// ListenUDPAddrPort 是"监听 UDP"的便捷写法
// 语义等价于 DialUDPAddrPort(laddr, 零值) —— 只绑定本地地址，不预设对端。
// （UDP 本无 Listen 语义，标准库也是把 ListenUDP 实现为"绑定本地、未连接的 UDP 端点"）
func (net *Net) ListenUDPAddrPort(laddr netip.AddrPort) (*gonet.UDPConn, error) {
	return net.DialUDPAddrPort(laddr, netip.AddrPort{})
}

// DialUDP 接受 *net.UDPAddr 形式，转换后转调 DialUDPAddrPort
func (net *Net) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	var la, ra netip.AddrPort
	if laddr != nil {
		ip, _ := netip.AddrFromSlice(laddr.IP)
		la = netip.AddrPortFrom(ip, uint16(laddr.Port))
	}
	if raddr != nil {
		ip, _ := netip.AddrFromSlice(raddr.IP)
		ra = netip.AddrPortFrom(ip, uint16(raddr.Port))
	}
	return net.DialUDPAddrPort(la, ra)
}

// ListenUDP 接受 *net.UDPAddr 形式，等价于 DialUDP(laddr, nil)
func (net *Net) ListenUDP(laddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return net.DialUDP(laddr, nil)
}

// ========== 以下是 Ping (ICMP) 连接相关实现 ==========
// 由于标准库没有 net.PingConn，这里自定义了 PingConn + PingAddr，
// 同时满足 net.Addr 接口（LocalAddr/RemoteAddr）和 net.Conn/PacketConn 的基本能力。

// PingConn 表示一个 ICMP Echo (Ping) 的"连接"端点
// 支持：Bind 本地地址 / Connect 对端地址 / 读写 / 截止时间
//
// 字段:
//   - laddr:    本地 Ping 地址（实现 net.Addr）
//   - raddr:    远端 Ping 地址（实现 net.Addr）
//   - wq:       gVisor waiter.Queue，用于等待端点可读事件（I/O 多路复用）
//   - ep:       gVisor 原生 Endpoint（实际的 ICMP 套接字）
//   - deadline: 读截止时间定时器，初始设为极长然后 Stop，需要时再 Reset
type PingConn struct {
	laddr    PingAddr
	raddr    PingAddr
	wq       waiter.Queue
	ep       tcpip.Endpoint
	deadline *time.Timer
}

// PingAddr 实现 net.Addr 接口，表示 ICMP 端点地址（仅含 IP，无端口概念）
// Network() 返回 "ping4" / "ping6" / "ping"，String() 返回 IP 文本
type PingAddr struct{ addr netip.Addr }

// String 返回 IP 地址的字符串形式（net.Addr 接口）
func (ia PingAddr) String() string {
	return ia.addr.String()
}

// Network 返回网络类型名（net.Addr 接口）
//   - IPv4 → "ping4"
//   - IPv6 → "ping6"
//   - 其他 → "ping"
func (ia PingAddr) Network() string {
	if ia.addr.Is4() {
		return "ping4"
	} else if ia.addr.Is6() {
		return "ping6"
	}
	return "ping"
}

// Addr 返回底层 netip.Addr
func (ia PingAddr) Addr() netip.Addr {
	return ia.addr
}

// PingAddrFromAddr 从 netip.Addr 构造 *PingAddr
func PingAddrFromAddr(addr netip.Addr) *PingAddr {
	return &PingAddr{addr}
}

// DialPingAddr 创建一个 PingConn（ICMP Echo 端点）
//   - laddr: 本地绑定地址；若无效(IsValid==false) 则根据 raddr 地址族选 unspec (0.0.0.0 / ::)
//   - raddr: 远端连接地址；若有效则执行 Connect（之后 Write() 不用写地址）
//
// 流程:
//  1. 参数校验（laddr/raddr 至少有一个有效）
//  2. 判断 v4/v6：任一端为 v6 即视为 v6；选对应的 ICMP 协议号 (ProtocolNumber4/6) 和网络层协议号
//  3. 创建 PingConn：
//     - deadline 初始设为 time.Hour << 10（约 109 万亿小时，等同于"无限远"），随后 Stop 停用
//     这样做的原因是 waiter 需要定时器对象存在，即使暂时不需要截止时间
//  4. net.stack.NewEndpoint(tn, pn, wq) 创建 gVisor ICMP 端点
//  5. 若 laddr 有效（bind=true）→ ep.Bind 绑定本地地址
//  6. 若 raddr 有效 → ep.Connect 连接对端，记录 raddr
func (net *Net) DialPingAddr(laddr, raddr netip.Addr) (*PingConn, error) {
	if !laddr.IsValid() && !raddr.IsValid() {
		return nil, errors.New("ping dial: invalid address")
	}
	v6 := laddr.Is6() || raddr.Is6()
	bind := laddr.IsValid()
	if !bind {
		// laddr 无效，按 raddr 族选择合适的未指定地址作为本地
		if v6 {
			laddr = netip.IPv6Unspecified()
		} else {
			laddr = netip.IPv4Unspecified()
		}
	}

	// 根据 v4/v6 选择对应的 gVisor ICMP 传输协议号 + IP 网络协议号
	tn := icmp.ProtocolNumber4
	pn := ipv4.ProtocolNumber
	if v6 {
		tn = icmp.ProtocolNumber6
		pn = ipv6.ProtocolNumber
	}

	pc := &PingConn{
		laddr:    PingAddr{laddr},
		deadline: time.NewTimer(time.Hour << 10), // 初始截止时间极远（占位）
	}
	pc.deadline.Stop() // 停用：此时无实际截止时间

	// 创建 gVisor ICMP 端点，关联 waiter 队列
	ep, tcpipErr := net.stack.NewEndpoint(tn, pn, &pc.wq)
	if tcpipErr != nil {
		return nil, fmt.Errorf("ping socket: endpoint: %s", tcpipErr)
	}
	pc.ep = ep

	// 绑定本地地址（如有）
	if bind {
		fa, _ := convertToFullAddr(netip.AddrPortFrom(laddr, 0))
		if tcpipErr = pc.ep.Bind(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping bind: %s", tcpipErr)
		}
	}

	// 连接远端地址（如有）
	if raddr.IsValid() {
		pc.raddr = PingAddr{raddr}
		fa, _ := convertToFullAddr(netip.AddrPortFrom(raddr, 0))
		if tcpipErr = pc.ep.Connect(fa); tcpipErr != nil {
			return nil, fmt.Errorf("ping connect: %s", tcpipErr)
		}
	}

	return pc, nil
}

// ListenPingAddr "监听" Ping 等价于只 Bind 本地地址、不 Connect 远端
// 实现就是转调 DialPingAddr(laddr, 零值Addr)
func (net *Net) ListenPingAddr(laddr netip.Addr) (*PingConn, error) {
	return net.DialPingAddr(laddr, netip.Addr{})
}

// DialPing 接受 *PingAddr 指针形式（任一可为 nil），转换后转调 DialPingAddr
func (net *Net) DialPing(laddr, raddr *PingAddr) (*PingConn, error) {
	var la, ra netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	if raddr != nil {
		ra = raddr.addr
	}
	return net.DialPingAddr(la, ra)
}

// ListenPing 接受 *PingAddr，等价于 ListenPingAddr
func (net *Net) ListenPing(laddr *PingAddr) (*PingConn, error) {
	var la netip.Addr
	if laddr != nil {
		la = laddr.addr
	}
	return net.ListenPingAddr(la)
}

// LocalAddr 返回本地地址（net.Conn 接口）
func (pc *PingConn) LocalAddr() net.Addr {
	return pc.laddr
}

// RemoteAddr 返回远端地址（net.Conn 接口）
func (pc *PingConn) RemoteAddr() net.Addr {
	return pc.raddr
}

// Close 关闭 Ping 端点：截止定时器归零 + 关闭 gVisor Endpoint
func (pc *PingConn) Close() error {
	pc.deadline.Reset(0)
	pc.ep.Close()
	return nil
}

// SetWriteDeadline 未实现（ICMP Write 本身是无阻塞/快速失败的）
func (pc *PingConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

// WriteTo 实现 net.PacketConn：向指定 addr 写入 ICMP 数据
//
// 步骤:
//  1. addr 类型断言：接受 *PingAddr 或 *net.IPAddr，提取出 netip.Addr (na)
//  2. 协议一致性检查：na 和本地 laddr 必须属于同一 IP 版本（都是 v4 或都是 v6）
//  3. 把 p 包装成 bytes.Reader；把 na 转换为 gVisor FullAddress(rfa)
//  4. ep.Write 写入（不会阻塞，因为暂未实现写截止）
func (pc *PingConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var na netip.Addr
	switch v := addr.(type) {
	case *PingAddr:
		na = v.addr
	case *net.IPAddr:
		na, _ = netip.AddrFromSlice(v.IP)
	default:
		return 0, fmt.Errorf("ping write: wrong net.Addr type")
	}
	// 协议一致性：IP 版本必须匹配
	if !((na.Is4() && pc.laddr.addr.Is4()) || (na.Is6() && pc.laddr.addr.Is6())) {
		return 0, fmt.Errorf("ping write: mismatched protocols")
	}

	buf := bytes.NewReader(p)
	rfa, _ := convertToFullAddr(netip.AddrPortFrom(na, 0))
	// won't block, no deadlines
	n64, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &rfa,
	})
	if tcpipErr != nil {
		return int(n64), fmt.Errorf("ping write: %s", tcpipErr)
	}

	return int(n64), nil
}

// Write 实现 net.Conn：向已 Connect 的 raddr 写入，内部转调 WriteTo(&pc.raddr)
func (pc *PingConn) Write(p []byte) (n int, err error) {
	return pc.WriteTo(p, &pc.raddr)
}

// ReadFrom 实现 net.PacketConn：从端点读取一个 ICMP 包，并返回远端地址
//
// 步骤:
//  1. waiter.NewChannelEntry(waiter.EventIn) 创建"可读"事件通知通道
//  2. 注册到 wq；defer 注销
//  3. select 等待两个事件：
//     - deadline.C 到期 → 返回 os.ErrDeadlineExceeded
//     - notifyCh 可读（端点有数据）→ 继续
//  4. tcpip.SliceWriter(p) 包装用户缓冲区
//  5. ep.Read 读取，NeedRemoteAddr=true 要求同时返回远端地址
//  6. 远端地址转换为 *PingAddr 返回
func (pc *PingConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	e, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&e)
	defer pc.wq.EventUnregister(&e)

	select {
	case <-pc.deadline.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)

	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		return 0, nil, fmt.Errorf("ping read: %s", tcpipErr)
	}

	remoteAddr, _ := netip.AddrFromSlice(res.RemoteAddr.Addr.AsSlice())
	return res.Count, &PingAddr{remoteAddr}, nil
}

// Read 实现 net.Conn：读取但丢弃远端地址信息
func (pc *PingConn) Read(p []byte) (n int, err error) {
	n, _, err = pc.ReadFrom(p)
	return
}

// SetDeadline 同时设置读写截止时间
// 由于写截止未实现，此处只设置读截止（注释已说明）
func (pc *PingConn) SetDeadline(t time.Time) error {
	// pc.SetWriteDeadline is unimplemented

	return pc.SetReadDeadline(t)
}

// SetReadDeadline 设置读截止时间：重置 deadline 定时器为 time.Until(t)
func (pc *PingConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}

// ========== 以下为内置 DNS 解析器实现 ==========
// 完全在用户态实现：报文构造 + UDP/TCP 传输 + 响应解析 + Happy Eyeballs 风格的拨号超时

// 9 个模拟标准库风格的 DNS / 网络错误变量
var (
	errNoSuchHost                   = errors.New("no such host")                 // NXDOMAIN：域名不存在
	errLameReferral                 = errors.New("lame referral")                // Lame 委托：服务器非权威且不支持递归、也无 Answer
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message") // DNS 响应解析失败
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")   // DNS 请求构造失败
	errServerMisbehaving            = errors.New("server misbehaving")           // 服务器行为异常（永久错）
	errInvalidDNSResponse           = errors.New("invalid DNS response")         // 响应 ID/问题不匹配等
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")    // 服务器无应答（UDP+TCP 均失败）
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")           // 服务器临时异常（如 SERVFAIL，可重试）
	errCanceled                     = errors.New("operation was canceled")       // 操作被取消（context.Canceled 映射）
	errTimeout                      = errors.New("i/o timeout")                  // I/O 超时（context.DeadlineExceeded 映射）
	errNumericPort                  = errors.New("port must be numeric")         // 端口必须是数字
	errNoSuitableAddress            = errors.New("no suitable address found")    // 没有匹配协议族的地址
	errMissingAddress               = errors.New("missing address")              // 地址列表为空
)

// LookupHost 是 LookupContextHost 的 Background 版本（无 context）
func (net *Net) LookupHost(host string) (addrs []string, err error) {
	return net.LookupContextHost(context.Background(), host)
}

// isDomainName 按照 RFC 1035 文法校验字符串是否为合法域名
// 同时通过"必须包含非数字字符"规则，把纯数字 IP 字面量（1.2.3.4）排除在外。
//
// 规则（对应 RFC1035 + Go 标准库 net 包实现）:
//   - 总长度 ∈ [1, 253]；若长度==254 则必须以 '.' 结尾（FQDN 绝对域名尾点）
//   - 每个标号(label, 两个 '.' 之间的段) 长度 ∈ [1, 63]
//   - 标号不能以 '-' 开头或结尾
//   - 标号允许字符：字母 a-z/A-Z、数字 0-9、下划线 _、连字符 -、分隔符 .
//   - 整个字符串必须包含至少一个非数字字符（避免把 "1.2.3.4" 误判为域名）
//   - 不能出现连续的 '.'
func isDomainName(s string) bool {
	l := len(s)
	// 总长校验：0 或 >254 非法；等于 254 但最后不是 '.' 也非法
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')   // 前一个字符，初始为 '.' 用于处理标号首字符约束
	nonNumeric := false // 是否出现了非数字字符（用于区分 IP 字面量）
	partlen := 0        // 当前标号已扫描长度
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false // 其他字符一律非法
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			// '-' 不能作为标号首字符（前一个字符是 '.' 代表标号开头）
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// 不能连续 '.'，也不能以 '-' 结尾一个标号
			if last == '.' || last == '-' {
				return false
			}
			// 标号长度超出 63 或为 0（空标号）
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	// 结尾检查：不能以 '-' 结束；最后一个标号长度也不能超过 63
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric // 必须存在非数字字符（否则是纯数字 IP 字面量）
}

// randU16 使用 crypto/rand 生成一个随机的 uint16（用作 DNS Transaction ID）
// 读取失败则 panic（因为密码学随机源不可用是严重错误）
func randU16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

// newRequest 构造一个 DNS 查询请求
//
// 参数: q - 问题（域名 + 类型 + 类）
// 返回:
//   - id:      随机生成的事务 ID（用于匹配响应）
//   - udpReq:  UDP 请求体（不含长度前缀，直接 512 字节以内发送）
//   - tcpReq:  TCP 请求体 = [2字节大端长度前缀][UDP 请求体内容]
//
// 构造细节:
//   - ID 随机；RecursionDesired=true（要求递归查询）
//   - EnableCompression() 开启 DNS 名字压缩
//   - 只有一个 Question
//   - Builder 在 Finish() 时返回的是 [2字节占位长度?][DNS报文] — 这里通过把
//     Finish 的结果直接作为 tcpReq，然后 tcpReq[2:] 截掉前 2 字节作为 udpReq，
//     再把真实长度 (len(tcpReq)-2) 写回前两字节的"大端长度前缀"，一次复用两次使用
func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = randU16()
	// 初始 buf 预分配 2+512=514 字节，头部带 ID + 递归期望标志
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression() // 启用 DNS 名字压缩，减少报文体积
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	// Finish 输出结果：[2字节前缀][实际DNS报文]；我们把前者当作 TCP 长度前缀使用
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]      // UDP 不需要长度前缀，去掉前 2 字节
	l := len(tcpReq) - 2     // 实际 DNS 报文长度 = 总长度 - 2 字节前缀
	tcpReq[0] = byte(l >> 8) // 长度高字节（大端）
	tcpReq[1] = byte(l)      // 长度低字节（大端）
	return id, udpReq, tcpReq, err
}

// equalASCIIName 大小写不敏感地比较两个 DNS 名字 (dnsmessage.Name) 是否相同
// DNS 域名在 ASCII 范围内是大小写不敏感的，按照 RFC 4343 进行比较
func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		// 把大写字母 (A-Z) 统一转换为小写：ASCII 大写+0x20 = 小写
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

// checkResponse 校验 DNS 响应是否匹配请求
//   - Response 位必须为 1（表示这是响应而非请求）
//   - 事务 ID 必须与请求一致
//   - Question 段的 Type/Class/Name 必须与请求的 Question 完全匹配
func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

// dnsPacketRoundTrip 实现 UDP 上的 DNS 请求/响应往返
//
// 特性:
//   - 写入请求，然后循环读取响应（UDP 可能收到乱序/无关响应，因此循环过滤）
//   - 每次读 512 字节（DNS UDP 传统上限，不带 EDNS 时）
//   - 若响应无法 Start / Question 不匹配 / checkResponse 失败 → continue 跳过继续读
//   - 找到匹配响应后返回 (Parser, Header, nil)
func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512) // DNS over UDP 默认最大 512 字节
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue // 解析失败，跳过此响应继续读
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue // Question 不匹配或格式异常，跳过
		}
		return p, h, nil
	}
}

// dnsStreamRoundTrip 实现 TCP 上的 DNS 请求/响应往返
//
// DNS over TCP 的帧格式: [2字节大端长度N][N字节DNS报文]
// 步骤:
//  1. 写入 tcpReq（已含 2 字节长度前缀）
//  2. 先 ReadFull 读取 2 字节长度，得到 l
//  3. 再 ReadFull 读取 l 字节完整 DNS 报文
//  4. 解析并 checkResponse；此处 UDP 那种"跳过畸形响应"不成立（因为 TCP 是字节流，
//     若读到的响应不匹配则已经无法回溯，只能直接报错）
func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280) // 初始缓冲 1280 字节（足够容纳常见 TCP DNS 响应）
	// 第一步：读 2 字节长度前缀
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	// 响应过大则扩展缓冲
	if l > len(b) {
		b = make([]byte, l)
	}
	// 第二步：ReadFull 读取完整 DNS 报文
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

// exchange 对单一 DNS 服务器执行一次查询：先 UDP，若返回被截断则 fallback 到 TCP
//
// 参数:
//   - ctx:     上下文（超时/取消）
//   - server:  服务器 IP（端口固定 53）
//   - q:       DNS Question（注意 Class 会被强制为 INET）
//   - timeout: 单次查询的超时（同时设置到 net.Conn 的 Deadline）
//
// 流程:
//  1. q.Class 强制设为 INET
//  2. newRequest 生成 id / udpReq / tcpReq
//  3. 先 useUDP=true 尝试:
//     a. 带 deadline 的 context 派生
//     b. 通过 netstack 自己的 DialUDP 连到 server:53
//     c. 设置 socket deadline
//     d. dnsPacketRoundTrip 完成 UDP 查询
//  4. UDP 结束后，若 h.Truncated == true（TC 位，响应被截断）→ continue，走 TCP
//     否则直接返回结果
//  5. 再 useUDP=false 尝试: 走 DialContextTCP + dnsStreamRoundTrip
//  6. 两次都失败 → errNoAnswerFromDNSServer
//  7. context.Canceled → errCanceled，context.DeadlineExceeded → errTimeout
func (tnet *Net) exchange(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	// 两轮尝试：[UDP 优先, TCP 兜底]
	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var c net.Conn
		var err error
		if useUDP {
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		} else {
			c, err = tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server, 53))
		}

		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		// 设置 socket deadline（与 context deadline 对齐）
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			// context 错误映射为我们定义的标准错误变量
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		// 跳过 Question 段，验证已解析完毕
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue // UDP 响应被截断 → 回退 TCP
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

// checkHeader 检查 DNS 响应头与 Answer 段的开头，判定是否存在协议级错误
//
// 错误映射规则:
//   - RCode == NXDOMAIN (NameError) → errNoSuchHost（域名不存在）
//   - RCode == Success 且 AA==0 且 RA==0 且 Answer 段为空 → errLameReferral
//     (Lame referral: 服务器既不是权威，也不提供递归，也没有给出任何答案)
//   - RCode != Success && != NameError:
//     · RCode == ServerFailure (SERVFAIL) → errServerTemporarilyMisbehaving（临时错误，可重试）
//     · 其他 → errServerMisbehaving（永久错误）
//   - 解析 AnswerHeader 出现非 ErrSectionDone 的错误 → errCannotUnmarshalDNSMessage
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	// Lame referral：RCode=成功，但 AA=0 RA=0 且无 Answer
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	// 其他失败 RCode
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving // SERVFAIL 被视为临时错误
		}
		return errServerMisbehaving // 其他（FORMERR/NOTIMP/REFUSED 等）视为永久错误
	}
	return nil
}

// skipToAnswer 从 Answer 段跳过类型不为 qtype 的记录（如 CNAME、NS 等）
// 直到找到一个类型为 qtype 的 Answer Header 时返回 nil，让调用方接着读取资源数据
//
//   - Answer 段全部读完仍无目标类型 → errNoSuchHost
//   - 解析错误 → errCannotUnmarshalDNSMessage
func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil // 找到匹配的 Answer
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

// tryOneName 对单个名称 + 单个查询类型，向所有 DNS 服务器进行"每服务器 2 次重试 × 轮询"
// 封装标准库风格的 *net.DNSError（含 IsTimeout/IsTemporary/IsNotFound 标志位）
//
// 流程:
//  1. 把 name 字符串构造为 dnsmessage.Name；失败 → errCannotMarshalDNSMessage
//  2. 外层 2 次重试循环 (i=0..1)
//  3. 内层轮询 dnsServers：
//     a. exchange(ctx, server, q, 5s) 完成 UDP+TCP 查询
//     b. exchange 出错 → 构造 DNSError，根据错误类型打 Timeout/Temporary 标记，记录为 lastErr，continue
//     c. checkHeader 校验响应头 → 出错则类似处理；errNoSuchHost 特殊处理（IsNotFound=true 且立即返回不再重试）
//     d. skipToAnswer 找到目标类型 Answer → 成功返回 (Parser, server, nil)
//  4. 全部服务器 + 全部重试均失败 → 返回 lastErr
func (tnet *Net) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	// 每个服务器尝试 2 次
	for i := 0; i < 2; i++ {
		for _, server := range tnet.dnsServers {
			p, h, err := tnet.exchange(ctx, server, q, time.Second*5)
			if err != nil {
				// 把错误包装为 *net.DNSError，带上 timeout/temporary 标志
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == errNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr // NXDOMAIN 直接返回，不再重试
				}
				lastErr = dnsErr
				continue
			}

			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil // 找到目标 Answer，成功
			}
			lastErr = &net.DNSError{
				Err:    err.Error(),
				Name:   name,
				Server: server.String(),
			}
			if err == errNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

// LookupContextHost 是内置 DNS 解析器的主入口，将主机名解析为 IP 地址列表
//
// 解析策略:
//  1. 空 host 或本机无任何 IP 能力 → 直接 errNoSuchHost
//  2. 若是字面量 IP (IPv4 或带 zone 的 IPv6) → 直接返回 [ip.String()]
//     （IPv6 可能包含 %zone，先截掉 zone 部分再 ParseAddr）
//  3. isDomainName 校验失败（例如纯数字串、非法字符）→ errNoSuchHost
//  4. 双栈并发查询 A + AAAA（goroutine + 带缓冲 channel 汇总）：
//     · hasV4 → goroutine tryOneName(host+".", TypeA)
//     · hasV6 → goroutine tryOneName(host+".", TypeAAAA)
//  5. 收集每个 lane 的结果：
//     · 循环 Answer 段；TypeA → AResource() → netip.AddrFrom4 加入 addrsV4
//     TypeAAAA → AAAAResource() → AddrFrom16 加入 addrsV6
//     其他类型（如 CNAME）→ SkipAnswer
//  6. 简易排序（不做完整 RFC6724）：若 hasV6 则 v6 地址放前面，否则 v4 在前
//  7. 无任何结果且有错误 → 返回 lastErr；否则返回字符串数组
func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		// 包含 ':' 说明是 IPv6，可能存在 %zone 后缀；需要去掉 zone 再 parse
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	// 情况 1：字面量 IP → 直接返回
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	// 情况 2：非法域名 → 直接失败
	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	// lane 通道用于并发 lane 数（1 或 2）个查询结果汇总
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}
	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if tnet.hasV4 {
		lanes++
	}
	if tnet.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	// 并发发起 A 和 AAAA 查询
	if tnet.hasV4 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if tnet.hasV6 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	// 收集 lanes 个结果
	for l := 0; l < lanes; l++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource() // A 记录: 4 字节 IPv4
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))

			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource() // AAAA 记录: 16 字节 IPv6
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))

			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				continue
			}
		}
	}
	// 简单的地址排序策略：不做 RFC6724，只要本机有 IPv6 能力就把 v6 地址放前面
	var addrs []netip.Addr
	if tnet.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}

	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	// 转为字符串数组返回
	saddrs := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		saddrs = append(saddrs, ip.String())
	}
	return saddrs, nil
}

// partialDeadline 实现 Happy Eyeballs 风格的"按剩余地址数分摊剩余时间"策略
// 用于 DialContext 在尝试多个 IP 时，让每个候选地址都能拿到合理的超时份额
//
// 参数:
//   - now:            当前时间
//   - deadline:       总体最终截止（若为零值表示不限时，直接返回零值）
//   - addrsRemaining: 剩余待尝试的地址个数
//
// 算法:
//   - 总剩余时间 timeRemaining = deadline - now；若 ≤ 0 → 超时错误
//   - 每地址初步超时 = timeRemaining / addrsRemaining
//   - 下限 saneMinimum = 2 秒：
//     · 若 timeRemaining < saneMinimum → 直接用 timeRemaining（等不到 2 秒就整体超时）
//     · 否则不足 2 秒的都至少给 2 秒（避免每个地址分几十毫秒根本来不及握手）
//   - 返回 now + timeout 作为下一次拨号的 partial deadline
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errTimeout
	}
	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining // 总剩余都不到 2s，就全给它吧
		} else {
			timeout = saneMinimum // 保证单次至少 2s
		}
	}
	return now.Add(timeout), nil
}

// protoSplitter 解析 network 字符串，捕获协议(tcp/udp/ping)和可选的地址族后缀(4/6)
var protoSplitter = regexp.MustCompile(`^(tcp|udp|ping)(4|6)?$`)

// DialContext 是 netstack 的高级拨号入口，模仿标准库 net.Dialer.DialContext
// 支持的 network: tcp / tcp4 / tcp6 / udp / udp4 / udp6 / ping / ping4 / ping6
//
// 整体流程（Happy Eyeballs 风格）:
//  1. 校验 context 非 nil
//  2. 正则解析 network → (协议 tcp/udp/ping, 地址族 4/6/空)
//     地址族为空 → acceptV4=acceptV6=true；否则只接受对应版本
//  3. 拆分 address 为 host + port（ping 无端口概念，跳过）
//     · TCP/UDP: net.SplitHostPort，端口必须是数字 0~65535
//  4. 调用 LookupContextHost 把 host 解析为 IP 字符串数组
//  5. 按 acceptV4/acceptV6 过滤，转为 []netip.AddrPort
//     若原解析有结果但过滤后无 → errNoSuitableAddress
//  6. 逐个地址尝试拨号：
//     · 先检查 ctx.Done()（被取消/超时直接返回）
//     · 若有总体 deadline → 用 partialDeadline 计算本次拨号的截止时间，必要时派生 dialCtx
//     · 根据协议调用:
//     tcp  → DialContextTCPAddrPort(dialCtx, addr)
//     udp  → DialUDPAddrPort(零值本地, addr)
//     ping → DialPingAddr(零值本地, addr.Addr())
//     · 首次成功立即 return
//     · 记录 firstErr
//  7. 全部失败：firstErr 非零则返回，否则返回 errMissingAddress
func (tnet *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	var acceptV4, acceptV6 bool
	matches := protoSplitter.FindStringSubmatch(network)
	if matches == nil {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError(network)}
	} else if len(matches[2]) == 0 {
		// 无 4/6 后缀 → 双栈
		acceptV4 = true
		acceptV6 = true
	} else {
		acceptV4 = matches[2][0] == '4'
		acceptV6 = !acceptV4
	}
	// 拆分 host/port（ping 协议无端口，整串当 host）
	var host string
	var port int
	if matches[1] == "ping" {
		host = address
	} else {
		var sport string
		var err error
		host, sport, err = net.SplitHostPort(address)
		if err != nil {
			return nil, &net.OpError{Op: "dial", Err: err}
		}
		port, err = strconv.Atoi(sport)
		if err != nil || port < 0 || port > 65535 {
			return nil, &net.OpError{Op: "dial", Err: errNumericPort}
		}
	}
	// DNS 解析
	allAddr, err := tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	// 根据协议族过滤候选地址，构造 AddrPort
	var addrs []netip.AddrPort
	for _, addr := range allAddr {
		ip, err := netip.ParseAddr(addr)
		if err == nil && ((ip.Is4() && acceptV4) || (ip.Is6() && acceptV6)) {
			addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
		}
	}
	if len(addrs) == 0 && len(allAddr) != 0 {
		return nil, &net.OpError{Op: "dial", Err: errNoSuitableAddress}
	}

	// 逐个地址尝试
	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			// 上下文取消/超时映射为统一错误
			err := ctx.Err()
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return nil, &net.OpError{Op: "dial", Err: err}
		default:
		}

		dialCtx := ctx
		// 计算 partial deadline，分摊剩余时间给后续地址
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Err: err}
				}
				break
			}
			// 若 partial deadline 严格早于总 deadline，则派生新 context
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		// 根据协议类型调用对应 Dial
		var c net.Conn
		switch matches[1] {
		case "tcp":
			c, err = tnet.DialContextTCPAddrPort(dialCtx, addr)
		case "udp":
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, addr)
		case "ping":
			c, err = tnet.DialPingAddr(netip.Addr{}, addr.Addr())
		}
		if err == nil {
			return c, nil // 任一成功就立即返回
		}
		if firstErr == nil {
			firstErr = err // 记录首个错误，便于最后汇总
		}
	}
	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Err: errMissingAddress}
	}
	return nil, firstErr
}

// Dial 是 DialContext 的 Background 版本，使用 context.Background()
func (tnet *Net) Dial(network, address string) (net.Conn, error) {
	return tnet.DialContext(context.Background(), network, address)
}
