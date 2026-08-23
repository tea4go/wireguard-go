/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Linux 平台 TUN 虚拟网络设备接口的实现
 *
 * TUN 设备是一种虚拟网络设备，工作在 OSI 模型的第三层（网络层）。
 * 它允许用户态程序直接读写 IP 数据包，常用于 VPN、隧道等场景。
 * WireGuard 利用 TUN 设备来收发加密前/解密后的原始 IP 数据包。
 */

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/rwcancel"
)

const (
	// cloneDevicePath 是 Linux 系统中 TUN/TAP 克隆设备的标准路径。
	// 打开 /dev/net/tun 后，通过 TUNSETIFF ioctl 可以创建或连接到一个具体的 TUN 设备。
	// 这是一种"克隆"机制：每次 open 都可以通过 TUNSETIFF 绑定到不同的虚拟接口。
	cloneDevicePath = "/dev/net/tun"
	// ifReqSize 是 ifreq 结构体缓冲区的大小。
	// unix.IFNAMSIZ 是接口名的最大长度（通常为 16 字节，含 '\0' 终止符）。
	// 后面加 64 字节是为了容纳 ifreq 结构中 union 成员的各种数据（如 ifr_mtu 4 字节、ifr_ifindex 4 字节等），
	// 这样做可以避免不同架构上结构体对齐差异导致的问题，保证缓冲区足够大。
	ifReqSize = unix.IFNAMSIZ + 64
)

// NativeTun 是 Linux 平台 TUN 设备的具体实现结构体。
// 它封装了所有与操作系统交互的底层细节，包括文件描述符、事件监听、GRO/GSO 卸载等。
type NativeTun struct {
	// tunFile 是打开的 TUN 设备文件（通过 /dev/net/tun 创建的实际设备文件描述符）。
	// 所有的数据包读写操作都通过这个文件进行。
	tunFile *os.File
	// index 是网络接口在内核中的索引编号（ifindex），
	// 用于在 netlink 消息中唯一标识这个 TUN 接口。
	index int32
	// errors 用于异步传递后台监听 goroutine（netlink/hack listener）中发生的错误。
	// 这些错误会在 Read/Write 调用时被选择性地接收处理。
	errors chan error
	// events 用于向外部订阅者发送 TUN 设备的状态变更事件，
	// 包括 EventUp（接口启用）、EventDown（接口禁用）、EventMTUUpdate（MTU 变更）。
	events chan Event
	// netlinkSock 是 NETLINK_ROUTE 类型的 netlink socket 文件描述符。
	// 用于从内核接收网络接口状态变更通知（链路状态、地址变化等）。
	netlinkSock int
	// netlinkCancel 是对 netlinkSock 进行可取消 I/O 操作的封装。
	// 它利用 rwcancel 机制，在 Close 时可以中断阻塞的 netlink Recvmsg 调用。
	netlinkCancel *rwcancel.RWCancel
	// hackListenerClosed 是一个互斥锁，用于协调 routineHackListener 和 routineNetlinkListener 的退出顺序。
	// routineNetlinkListener 在退出前会 Lock 这个锁，这要求 routineHackListener 必须先完成退出（Unlock），
	// 从而保证 hack listener 在 events 通道被关闭前已经停止写入，避免向已关闭的 channel 发送导致 panic。
	hackListenerClosed sync.Mutex
	// statusListenersShutdown 是一个用于通知两个后台监听 goroutine（netlink 和 hack）退出的信号通道。
	// Close 时关闭此通道，两个 goroutine 检测到通道关闭后会自行清理并退出。
	statusListenersShutdown chan struct{}
	// batchSize 是批量读写的理想包数量。
	// 当启用了 VIRTIO_NET_HDR（支持 TSO/GSO）时，使用 conn.IdealBatchSize（通常是 256）以获得更好的吞吐；
	// 否则为 1，因为没有 GRO 合并的必要。
	batchSize int
	// vnetHdr 表示是否启用了 virtio 网络头（I/O 时每个数据包前带 virtioNetHdr 结构）。
	// 当内核支持 TUN_F_CSUM/TSO/USO 等硬件卸载特性时启用，
	// 允许用户态和内核之间传递大包（GSO）并进行校验和/分段卸载，减少 CPU 开销。
	vnetHdr bool
	// udpGSO 表示是否启用了 UDP GSO（Generic Segmentation Offload）支持。
	// UDP GSO 是较新的特性（Linux 6.2+ 引入 TUN_F_USO4/TUN_F_USO6），
	// 允许内核将多个 UDP 包合并传输，提升 UDP 大包吞吐。
	udpGSO bool

	// closeOnce 确保 Close 方法只执行一次关闭逻辑，防止重复关闭文件和通道导致 panic。
	closeOnce sync.Once

	// nameOnce 是 sync.Once，保证 initNameCache 只被执行一次。
	// 接口名在 TUN 设备创建后不会改变，因此只需要缓存一次。
	nameOnce sync.Once
	// nameCache 缓存的接口名称字符串（如 "wg0"），避免重复发起 ioctl 系统调用。
	nameCache string
	// nameErr 记录第一次获取接口名时可能发生的错误，后续调用会直接返回该错误。
	nameErr error

	// readOpMu 互斥锁保护 readBuff 缓冲区，确保同一时间只有一个 Read 调用在进行。
	// 因为 readBuff 是结构体成员（共享缓冲区），需要互斥访问避免并发读写冲突。
	readOpMu sync.Mutex
	// readBuff 是读取操作的内部缓冲区。
	// 当 vnetHdr=true 时，从内核读到的数据先放入这个缓冲区（包含 virtio 头 + 数据包），
	// 然后再交给 handleVirtioRead 解析和分段。
	// 大小 = virtioNetHdrLen + 65535（最大 IP 包长度），确保能容纳任何一个大包。
	readBuff [virtioNetHdrLen + 65535]byte

	// writeOpMu 互斥锁保护 toWrite 切片以及 tcpGROTable/udpGROTable，
	// 确保同一时间只有一个 Write 调用在执行 GRO 合并逻辑。
	writeOpMu   sync.Mutex
	// toWrite 存储经过 GRO 合并后需要实际写入 TUN 设备的数据包在 bufs 数组中的索引。
	// 之所以存储索引而非直接存储数据包切片，是为了避免内存拷贝，提高效率。
	toWrite     []int
	// tcpGROTable 是 TCP GRO（Generic Receive Offload）合并表。
	// Write 时，如果启用 vnetHdr，会先将多个小的 TCP 包按流合并成一个大包再写入内核，
	// 这样可以减少系统调用次数，提升吞吐（模拟网卡的接收合并）。
	tcpGROTable *tcpGROTable
	// udpGROTable 是 UDP GRO 合并表，原理同 tcpGROTable，但针对 UDP 报文。
	udpGROTable *udpGROTable
}

// File 返回底层的 TUN 设备文件指针，供外部需要直接访问文件描述符时使用。
func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

// routineHackListener 是一个"hack" 监听器，通过特殊的方式检测 TUN 接口的 up/down 状态。
//
// 为什么需要这个 hack？
// Linux 的 netlink 通知机制在跨网络命名空间（network namespace）场景下存在局限：
// 如果 TUN 设备被移动到另一个 netns，原来 netns 中的 netlink socket 将收不到该设备的状态变更通知。
// 为了解决这个问题，采用了一种探测式的方案：每秒向 TUN 设备 write(nil)（空写），
// 根据返回的 errno 来推断接口当前是 up 还是 down。
//
// 原理（来自内核 tun 驱动的行为）：
//   - 当接口 UP 时，tun 驱动会先校验数据合法性，然后再做其他检查，
//     对于 write(nil) 这种空数据会返回 -EINVAL（参数无效，因为数据长度为 0）。
//   - 当接口 DOWN 时，tun 驱动在进入数据校验前就会检查设备状态，
//     直接返回 -EIO（I/O 错误，设备不可用）。
//
// 通过这两个不同的 errno 就可以可靠地判断接口状态，即使跨 netns 也能工作，
// 因为它是直接操作设备文件描述符，不依赖 netlink。
func (tun *NativeTun) routineHackListener() {
	// 退出时 Unlock hackListenerClosed，让 routineNetlinkListener 中的 Lock 得以继续执行。
	// 这保证了本 routine 先退出，netlink routine 后退出并关闭 events 通道，
	// 避免了本 routine 向已关闭的 events 通道发送数据。
	defer tun.hackListenerClosed.Unlock()
	/* 这个 hack 是为了让状态检测能跨网络命名空间工作
	 * 如果你知道更好的实现方式，请联系 WireGuard 团队。
	 */
	// last 记录上一次发送的事件状态，避免重复发送相同事件。
	last := 0
	const (
		up   = 1 // 表示上次发送了 EventUp
		down = 2 // 表示上次发送了 EventDown
	)
	for {
		// 获得 tunFile 的底层 SyscallConn，以便执行原始 fd 上的系统调用。
		// SyscallConn 是 Go 1.11+ 提供的安全获取底层 fd 的方式，避免与 netpoll 冲突。
		sysconn, err := tun.tunFile.SyscallConn()
		if err != nil {
			// 获取 sysconn 失败，直接退出（通常是文件已关闭）。
			return
		}
		// 通过 Control 回调获得原始文件描述符 fd，在其上执行 write(nil)。
		err2 := sysconn.Control(func(fd uintptr) {
			// 向 TUN 设备写入 0 字节数据（nil 切片）。
			// 关键：这个调用不会真的发送数据，只是利用内核返回的 errno 判断状态。
			_, err = unix.Write(int(fd), nil)
		})
		if err2 != nil {
			// Control 回调执行失败（如文件已关闭），退出。
			return
		}
		// 根据 write(nil) 返回的 errno 判断接口状态。
		switch err {
		case unix.EINVAL:
			// 收到 EINVAL：说明设备 UP，内核已经走到了数据合法性校验的步骤。
			// 只在状态变化时才发送事件，避免事件洪泛。
			if last != up {
				// 隧道已启用，write() 调用被允许，但因为我们提供了无效数据（空），所以返回 EINVAL。
				tun.events <- EventUp
				last = up
			}
		case unix.EIO:
			// 收到 EIO：说明设备 DOWN，内核在数据校验前就拒绝了 I/O 操作。
			if last != down {
				// 隧道已禁用，没有 I/O 操作可能，内核不会检查提供的数据，直接返回 EIO。
				tun.events <- EventDown
				last = down
			}
		default:
			// 其他错误（如 EBADF 表示 fd 已关闭）：退出监听循环。
			return
		}
		// 等待 1 秒后再次探测，或者收到关闭信号则立即退出。
		select {
		case <-time.After(time.Second):
			// 每秒探测一次，这是权衡了响应速度和 CPU 开销的选择。
		case <-tun.statusListenersShutdown:
			// 设备正在关闭，收到退出信号，返回。
			return
		}
	}
}

// createNetlinkSocket 创建并绑定一个 NETLINK_ROUTE 类型的 netlink socket。
// netlink 是 Linux 用户态与内核通信的标准机制，NETLINK_ROUTE 专门用于网络路由/接口/地址的管理和通知。
// 返回值：socket 文件描述符（成功）或 -1 和错误。
func createNetlinkSocket() (int, error) {
	// 创建 AF_NETLINK 域、SOCK_RAW 类型、NETLINK_ROUTE 协议的 socket。
	// SOCK_CLOEXEC 标志确保 exec 时自动关闭 fd，避免泄漏到子进程。
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	// 构造 netlink socket 地址结构，指定需要订阅的多播组。
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		// RTMGRP_LINK:      订阅网络链路（接口）状态变更事件（如 up/down、MTU 变化）
		// RTMGRP_IPV4_IFADDR: 订阅 IPv4 地址变更事件
		// RTMGRP_IPV6_IFADDR: 订阅 IPv6 地址变更事件
		// 虽然当前代码只处理 RTM_NEWLINK，但订阅地址组为未来扩展预留。
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	// 将 socket 绑定到指定地址和多播组。只有绑定后才能收到对应的内核通知。
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

// routineNetlinkListener 是 netlink 事件监听器，从内核接收网络接口状态变更通知。
// 与 routineHackListener 互补：在同一 netns 内 netlink 通知是即时且高效的（每秒轮询 vs 事件驱动）。
// 主要处理 RTM_NEWLINK 消息，检测 IFF_RUNNING 标志判断 up/down，
// 并在任何链路变化时发送 MTU 更新事件（因为链路变化可能伴随 MTU 调整）。
func (tun *NativeTun) routineNetlinkListener() {
	defer func() {
		// 退出时的清理工作：
		// 1. 关闭 netlink socket
		// 2. 等待 hackListenerClosed 解锁（即 routineHackListener 已完全退出）后再关闭 events 通道
		//    这样确保 hack listener 不会向已关闭的 events 写入
		// 3. 关闭 netlinkCancel，释放其占用的资源
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()

	// msg 是接收 netlink 消息的缓冲区，大小 64KB（2^16），足够容纳通常的 netlink 多消息批。
	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		// 内层循环：处理 EINTR 等可重试错误。
		for {
			// Recvmsg 从 netlink socket 读取一条或多条消息到 msg 缓冲区。
			// 由于 netlink 是数据报 socket，一次 Recvmsg 返回的可能是多个连续的 netlink 消息（由 NlMsghdr 分隔）。
			msgn, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				// 成功读取，或者遇到不可重试的错误，跳出内层循环。
				break
			}
			// 如果是可重试错误（如 EINTR），检查是否是 netlinkCancel 触发的取消信号。
			if !tun.netlinkCancel.ReadyRead() {
				// ReadyRead 返回 false 说明 Cancel 已被调用，socket 正在被关闭。
				tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
				return
			}
		}
		if err != nil {
			// 读取 netlink 消息失败（非重试类错误），将错误传递给 errors 通道并退出。
			tun.errors <- fmt.Errorf("failed to receive netlink message: %w", err)
			return
		}

		// 在处理消息前，先检查是否收到关闭信号，防止在关闭过程中还在处理事件。
		select {
		case <-tun.statusListenersShutdown:
			return
		default:
		}

		// wasEverUp 用于跟踪本连接的 TUN 设备是否曾经发出过 EventUp。
		// 避免在启动时，netlink 先收到"当前处于 down 状态"的消息，从而错误地发出 EventDown。
		// 因为在设备刚创建时，接口通常处于 down 状态，如果这时就发 EventDown，
		// 会与 HackListener 先检测到 Up 产生竞态和状态不一致。
		wasEverUp := false
		// 遍历一次 Recvmsg 收到的所有 netlink 消息（可能多条拼接在一起）。
		// remain 是剩余未解析的消息切片，每次解析后前进 hdr.Len 字节。
		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			// 将消息开头强制转换为 NlMsghdr（netlink 消息头），读取消息长度和类型。
			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			// 完整性校验：如果头中声明的长度超过了剩余缓冲区，说明数据不完整，停止解析。
			if int(hdr.Len) > len(remain) {
				break
			}

			// 根据 netlink 消息类型分发处理。
			switch hdr.Type {
			case unix.NLMSG_DONE:
				// NLMSG_DONE 标志着一组多部分消息（multi-part message）的结束。
				// 直接清空 remain，退出解析循环。
				remain = []byte{}

			case unix.RTM_NEWLINK:
				// RTM_NEWLINK：网络接口创建或属性变更事件（包括 up/down 标志、MTU 等变化）。
				// 消息结构：NlMsghdr + IfInfomsg + 一系列属性（rtattr）。

				// 解析 IfInfomsg：从 netlink 头之后的位置开始。
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				// 将 remain 推进到下一条消息（按 hdr.Len 跳转，而不是固定大小，因为后面还有变长 rtattr）。
				remain = remain[hdr.Len:]

				// 只处理属于我们这个 TUN 接口的消息（通过 ifindex 匹配）。
				if info.Index != tun.index {
					// 不是我们的接口，跳过。
					continue
				}

				// IFF_RUNNING 标志表示接口处于"运行中"状态（已启用且物理链路可用，对于虚拟设备就是已 UP）。
				if info.Flags&unix.IFF_RUNNING != 0 {
					// RUNNING 位被设置 → 接口已 up。
					tun.events <- EventUp
					wasEverUp = true
				}

				// RUNNING 位未设置 → 接口已 down。
				if info.Flags&unix.IFF_RUNNING == 0 {
					// 只有在之前曾经发出过 EventUp 的情况下，才发出 EventDown。
					// 这避免了启动时的竞态：HackListener 可能先检测到 Up，
					// 而此处如果 netlink 先报告 Down，会导致状态混乱。
					if wasEverUp {
						tun.events <- EventDown
					}
				}

				// 无论什么变化（up/down 或其他链路属性变更），都发送一次 MTU 更新事件。
				// 因为 RTM_NEWLINK 也会在 MTU 改变时触发，这样订阅者可以重新读取最新 MTU。
				tun.events <- EventMTUUpdate

			default:
				// 其他消息类型（如 RTM_NEWADDR 地址变更）：目前不处理，直接跳过。
				remain = remain[hdr.Len:]
			}
		}
	}
}

// getIFIndex 根据接口名（如 "wg0"）查询其在内核中的 ifindex 编号。
// ifindex 是内核中每个网络接口的唯一整数标识，用于 netlink 等 API 中快速定位接口。
func getIFIndex(name string) (int32, error) {
	// 创建一个临时的 UDP socket（SOCK_DGRAM），用于执行 ioctl。
	// SIOCGIFINDEX ioctl 要求 socket 的地址族必须是 AF_INET（或 AF_INET6），
	// 这是历史遗留设计：通过任意网络 socket fd 都可以执行接口查询类 ioctl。
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// 构造 ifreq 请求结构体：前 IFNAMSIZ 字节是接口名，后面是返回值位置。
	var ifr [ifReqSize]byte
	// 将接口名拷贝到 ifreq 的开头（ifr_name 字段）。
	copy(ifr[:], name)
	// 执行 SIOCGIFINDEX ioctl：根据接口名获取其 ifindex。
	// 内核会将结果写入 ifr_ifindex 字段（即 ifr[IFNAMSIZ:] 起始的 4 字节）。
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	// 从 ifr[IFNAMSIZ:] 位置读取 int32 作为 ifindex 返回。
	// 注意：使用 unsafe.Pointer 直接解释内存，这是与 C 结构体交互的惯用方式。
	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

// setMTU 设置 TUN 设备的最大传输单元（Maximum Transmission Unit）。
// MTU 决定了在不进行 IP 分片的情况下，接口能够传输的最大数据包大小。
// WireGuard 默认使用 1420（为 1500 MTU 的以太网减去 WireGuard 封装开销预留空间）。
func (tun *NativeTun) setMTU(n int) error {
	// 先通过 Name() 获取接口名（带缓存，开销低）。
	name, err := tun.Name()
	if err != nil {
		return err
	}

	// 创建一个临时的 UDP socket 用于执行 ioctl（同 getIFIndex）。
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// 构造 ifreq 请求。
	var ifr [ifReqSize]byte
	// ifr_name: 设置接口名
	copy(ifr[:], name)
	// ifr_mtu: 在 IFNAMSIZ 之后的位置写入要设置的 MTU 值（4 字节 uint32）。
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	// 执行 SIOCSIFMTU ioctl：Set Interface MTU。
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}

	return nil
}

// MTU 查询 TUN 设备当前的 MTU 值。
// 与 setMTU 对称，通过 SIOCGIFMTU ioctl 获取。
func (tun *NativeTun) MTU() (int, error) {
	name, err := tun.Name()
	if err != nil {
		return 0, err
	}

	// 创建临时 UDP socket。
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// 构造 ifreq 请求。
	var ifr [ifReqSize]byte
	// ifr_name: 设置接口名。
	copy(ifr[:], name)
	// 执行 SIOCGIFMTU ioctl：Get Interface MTU。
	// 内核会将当前 MTU 值写入 ifr_mtu 字段（ifr[IFNAMSIZ:]）。
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}

	// 从返回缓冲区中读取 int32 类型的 MTU 值并转换为 int 返回。
	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

// Name 返回 TUN 设备的接口名称（如 "wg0"）。
// 通过 sync.Once 保证只调用一次底层查询，结果被缓存到 nameCache/nameErr。
func (tun *NativeTun) Name() (string, error) {
	tun.nameOnce.Do(tun.initNameCache)
	return tun.nameCache, tun.nameErr
}

// initNameCache 是被 nameOnce 保护的初始化函数，仅执行一次。
// 它调用 nameSlow() 执行真正的 ioctl 查询，并将结果缓存。
func (tun *NativeTun) initNameCache() {
	tun.nameCache, tun.nameErr = tun.nameSlow()
}

// nameSlow 是实际执行 TUNGETIFF ioctl 查询接口名的函数。
// 为什么叫 "slow"？因为涉及系统调用，相比读取缓存变量要慢得多。
// 通过 SyscallConn.Control 在 tun 文件描述符上执行 ioctl，确保与 Go runtime 的 netpoll 安全协作。
func (tun *NativeTun) nameSlow() (string, error) {
	// 获取底层 SyscallConn，这是 Go 提供的在 *os.File 上执行原始系统调用的安全方式。
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	// 构造 ifreq 缓冲区用于接收返回的接口名。
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	// 通过 Control 回调获得安全的 fd，在 fd 上执行 ioctl。
	err = sysconn.Control(func(fd uintptr) {
		// 执行 TUNGETIFF ioctl：获取 TUN 设备当前的接口标志和名称。
		// 对于此 ioctl，ifr_name 字段会被内核填入实际的接口名称（如果创建时指定了 "wg%d" 这类模式，
		// 内核会自动分配编号并返回最终名称）。
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	// ifr 缓冲区开头就是以 '\0' 结尾的接口名（C 风格字符串）。
	// unix.ByteSliceToString 将字节切片转换为 Go string，遇到第一个 '\0' 时截断。
	return unix.ByteSliceToString(ifr[:]), nil
}

// Write 将多个数据包（bufs）写入 TUN 设备。offset 指定每个数据包切片开头需要跳过的字节数。
// 返回值：成功写入的总字节数，以及可能的错误。
//
// 核心流程：
//  1. 获取 writeOpMu 锁，保护 GRO 表和 toWrite 列表（串行化所有 Write 调用）。
//  2. 如果启用了 vnetHdr（支持 GSO），先调用 handleGRO 对数据包进行 GRO 合并（多个小包合并为大包）。
//     合并后的包索引存入 toWrite。handleGRO 还会为每个合并后的包添加 virtio 头。
//  3. 如果未启用 vnetHdr，则每个包都直接写入，跳过合并步骤。
//  4. 遍历 toWrite 中的索引，将对应的数据包实际写入 tunFile。
//  5. 写入完成后，重置 GRO 表（清空合并状态），释放锁。
func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.writeOpMu.Lock()
	defer func() {
		// 每次 Write 调用结束后必须重置 GRO 表，避免残留的合并状态影响下一次调用。
		// GRO 合并是单次 Write 内的局部行为，不跨 Write 调用。
		tun.tcpGROTable.reset()
		tun.udpGROTable.reset()
		tun.writeOpMu.Unlock()
	}()
	var (
		errs  error
		total int
	)
	// 清空 toWrite（保持底层数组容量，避免重复分配）。
	tun.toWrite = tun.toWrite[:0]
	if tun.vnetHdr {
		// 启用了 virtio 头：先执行 GRO（Generic Receive Offload，接收合并的逆过程）。
		// handleGRO 会遍历 bufs 中的每个包，将符合合并条件的 TCP/UDP 小包合并成一个大包，
		// 并在包前面插入 virtioNetHdr（设置 GSO 类型、分段大小等信息）。
		// 合并后的（或无法合并的单个包）的索引会被追加到 tun.toWrite。
		err := handleGRO(bufs, offset, tun.tcpGROTable, tun.udpGROTable, tun.udpGSO, &tun.toWrite)
		if err != nil {
			return 0, err
		}
		// 注意：handleGRO 在每个包前面插入了 virtioNetHdrLen 字节的 virtio 头，
		// 所以实际写入时的 offset 需要减少 virtioNetHdrLen，才能读到包含头的完整数据。
		offset -= virtioNetHdrLen
	} else {
		// 未启用 virtio 头：不进行 GRO，所有包按原样写入。
		for i := range bufs {
			tun.toWrite = append(tun.toWrite, i)
		}
	}
	// 遍历待写入的数据包索引列表，逐个写入 TUN 设备文件。
	for _, bufsI := range tun.toWrite {
		n, err := tun.tunFile.Write(bufs[bufsI][offset:])
		if errors.Is(err, syscall.EBADFD) {
			// EBADF 表示文件描述符已无效（通常是设备被关闭），转换为标准的 os.ErrClosed。
			return total, os.ErrClosed
		}
		if err != nil {
			// 累加写入过程中出现的多个错误（使用 errors.Join 可以保留所有错误信息）。
			errs = errors.Join(errs, err)
		} else {
			// 累加成功写入的字节数。
			total += n
		}
	}
	return total, errs
}

// handleVirtioRead 解析从 TUN 设备读取的带 virtioNetHdr 头的数据，
// 执行 GSO（Generic Segmentation Offload）分段（如果是 GSO 大包）和校验和补算，
// 将结果填充到 bufs 切片中。
//
// 参数：
//   - in: 从 TUN 读取的原始数据（包含 virtioNetHdr + 数据包）
//   - bufs: 输出缓冲区数组，每个缓冲区前面预留了 offset 字节
//   - sizes: 对应每个 bufs[i] 的实际数据长度（输出参数）
//   - offset: bufs 每个缓冲区前面需要跳过的字节数（在其前面填入数据）
//
// 返回：实际解析出的数据包个数，以及可能的错误。
//
// 处理流程：
//  1. 解码 virtio 头，判断是普通包（GSO_NONE）还是 GSO 大包。
//  2. 对于普通包，如果设置了 NEEDS_CSUM 标志，则补算 L4 校验和。
//  3. 对于 GSO 大包（TCPv4/TCPv6/UDP_L4），调用 gsoSplit 将其拆分为多个 MSS 大小的包，
//     每个包重新计算校验和（因为分段后 IP/TCP 头部内容会变化）。
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	// 解码 in 开头的 virtioNetHdr 结构（flags、gsoType、hdrLen、csumStart、csumOffset 等字段）。
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return 0, err
	}
	// 跳过 virtio 头，in 现在指向真正的 IP 数据包起始位置。
	in = in[virtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		// GSO_NONE：这是一个普通包，不分段。但可能需要我们补算校验和。
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// NEEDS_CSUM 标志对应内核中的 CHECKSUM_PARTIAL 语义：
			// 内核已经计算了伪首部校验和并填入了 L4 校验和字段，
			// 我们需要从 csumStart 位置开始，计算到数据包末尾的完整校验和，
			// 然后将最终结果写入 csumOffset 位置（相对于 csumStart 的偏移）。
			err = gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset)
			if err != nil {
				return 0, err
			}
		}
		// 普通包直接拷贝到 bufs[0]，前面留出 offset 字节。
		if len(in) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(bufs[0][offset:]))
		}
		n := copy(bufs[0][offset:], in)
		sizes[0] = n
		return 1, nil
	}
	// GSO 大包类型检查：目前仅支持 TCPv4、TCPv6 和 UDP_L4 三种 GSO 类型。
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	// 从 IP 头第一个字节的高 4 位获取 IP 版本号（4 或 6）。
	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		// IPv4 只允许 TCPv4 GSO 或 UDP_L4 GSO（IPv4 版）。
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		// IPv6 只允许 TCPv6 GSO 或 UDP_L4 GSO（IPv6 版）。
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// 重新计算 hdrLen（L4 首部长度 + IP 首部长度 = IP+L4 头总长）。
	// 为什么不完全信任内核给出的 hdr.hdrLen？
	// 因为在 FORWARD 路径下，内核有时会将 hdrLen 设置为等于第一个分段的总长而非头长，
	// 这会导致后续分段逻辑错误。因此我们通过解析头部自行计算更可靠：
	//   - UDP：固定 8 字节 UDP 头，hdrLen = csumStart（IP 头长）+ 8
	//   - TCP：从 TCP 头第 13 字节（Data Offset 字段）高 4 位读出 TCP 头长（单位 4 字节）
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		// TCP：先确保包长度足够容纳 csumStart + 13 字节（TCP header length 字段位置）。
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}

		// TCP 头第 13 字节（偏移 12，0-based）的高 4 位是 Data Offset，
		// 表示 TCP 头总长度（单位：4 字节）。所以乘以 4 得到字节数。
		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// TCP 头最小 20 字节（无选项），最大 60 字节（最多 40 字节选项）。
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		// hdrLen = IP 头长 + TCP 头长（即 IP+TCP 头总长度，payload 从 hdrLen 之后开始）。
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	// 边界校验：整包至少要包含完整的头部。
	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}

	// 头长必须 >= csumStart，否则不可能。
	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	// csumOffset 是相对于 csumStart 的偏移，所以 L4 校验和字段的绝对位置是 csumStart + csumOffset。
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	// 确保校验和字段（2 字节）完全位于包内。
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	// 调用 gsoSplit 将 GSO 大包拆分为多个 MSS 大小的普通包，
	// 每个分段会有独立的 IP/L4 头，且校验和会被重新计算。
	// 最后一个参数 isIPv6 = (ipVersion == 6)，用于区分 IPv4/IPv6 头格式。
	return gsoSplit(in, hdr, bufs, sizes, offset, ipVersion == 6)
}

// Read 从 TUN 设备读取一个或多个数据包。
// 参数：
//   - bufs: 接收缓冲区数组，每个元素是一个包的缓冲区。
//   - sizes: 输出参数，记录每个 bufs[i] 中实际数据长度。
//   - offset: 每个 bufs[i] 前面跳过的字节数（数据包从 offset 处开始写入）。
//
// 返回：成功读取的数据包数量（通常为 1，但如果是 GSO 分段则可能 > 1），以及错误。
//
// 流程：
//  1. 获取 readOpMu 锁，保护共享的 readBuff 缓冲区。
//  2. 非阻塞地检查 errors 通道中是否有待处理的后台错误（如 netlink 读取失败），
//     有则立即返回错误。
//  3. 根据 vnetHdr 标志决定读取目标：
//     - vnetHdr=true: 读到 readBuff（包含 virtio 头，需要后续解析分段）。
//     - vnetHdr=false: 直接读到 bufs[0][offset:]（单个普通包）。
//  4. 调用 tunFile.Read 执行实际读取。
//  5. 如果启用了 vnetHdr，调用 handleVirtioRead 解析 virtio 头、分段（如果是 GSO 大包）、
//     补算校验和，结果填充到 bufs/sizes。
//  6. 否则直接设置 sizes[0] = n（单个包）。
func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.readOpMu.Lock()
	defer tun.readOpMu.Unlock()
	select {
	case err := <-tun.errors:
		// 优先返回后台监听 goroutine 中发生的异步错误（如 netlink socket 异常）。
		// 这样外层调用者可以及时感知到设备内部状态异常。
		return 0, err
	default:
		// 默认无错误时正常执行读取。
		// readInto 决定本次 Read 系统调用实际写入的目标缓冲区。
		readInto := bufs[0][offset:]
		if tun.vnetHdr {
			// 启用 virtio 头：先读到内部共享 readBuff。
			// 因为从内核读出的数据是 [virtioNetHdr + payload]，
			// 需要先整体读入，再交给 handleVirtioRead 解析、分段、拷贝到 bufs。
			readInto = tun.readBuff[:]
		}
		// 从 TUN 设备文件读取数据。对于 TUN 设备，一次 read() 最多返回一个数据包（或一个 GSO 超级包）。
		n, err := tun.tunFile.Read(readInto)
		if errors.Is(err, syscall.EBADFD) {
			// EBADF → 设备已关闭，转换为标准 os.ErrClosed。
			err = os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		if tun.vnetHdr {
			// 带 virtio 头：解析头、GSO 分段、校验和补算，结果输出到 bufs/sizes。
			return handleVirtioRead(readInto[:n], bufs, sizes, offset)
		} else {
			// 普通模式：单包直接拷贝完成，返回 1 个包。
			sizes[0] = n
			return 1, nil
		}
	}
}

// Events 返回设备事件通道，外部订阅者可以通过该通道接收 up/down/MTU 变更事件。
// 通道会在设备关闭时被 routineNetlinkListener 自动关闭。
func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

// Close 关闭 TUN 设备，停止所有后台 goroutine，释放相关资源。
// 通过 sync.Once 确保整个关闭流程只执行一次（重复调用 Close 是安全的，不会 panic）。
func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		if tun.statusListenersShutdown != nil {
			// 常规创建路径（CreateTUN/CreateTUNFromFile）：statusListenersShutdown 非 nil。
			// 关闭该通道以通知两个后台监听器（netlink 和 hack）退出。
			// 这是安全的退出信号，不会像关闭 events 通道那样有并发写入风险。
			close(tun.statusListenersShutdown)
			if tun.netlinkCancel != nil {
				// 调用 netlinkCancel.Cancel() 中断可能阻塞在 netlink Recvmsg 上的调用。
				// rwcancel 的实现原理：通过 dup 的 eventfd 写入数据，
				// 触发被 poll/epoll 阻塞的 syscall 返回 EINTR，从而让 Recvmsg 解除阻塞。
				err1 = tun.netlinkCancel.Cancel()
			}
		} else if tun.events != nil {
			// CreateUnmonitoredTUNFromFD 路径：没有后台监听器，statusListenersShutdown 为 nil。
			// 此时直接关闭 events 通道即可（不会有并发写入风险）。
			close(tun.events)
		}
		// 关闭底层 TUN 设备文件。文件关闭后，所有阻塞在 Read/Write 上的调用都会返回错误。
		// 对于 TUN 设备，关闭文件描述符也会触发内核中相应的清理（如释放设备资源）。
		err2 = tun.tunFile.Close()
	})
	if err1 != nil {
		// 优先返回 netlinkCancel.Cancel() 的错误。
		return err1
	}
	return err2
}

// BatchSize 返回本设备理想的批量读写包数量。
//   - 如果启用了 vnetHdr（GSO/GRO 支持），则使用 conn.IdealBatchSize（通常 256），
//     因为批处理越多，GRO 合并机会越大，系统调用开销占比越低。
//   - 否则为 1，因为没有 virtio 头时无法进行 GSO/GRO，批量写入也只能逐个 write()。
func (tun *NativeTun) BatchSize() int {
	return tun.batchSize
}

const (
	// tunTCPOffloads 是 TCP 相关的硬件卸载标志集合，需要通过 TUNSETOFFLOAD ioctl 开启。
	//   TUN_F_CSUM: 允许用户态传递设置了 NEEDS_CSUM 的包，内核负责校验和补算或交由硬件处理。
	//               这是 TSO 工作的前提，因为 GSO 包的校验和通常是部分校验和。
	//   TUN_F_TSO4: 启用 IPv4 TCP 分段卸载（Generic Segmentation Offload for TCP over IPv4）。
	//               用户态可以传递大于 MTU 的 TCP 超级包，内核或网卡会将其拆分为 MTU 大小的分段。
	//   TUN_F_TSO6: 启用 IPv6 TCP 分段卸载，同上但针对 IPv6。
	// TODO: 目前尚不支持带 ECN（Explicit Congestion Notification）位的 TSO，未来可能需要支持。
	tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	// tunUDPOffloads 是 UDP 相关的硬件卸载标志（Linux 6.2+ 内核才支持）。
	//   TUN_F_USO4: IPv4 UDP 分段卸载（UDP Segmentation Offload）。
	//   TUN_F_USO6: IPv6 UDP 分段卸载。
	// UDP GSO 相比 TCP GSO 支持得晚一些，因此代码中对其启用是"尽力而为"，失败不报错。
	tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
)

// initFromFlags 在 TUN 设备创建后初始化相关标志和配置。
// 主要作用是检测并启用各种 TUN 卸载特性（vnetHdr、CSUM、TSO、USO 等）。
// 检测方法：先通过 TUNGETIFF 读取当前 flags，检查 IFF_VNET_HDR 是否已设置。
func (tun *NativeTun) initFromFlags(name string) error {
	// 获取安全的 SyscallConn 以便在 tun fd 上执行 ioctl。
	sc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return err
	}
	// 通过 Control 回调在安全上下文中执行 ioctl 操作。
	if e := sc.Control(func(fd uintptr) {
		var (
			ifr *unix.Ifreq
		)
		// 构造一个 ifreq，填入接口名（Name），为 TUNGETIFF ioctl 做准备。
		ifr, err = unix.NewIfreq(name)
		if err != nil {
			return
		}
		// 执行 TUNGETIFF ioctl：获取 TUN 设备当前的 flags。
		// 注意：CreateTUN 中我们设置了 IFF_VNET_HDR，这里是验证内核是否真的接受了这个标志。
		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
		if err != nil {
			return
		}
		// 从 ifr 中取出 uint16 类型的 flags 字段。
		got := ifr.Uint16()
		if got&unix.IFF_VNET_HDR != 0 {
			// 内核确认支持 IFF_VNET_HDR：每个数据包都会带 virtioNetHdr 前缀。
			// 尝试开启 TCP 相关的卸载（CSUM + TSO4 + TSO6）。
			// 这些特性自 Linux 2.6 早期就已存在，几乎所有现代内核都支持，
			// 所以如果这一步失败，认为是致命错误，直接返回 err。
			// tunTCPOffloads 是 vnetHdr 工作的必要条件：没有 CSUM 支持就无法传递部分校验和的大包。
			err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads)
			if err != nil {
				return
			}
			// 成功开启：标记 vnetHdr=true，后续读写都带 virtio 头。
			tun.vnetHdr = true
			// 启用 GSO/GRO 后，可以处理更大批量的数据包以提升效率。
			tun.batchSize = conn.IdealBatchSize
			// 尝试额外开启 UDP 卸载（USO4 + USO6）。
			// 注意：这是"尽力而为"——即使失败也不返回错误，
			// 因为 UDP GSO 是 Linux 6.2 才引入的，老内核不支持是正常情况。
			// 判断方式：如果 TUNSETOFFLOAD(tunTCPOffloads | tunUDPOffloads) 成功，
			// 说明内核也支持 UDP GSO，则 tun.udpGSO = true。
			tun.udpGSO = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil
		} else {
			// 内核不支持 IFF_VNET_HDR（很老的内核，或特殊环境）：
			// 关闭所有卸载特性，只能逐包处理，batchSize 设为 1。
			tun.batchSize = 1
		}
	}); e != nil {
		// Control 回调本身执行失败（如文件已关闭），返回 Control 的错误。
		return e
	}
	// 返回 ioctl 执行过程中可能产生的 err（如 TUNSETOFFLOAD(TCP) 失败等）。
	return err
}

// CreateTUN 根据给定的接口名和 MTU 创建一个新的 TUN 设备。
// 这是创建 WireGuard 网络接口的标准入口。
//
// 流程：
//  1. 打开 /dev/net/tun 克隆设备。
//  2. 通过 TUNSETIFF ioctl 将克隆 fd 绑定到具体的 TUN 接口（按 name 创建或连接），
//     设置 IFF_TUN（三层设备）| IFF_NO_PI（不附加额外的 packet info 头）| IFF_VNET_HDR（启用 virtio 头）。
//  3. 将 fd 设置为非阻塞模式，以便 Go runtime 的 netpoll 可以高效地管理它。
//  4. 把原始 fd 包装为 *os.File，交给 CreateTUNFromFile 继续后续初始化。
func CreateTUN(name string, mtu int) (Device, error) {
	// 以读写模式打开 /dev/net/tun。O_CLOEXEC 防止 exec 时 fd 泄漏。
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// 如果路径不存在，通常是因为内核没有加载 tun 模块，或者 /dev/net/tun 节点未创建。
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	// 构造 TUNSETIFF ioctl 需要的 ifreq 结构，填入接口名。
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	// 设置接口类型标志：
	//   IFF_TUN:    工作在三层模式（TUN），读写 IP 包（没有以太网头）。
	//               与 IFF_TAP（二层模式，含以太网头）互斥。
	//   IFF_NO_PI:  不在每个数据包前附加额外的 4 字节 Packet Info 头（flags + proto）。
	//               因为我们只使用单协议（IP）且不需要额外 flag，所以关闭 PI 以节省开销。
	//   IFF_VNET_HDR: 启用 virtio 网络头。要求每个读/写的包前面带 struct virtio_net_hdr，
	//               这是使用 TSO/GRO/CSUM 等卸载特性的前提条件。
	//               此外，这个标志也让 routineHackListener 的 "write(nil) hack" 能正常工作——
	//               当 vnet hdr 启用时，write 的长度校验会先于设备状态检查，从而产生我们需要的 EINVAL vs EIO 差异。
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	// 执行 TUNSETIFF ioctl：
	// - 如果指定的 name（如 "wg0"）不存在，则创建新的 TUN 接口。
	// - 如果 name 包含 "%d" 通配符（如 "wg%d"），内核会自动分配一个可用的编号。
	// - 如果 name 已存在且是 TUN 类型，则尝试连接到该接口（需要权限和所有权匹配）。
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	// 将 fd 设置为非阻塞模式。
	// 这一步非常关键：只有设置了 O_NONBLOCK，Go runtime 才能用 epoll 对其进行 I/O 多路复用，
	// 否则 Read/Write 会阻塞整个 OS 线程，影响调度性能（Go 的 goroutine 调度依赖非阻塞 I/O + netpoll）。
	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// 注意：上面三步（open → TUNSETIFF → nonblock）必须严格按此顺序在交给 netpoll 之前完成。
	// 如果先交给 Go *os.File（netpoll 接管）再做 ioctl，可能因为状态不一致导致问题。

	// 将 Unix 文件描述符包装为 Go 的 *os.File，赋予其文件名（用于调试和 /proc 显示）。
	fd := os.NewFile(uintptr(nfd), cloneDevicePath)
	// 继续后续的设备初始化（获取名称、检测卸载特性、启动监听器、设置 MTU）。
	return CreateTUNFromFile(fd, mtu)
}

// CreateTUNFromFile 从已打开的 TUN 设备文件继续完成初始化。
// 职责：构造 NativeTun 结构体，启动事件监听 goroutine，设置 MTU。
// CreateTUN 和外部传入文件描述符的场景都会调用此函数。
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	// 构造 NativeTun 实例，初始化各字段。
	tun := &NativeTun{
		tunFile:                 file,
		events:                  make(chan Event, 5),          // 带缓冲的事件通道，避免慢消费者丢事件
		errors:                  make(chan error, 5),          // 带缓冲的错误通道
		statusListenersShutdown: make(chan struct{}),          // 关闭信号通道，关闭时触发
		tcpGROTable:             newTCPGROTable(),             // TCP GRO 合并表，Write 时使用
		udpGROTable:             newUDPGROTable(),             // UDP GRO 合并表
		toWrite:                 make([]int, 0, conn.IdealBatchSize), // 预分配容量的写索引切片
	}

	// 获取并缓存接口名（通过 TUNGETIFF ioctl）。
	name, err := tun.Name()
	if err != nil {
		return nil, err
	}

	// 根据内核实际支持的 flags 初始化卸载特性（vnetHdr、TSO、USO 等）和 batchSize。
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, err
	}

	// 启动事件监听器之前，先根据接口名查询 ifindex（后续 netlink 消息匹配用）。
	tun.index, err = getIFIndex(name)
	if err != nil {
		return nil, err
	}

	// 创建 netlink socket，用于接收接口状态变更事件（同 netns 内即时通知）。
	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		return nil, err
	}
	// 为 netlink socket 创建可取消包装器，用于 Close 时中断阻塞的 Recvmsg。
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	// 协调两个监听器的启动顺序：
	// 先 Lock hackListenerClosed，然后启动两个 goroutine。
	// routineHackListener 在 defer 中 Unlock，routineNetlinkListener 在 defer 中先 Lock。
	// 这样可以保证：
	//   - routineNetlinkListener 总是在 routineHackListener 完全退出后才继续执行 cleanup，
	//     从而安全地 close(tun.events) 而不用担心 hack listener 还在写入。
	tun.hackListenerClosed.Lock()
	// 启动 netlink 监听器（同 netns 内的事件驱动通知，响应迅速）。
	go tun.routineNetlinkListener()
	// 启动 hack 监听器（跨 netns 的轮询探测，每秒一次，作为 netlink 无法覆盖场景的兜底）。
	go tun.routineHackListener()

	// 最后，设置设备的 MTU。如果设置失败，需要清理 netlink socket 再返回错误。
	err = tun.setMTU(mtu)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	return tun, nil
}

// CreateUnmonitoredTUNFromFD 从已有的文件描述符创建一个"未监控"的 TUN 设备。
// 与 CreateTUNFromFile 的区别：
//   - 不启动 routineNetlinkListener 和 routineHackListener（无事件监控）。
//   - statusListenersShutdown 和 netlinkCancel/netlinkSock 均为零值。
//   - Close() 时不会关闭监听器，只会关闭 events 和 tunFile。
//
// 使用场景：外部已自行管理事件监听，或在测试/嵌入式环境中不需要事件通知。
// 返回：设备实例、接口名称、错误。
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	// 先将 fd 设置为非阻塞模式（同 CreateTUN 中的说明，Go netpoll 需要）。
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, "", err
	}
	// 包装为 *os.File。
	file := os.NewFile(uintptr(fd), "/dev/tun")
	// 构造 NativeTun 实例，但不初始化 netlink/hack 相关字段。
	tun := &NativeTun{
		tunFile:     file,
		events:      make(chan Event, 5),
		errors:      make(chan error, 5),
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     make([]int, 0, conn.IdealBatchSize),
	}
	// 获取接口名（同时也验证了 fd 确实是一个有效的 TUN 设备）。
	name, err := tun.Name()
	if err != nil {
		return nil, "", err
	}
	// 初始化卸载特性标志。
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, "", err
	}
	return tun, name, err
}
