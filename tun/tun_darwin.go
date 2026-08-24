/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// utunControlName 是 macOS 内核中 utun 网络控制接口的注册名称。
// macOS 使用 Network Kernel Extension (NKE) 的 Kernel Control API 提供
// 用户态与内核态 tunnel 驱动的通信机制。应用程序通过
// com.apple.net.utun_control 这个唯一标识符找到对应的内核控制通道，
// 然后通过 connect() 将 socket 绑定到某个具体的 utunN 接口上。
const utunControlName = "com.apple.net.utun_control"

// NativeTun 是 macOS 平台上 TUN 设备的 Go 层封装结构体。
// 该结构体维护了与内核 utun 驱动交互所需的全部状态。
type NativeTun struct {
	// name 保存接口名称，例如 "utun0"、"utun3" 等。
	// 在 Name() 中通过 getsockopt 获取后缓存到此字段。
	name string

	// tunFile 是封装了 utun socket fd 的 *os.File 对象。
	// 此 fd 通过 AF_SYSTEM + SOCK_DGRAM + SYSPROTO_CONTROL 创建，
	// 然后 connect 到 com.apple.net.utun_control。
	// Read/Write 实际的 IP 报文就是通过此 fd 进行的。
	tunFile *os.File

	// events 是对外发布接口事件的通道。
	// 由 routineRouteListener 向此通道写入：
	//   - EventUp       接口从 DOWN 变为 UP
	//   - EventDown     接口从 UP 变为 DOWN
	//   - EventMTUUpdate 接口 MTU 值发生变化
	// 通道容量为 10，属于有缓冲通道，避免事件丢失。
	events chan Event

	// errors 用于传递后台 goroutine（routineRouteListener）中发生的错误。
	// 例如 AF_ROUTE socket 读取失败、ioctl 失败等。
	// 容量为 5，有缓冲防止写阻塞。
	errors chan error

	// routeSocket 是 AF_ROUTE 域的原始 socket 描述符。
	// macOS 的路由域 socket 可以订阅内核中的网络事件（如接口状态变化、
	// 路由变化、地址变化等）。本代码只关心 RTM_IFINFO 消息，
	// 用于检测本接口的 IFF_UP 标志变化及 MTU 变化。
	routeSocket int

	// closeOnce 保证 Close() 方法在并发调用时只执行一次实际关闭逻辑。
	// 防止 tunFile 和 routeSocket 被重复 close 引发 panic。
	closeOnce sync.Once
}

// routineRouteListener 是后台运行的事件监听 goroutine。
// 它从 AF_ROUTE socket 读取内核派发的路由消息（ifmsghdr 结构），
// 只处理本接口（tunIfindex 指定的 index）的 RTM_IFINFO 消息，
// 从中提取接口标志位（flags）和 MTU，与上次缓存的状态对比，
// 发生变化时向 events 通道发送对应事件。
//
// 参数:
//   - tunIfindex: 目标 TUN 接口在内核中的编号（net.Interface.Index）。
//     通过此编号过滤掉其它接口的事件。
//
// 关于 macOS ifmsghdr 结构体字段在 data 字节数组中的偏移（64 位平台）：
//
//	data[0..1]   ifm_msglen   uint16  整个消息的总长度（含头部）
//	data[2]      ifm_version  uint8   消息版本号，通常为 RTM_VERSION
//	data[3]      ifm_type     uint8   消息类型，这里只处理 RTM_IFINFO
//	data[4..7]   ifm_addrs    int32   位掩码，表示后随哪些 sockaddr
//	data[8..11]  ifm_flags    int32   接口标志位（IFF_UP / IFF_RUNNING 等）
//	data[12..13] ifm_index    uint16  接口索引（ifindex）
//	data[14..15] (填充对齐)
//	data[16..19] ifm_snd_len  int32   发送队列长度
//	data[20..23] ifm_snd_maxlen int32 发送队列最大长度
//	data[24..27] ifm_snd_drops int32  发送丢包数
//	以上是 if_data 结构起始部分。其中 data[24..27] 即 ifm_data.ifi_mtu
//	（实际上 ifi_mtu 在 if_data 中的偏移是 0，而 if_data 在 ifmsghdr 中的
//	偏移在 macOS 64 位上是 24 字节）
func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		// statusUp  缓存上一次检测到的接口 Up/Down 状态
		statusUp bool

		// statusMTU 缓存上一次检测到的接口 MTU 值
		statusMTU int
	)

	// 退出时关闭 events 通道，通知接收方不再有新事件
	defer close(tun.events)

	// 分配一页大小的缓冲区存放内核路由消息
	data := make([]byte, os.Getpagesize())
	for {
	retry:
		// 从 AF_ROUTE socket 读取一条消息
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			// EINTR 表示被信号中断，属于可恢复错误，重试即可
			if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR {
				goto retry
			}
			// 其它错误上报到 errors 通道后退出 goroutine
			tun.errors <- err
			return
		}

		// 消息过短（小于 28 字节，连 ifmsghdr 头部都不完整），直接丢弃
		if n < 28 {
			continue
		}

		// 只处理 RTM_IFINFO（接口信息变化）类型的消息
		// 其它类型（RTM_ADD/RTM_DELETE 路由变化、RTM_NEWADDR 地址变化等）忽略
		if data[3 /* ifm_type */] != unix.RTM_IFINFO {
			continue
		}
		// 取出消息中携带的接口索引，只处理属于本 TUN 接口的消息
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifm_index */])))
		if ifindex != tunIfindex {
			continue
		}

		// 读取接口标志位（32 位 int），偏移 8 字节
		flags := int(*(*uint32)(unsafe.Pointer(&data[8 /* ifm_flags */])))

		// ===== Up / Down 事件检测 =====
		// 检查 IFF_UP 位是否置位。IFF_UP 表示接口被管理员启用。
		// （与 IFF_RUNNING 不同，后者表示接口物理链路是否活动。）
		up := (flags & syscall.IFF_UP) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		// ===== MTU 变化检测 =====
		// 读取接口 MTU，在 ifmsghdr 中偏移 24 字节的位置（if_data.ifi_mtu）
		mtu := int(*(*uint32)(unsafe.Pointer(&data[24 /* ifm_data.ifi_mtu */])))

		// MTU 发生变化时发送 EventMTUUpdate 事件
		if mtu != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = mtu
	}
}

// CreateTUN 在 macOS 上创建并配置一个 utun 接口。
//
// macOS 的 utun 驱动不是通过打开 /dev/tunX 设备文件方式，
// 而是使用 BSD 特有的 "Kernel Control API"：
//  1. 调用 socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) 创建控制 socket；
//  2. 通过 ioctl CTLIOCGINFO 根据名称 com.apple.net.utun_control
//     查到该内核控制模块的 ID；
//  3. 构造 SockaddrCtl 结构体并 connect：
//     - ID   = 查找到的内核控制器 ID
//     - Unit = 想要绑定的 utun 编号 + 1（Unit 从 1 开始，
//     Unit=1 对应 utun0，Unit=4 对应 utun3，以此类推）
//
// 参数:
//   - name: 期望的接口名，格式必须为 "utun" 或 "utunN"（N 为非负整数）。
//     传 "utun" 表示让内核自动分配一个未使用的编号。
//   - mtu : 期望设置的 MTU 值，<=0 表示使用系统默认值。
//
// 返回: 实现 Device 接口的 *NativeTun 对象，或错误。
func CreateTUN(name string, mtu int) (Device, error) {
	// 解析接口名，提取用户指定的编号
	ifIndex := -1
	if name != "utun" {
		// 从 "utun%d" 中解析数字
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]*")
		}
	}

	// 步骤 1: 创建 AF_SYSTEM / SOCK_DGRAM / SYSPROTO_CONTROL 类型的 socket。
	// AF_SYSTEM 是 macOS 特有的地址族，用于用户态进程与内核扩展
	// （NKE / KEXT）之间通信；SYSPROTO_CONTROL 表示使用 Kernel
	// Control 协议。此处 proto 参数 2 即 #define SYSPROTO_CONTROL 2。
	// 使用 socketCloexec 包装，保证 fd 设置了 FD_CLOEXEC（执行 exec 时关闭）
	// 并通过 ForkLock 防止与 fork 发生竞态。
	fd, err := socketCloexec(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, err
	}

	// 步骤 2: 通过控制 socket 调用 ioctl CTLIOCGINFO 查询
	// com.apple.net.utun_control 控制器的内核 ID 等信息。
	// 结果填充到 ctlInfo 中，其中 ctlInfo.Id 就是后续 connect 所需的 ID。
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], []byte(utunControlName))
	err = unix.IoctlCtlInfo(fd, ctlInfo)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("IoctlGetCtlInfo, %w", err)
	}

	// 步骤 3: 构造 SockaddrCtl 并调用 connect 将 socket 绑定到指定 utun 单元。
	//   - ID:   内核控制器 ID（上一步查询得到）
	//   - Unit: 单元号。注意：Unit 从 1 开始编号。
	//           用户传 "utun0" -> ifIndex=0 -> Unit=1 -> 绑定到 utun0；
	//           用户传 "utun5" -> ifIndex=5 -> Unit=6 -> 绑定到 utun5；
	//           用户传 "utun"  -> ifIndex=-1 -> Unit=0，让内核自动挑选。
	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}

	err = unix.Connect(fd, sc)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// 步骤 4: 设置 socket 为非阻塞模式。
	// os.File 的 Read/Write 调度依赖非阻塞 fd + netpoller。
	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// 步骤 5: 将 fd 包装为 os.File，交给 CreateTUNFromFile 完成剩余初始化
	// （创建 NativeTun、启动路由监听、设置 MTU 等）
	tun, err := CreateTUNFromFile(os.NewFile(uintptr(fd), ""), mtu)

	// 如果用户传的是通配名 "utun"（自动分配编号），
	// 且环境变量 WG_TUN_NAME_FILE 被设置，则将实际分配到的接口名
	// 写入该文件。此机制用于外部脚本/工具获取实际接口名。
	if err == nil && name == "utun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			os.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0o400)
		}
	}

	return tun, err
}

// CreateTUNFromFile 接受一个已经就绪的 utun socket 文件对象，
// 完成 NativeTun 结构体的剩余初始化：
//  1. 通过 getsockopt 查询接口名；
//  2. 根据名字查到接口 ifindex；
//  3. 创建 AF_ROUTE socket 用于事件监听；
//  4. 启动 routineRouteListener 后台 goroutine；
//  5. 如 mtu>0 则调用 setMTU 设置 MTU。
//
// 参数:
//   - file: 已经 connect 到 utun 控制单元的 *os.File。
//   - mtu : 期望 MTU，<=0 则跳过设置。
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 5),
	}

	// 获取实际接口名（如 "utun2"）并缓存到 tun.name
	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	// 查询接口的 ifindex，用于后续在路由消息中过滤本接口
	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	// 创建 AF_ROUTE / SOCK_RAW socket，用于接收内核网络事件通知
	tun.routeSocket, err = socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	// 启动后台事件监听 goroutine
	go tun.routineRouteListener(tunIfindex)

	// 若指定了 MTU 则设置之，失败则回滚关闭
	if mtu > 0 {
		err = tun.setMTU(mtu)
		if err != nil {
			tun.Close()
			return nil, err
		}
	}

	return tun, nil
}

// Name 返回 utun 接口的实际名称（如 "utun0"）。
//
// macOS 上无法通过 ioctl 查询，而是使用 getsockopt 读取：
//   - level  = SYSPROTO_CONTROL (2)
//   - optname= UTUN_OPT_IFNAME (2)
//
// 该选项直接返回内核分配的接口名字符串。
func (tun *NativeTun) Name() (string, error) {
	var err error
	// operateOnFd 封装了 os.File.SyscallConn().Control()，
	// 安全地在 fd 上执行回调（保证 fd 在回调期间不会被 finalize 关闭）
	tun.operateOnFd(func(fd uintptr) {
		tun.name, err = unix.GetsockoptString(
			int(fd),
			2, /* #define SYSPROTO_CONTROL 2    - socket level */
			2, /* #define UTUN_OPT_IFNAME    2    - option name  */
		)
	})

	if err != nil {
		return "", fmt.Errorf("GetSockoptString, %w", err)
	}

	return tun.name, nil
}

// File 返回底层的 TUN 设备文件对象。
// 主要用于外部代码需要获取原始 fd 的场景（如进一步 ioctl 配置）。
func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

// Events 返回事件接收通道。
// 外部 tun.Device 使用者从此通道读取：
//
//	EventUp / EventDown / EventMTUUpdate
func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

// Read 从 utun 设备读取一条 IP 报文到 bufs[0] 中，
// 返回读取到的报文数量（在 macOS 上始终是 1 或 0）。
//
// ===== macOS / BSD 上 4 字节地址族（AF）头部说明 =====
// 当启用了 TUNSIFHEAD（"packet info" / IFHEAD）模式后，
// 从 /dev/tunX 或 utun socket 读出的每个报文前面会多一个 4 字节头部：
//
//	  字节 0    1    2    3    4    5    6    7    ...
//	+----+----+----+----+----+----+----+----+
//	| 00 | 00 | 00 | AF | IP / IPv6 报文内容...     |
//	+----+----+----+----+----+----+----+----+
//
// 其中前 3 字节固定为 0x00（用于地址族字段之前的预留/对齐），
// 第 4 字节（offset 3）是 BSD 地址族常量：
//
//	0x02 = AF_INET  (IPv4)
//	0x1E = AF_INET6 (IPv6)
//
// 为什么需要这个 4 字节头部？
//  1. 区分协议：同一个 TUN 接口同时承载 IPv4 和 IPv6 报文时，
//     内核通过此头部告知用户态读到的报文是哪种 IP 版本；
//     写入时用户态也要告知内核要把报文投递到哪个协议栈。
//  2. 历史兼容：早期 tun 驱动只支持 IPv4，不带头部；
//     后来加入多协议支持后，通过 TUNSIFHEAD 开关选择是否带 AF 头。
//  3. 对上层 WireGuard 而言，我们只需要完整的 IP 包（从 offset 4 开始），
//     所以在 Read 时 sizes[0] = n - 4，去掉前面 4 字节。
//
// 参数:
//   - bufs  : 接收缓冲区切片（只使用 bufs[0]，BatchSize=1）
//   - sizes : 每个缓冲区实际写入的字节数（同样只用 sizes[0]）
//   - offset: IP 报文应放置的起始偏移。实际读取时从 offset-4 开始，
//     让 4 字节 AF 头放在 IP 报文之前，便于上层统一处理。
func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// 先检查 errors 通道是否有后台错误待处理
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		// 从 offset-4 开始读：buf[offset-4 .. offset-1] 放 AF 头，
		// buf[offset .. ] 放实际 IP 报文内容
		buf := bufs[0][offset-4:]
		n, err := tun.tunFile.Read(buf[:])
		if n < 4 {
			return 0, err
		}
		// sizes[0] 只计 IP 报文长度，去掉前面 4 字节 AF 头
		sizes[0] = n - 4
		return 1, err
	}
}

// Write 将 bufs 中若干个 IP 报文写入 TUN 设备。
// 每个报文在写入前需要补上 4 字节的 AF 头。
//
// 在 offset 指定位置之前（offset-4 ~ offset-1）写入：
//
//	buf[offset-4] = 0x00
//	buf[offset-3] = 0x00
//	buf[offset-2] = 0x00
//	buf[offset-1] = AF_INET (2) 或 AF_INET6 (30/0x1E)
//
// AF 的判断方式：检查 buf[offset] 即 IP 报文第一个字节的高 4 位。
//   - IPv4 首字节高 4 位 = 4（Version=4）
//   - IPv6 首字节高 4 位 = 6（Version=6）
//     buf[offset] >> 4 正好得到版本号。
//
// 参数:
//   - bufs  : 待发送报文缓冲区切片
//   - offset: 每个缓冲区中 IP 报文起始偏移。
//     要求 offset>=4，方便在前面写 AF 头。
//
// 返回: 实际成功写入的报文数量。
func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		// 写 4 字节 AF 头：前 3 字节为 0，第 4 字节填地址族
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		// IP 版本号在 IP 报文首字节（即当前 buf[4]）的高 4 位
		switch buf[4] >> 4 {
		case 4:
			buf[3] = unix.AF_INET
		case 6:
			buf[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := tun.tunFile.Write(buf); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// Close 关闭 TUN 设备，释放所有资源。
// 使用 sync.Once 保证并发调用也只会实际关闭一次。
// 关闭流程：
//  1. 关闭 utun 的 tunFile（底层 socket fd）；
//  2. 关闭 AF_ROUTE routeSocket（先 shutdown 再 close 防止阻塞）。
//     routeSocket 若未初始化（为 -1），则兜底关闭 events 通道。
func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		if tun.routeSocket != -1 {
			// 先 SHUT_RDWR 让阻塞在 Read 上的 goroutine 立刻返回错误退出
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err2 = unix.Close(tun.routeSocket)
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

// setMTU 设置接口 MTU 值，通过 ioctl SIOCSIFMTU 实现。
// 需要一个临时的 AF_INET datagram socket 来承载 ioctl（ioctl 不需要
// 绑定地址，只需要一个有效的 socket fd 即可）。
func (tun *NativeTun) setMTU(n int) error {
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// unix.IfreqMTU 是 ifreq 的变体：前 IFNAMSIZ 字节是接口名，
	// 紧接着是 int32 MTU 字段。
	var ifr unix.IfreqMTU
	copy(ifr.Name[:], tun.name)
	ifr.MTU = int32(n)
	err = unix.IoctlSetIfreqMTU(fd, &ifr)
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s, %w", tun.name, err)
	}

	return nil
}

// MTU 查询接口当前 MTU，通过 ioctl SIOCGIFMTU 实现。
func (tun *NativeTun) MTU() (int, error) {
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	ifr, err := unix.IoctlGetIfreqMTU(fd, tun.name)
	if err != nil {
		return 0, fmt.Errorf("failed to get MTU on %s, %w", tun.name, err)
	}

	return int(ifr.MTU), nil
}

// BatchSize 返回单次 Read/Write 调用能处理的最大报文数。
// macOS/BSD 上 tun 设备不支持 recvmmsg/sendmmsg 式的批量收发，
// 每次系统调用只能处理一个报文，因此返回 1。
func (tun *NativeTun) BatchSize() int {
	return 1
}

// socketCloexec 创建一个 socket，并在 fork() 与 close-on-exec 之间
// 做了正确的竞态保护。返回的 fd 一定设置了 FD_CLOEXEC 标志位，
// 即在执行 execve() 类系统调用时 fd 会被自动关闭，防止泄漏给子进程。
//
// 为什么需要 ForkLock？
//
//	Go 运行时在某些场景下会 fork（例如 exec.Command 底层使用 fork+exec），
//	如果在创建 socket 到设置 FD_CLOEXEC 之间被 fork 打断，
//	子进程会继承这个未设置 CLOEXEC 的 fd，造成资源泄漏。
//	标准库通过 syscall.ForkLock 这个全局读写锁来同步：
//	  - fork 操作持有写锁；
//	  - 创建 fd + 设置 CLOEXEC 这段临界区持有读锁。
//	这正是 Go 标准库 net 包 sys_cloexec.go 中的惯用做法。
func socketCloexec(family, sotype, proto int) (fd int, err error) {
	// See go/src/net/sys_cloexec.go for background.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	fd, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return
}
