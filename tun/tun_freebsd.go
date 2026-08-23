/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ===== FreeBSD TUN 驱动专用 ioctl 常量定义 =====
// 这些常量与 FreeBSD 内核 <sys/sockio.h> 与 <net/if_tunvar.h> 中定义的
// ioctl request 编号完全一致。ioctl 编号的编码规则遵循 BSD _IOC 宏：
//
//	位 29-31 方向: 0x2=IOC_IN, 0x1=IOC_OUT, 0x3=IOC_INOUT
//	位 16-28 参数大小（字节）
//	位  8-15 组（如 't' = 0x74 表示 tun）
//	位  0-7  子编号
const (
	// _TUNSIFHEAD:  Set IFHEAD mode，参数是指向 int 的指针（4 字节）。
	//   编码 IOC_IN | 4 | 't'<<8 | 0x60
	//   当设为 1 时，从 tun 设备读写的每个报文前面都要带 4 字节 AF 头
	//   （与 darwin/openbsd 相同格式），从而支持同一接口承载 v4+v6。
	//   关闭时（默认）仅支持 IPv4，报文不带 AF 头。
	_TUNSIFHEAD = 0x80047460

	// _TUNSIFMODE:  Set interface mode，参数是指向 int 标志位的指针。
	//   用于在 PTP(Point-to-Point) 模式和 BROADCAST/MULTICAST 模式之间切换。
	//   编码 IOC_IN | 4 | 't'<<8 | 0x5e
	_TUNSIFMODE = 0x8004745e

	// _TUNGIFNAME:  Get interface name，参数是指向 ifreqName 结构体的指针
	//   （16 字节 name + 16 字节填充 = 32 字节）。
	//   编码 IOC_OUT | 32 | 't'<<8 | 0x5d
	_TUNGIFNAME = 0x4020745d

	// _TUNSIFPID:   Set controlling PID，参数是 pid_t（传 0 表示当前进程）。
	//   用于设置 "控制进程"，当进程退出时内核自动销毁 tun 接口。
	//   编码 IOC_IN | 4 | 't'<<8 | 0x5f
	_TUNSIFPID = 0x2000745f

	// ===== IPv6 ND6（邻居发现协议）相关 ioctl =====

	// _SIOCGIFINFO_IN6: 获取接口的 IPv6 ND6 信息，大小 0x48=72 字节
	_SIOCGIFINFO_IN6 = 0xc048696c
	// _SIOCSIFINFO_IN6: 设置接口的 IPv6 ND6 信息
	_SIOCSIFINFO_IN6 = 0xc048696d

	// _ND6_IFF_AUTO_LINKLOCAL: ND6 标志位，表示内核自动给接口分配
	//   链路本地 IPv6 地址（fe80::/10）。我们手动清掉此位，避免
	//   FreeBSD 内核在 TUN 接口上自动生成并挂载 LLv6 地址。
	_ND6_IFF_AUTO_LINKLOCAL = 0x20

	// _ND6_IFF_NO_DAD: ND6 标志位，表示在 IPv6 地址上禁用
	//   Duplicate Address Detection（重复地址检测）。
	//   TUN 接口是点到点隧道，不可能有地址冲突，禁用 DAD
	//   可以避免等待 DAD 超时带来的延迟与竞态。
	_ND6_IFF_NO_DAD = 0x100
)

// ===== ifreq 系列结构体定义 =====
// FreeBSD 的 ioctl 大多数通过 <net/if.h> 中的 struct ifreq 传递参数。
// ifreq 的前 16 字节固定为 ifr_name[IFNAMSIZ]（接口名，含终止 NUL），
// 后面 16 字节是 union ifr_ifru（存放指针、整数、地址结构体等）。
// 为了 Go 中类型安全，我们根据不同用途定义三种具体的结构体，
// 每个结构体都固定大小 32 字节（16 + 16），与内核 struct ifreq 大小对齐。

// Iface requests with just the name
// ifreqName: 只使用接口名字段的 ifreq 变体（其余字段保留为 0）。
//
//	主要用于 _TUNGIFNAME：ioctl 读取后在内核端回填 Name 字段。
type ifreqName struct {
	// Name: 接口名称缓冲区，IFNAMSIZ=16 字节，最后一字节为 \0。
	Name [unix.IFNAMSIZ]byte
	// 16 字节保留填充，使整个结构体大小 == sizeof(struct ifreq) == 32。
	_ [16]byte
}

// Iface requests with a pointer
// ifreqPtr: 携带一个指针参数的 ifreq 变体。
//
//	用于 SIOCSIFNAME（改名 ioctl），Data 指向存放新名字的缓冲区。
type ifreqPtr struct {
	// Name: 要操作的源接口名称。
	Name [unix.IFNAMSIZ]byte
	// Data: 指针参数（uintptr 表示），如指向新接口名缓冲区。
	Data uintptr
	// 剩余填充字节。在 64 位平台 uintptr=8 字节，故还需 16-8=8 字节填充；
	// 在 32 位平台 uintptr=4 字节，还需 12 字节填充。
	_ [16 - unsafe.Sizeof(uintptr(0))]byte
}

// Iface requests with MTU
// ifreqMtu: 携带 MTU 整数值的 ifreq 变体。
//
//	用于 SIOCSIFMTU（设置 MTU）和 SIOCGIFMTU（获取 MTU）。
type ifreqMtu struct {
	// Name: 接口名。
	Name [unix.IFNAMSIZ]byte
	// MTU:  最大传输单元值（单位字节），FreeBSD 内核使用 uint32。
	MTU uint32
	// 12 字节填充使总大小达到 32 字节（16 name + 4 mtu + 12 pad）。
	_ [12]byte
}

// ND6 flag manipulation
// nd6Req: 对应 FreeBSD 内核 struct nd6_ifreq，用于通过
//
//	SIOCGIFINFO_IN6 / SIOCSIFINFO_IN6 两个 ioctl 读取和修改
//	接口级别的 IPv6 Neighbor Discovery 参数。
//	整个结构体大小 0x48=72 字节，与 _SIOCGIFINFO_IN6 编码中的
//	参数长度一致。
type nd6Req struct {
	// Name: 要操作的接口名称（16 字节）。
	Name [unix.IFNAMSIZ]byte
	// Linkmtu: 接口链路 MTU（IPv6 相关）。
	Linkmtu uint32
	// Maxmtu: 允许的最大 MTU。
	Maxmtu uint32
	// Basereachable: 基础可达时间（毫秒）。
	Basereachable uint32
	// Reachable: 当前可达时间。
	Reachable uint32
	// Retrans: 重传定时器（毫秒）。
	Retrans uint32
	// Flags: ND6 接口标志位（我们关心 AUTO_LINKLOCAL 和 NO_DAD 两位）。
	Flags uint32
	// Recalctm: 重新计算计时器（单位 tick）。
	Recalctm int
	// Chlim: IPv6 默认跳数限制（Hop Limit）。
	Chlim uint8
	// Initialized: 标志，表示该接口 ND6 是否已初始化。
	Initialized uint8
	// Randomseed0/Randomseed1/Randomid: DAD 临时 ID 生成器的随机种子。
	Randomseed0 [8]byte
	Randomseed1 [8]byte
	Randomid    [8]byte
}

// NativeTun 是 FreeBSD 平台 TUN 设备的 Go 层封装。
type NativeTun struct {
	// name: 接口名称（如 "tun0"、"wg0"）。通过 ioctl 读取后缓存。
	name string
	// tunFile: 打开 /dev/tun 得到的文件对象。读写 IP 报文通过它。
	tunFile *os.File
	// events: 对外发布的事件通道（EventUp / EventDown / EventMTUUpdate）。
	events chan Event
	// errors: 后台 goroutine 发生错误时写入此通道。
	errors chan error
	// routeSocket: AF_ROUTE socket，用于订阅内核接口变化事件。
	routeSocket int
	// closeOnce: 并发安全地保证 Close() 只执行一次资源清理。
	closeOnce sync.Once
}

// routineRouteListener 从 AF_ROUTE socket 读取路由消息，
// 监听本接口的标志位和 MTU 变化并发送事件。
//
// FreeBSD 64 位平台上 struct ifmsghdr 在 data 字节数组中的偏移：
//
//	data[0..1]   ifm_msglen   uint16  消息总长度
//	data[2]      ifm_version  uint8   消息版本
//	data[3]      ifm_type     uint8   消息类型（只处理 RTM_IFINFO）
//	data[4..5]   ifm_hdrlen   uint16  头部长度
//	data[6..7]   ifm_index    uint16  接口索引（ifindex）
//	data[8..11]  ifm_flags    int32   接口标志位
//	data[12..]   (可选地址结构与 if_data)
//
// 这里我们不像 darwin 那样直接从 data 偏移解析 MTU，
// 而是在收到 RTM_IFINFO 时通过 net.InterfaceByIndex() 重新查询
// 接口的最新 Flags 和 MTU——这样做虽然多了一次系统调用，
// 但 FreeBSD 不同版本之间 ifmsghdr + if_data 的布局可能略有差异，
// 走标准库 net.Interface 接口更具移植性。
func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		// statusUp:  上一次检测到的 Up/Down 状态
		statusUp bool
		// statusMTU: 上一次检测到的 MTU 值
		statusMTU int
	)

	defer close(tun.events)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				goto retry
			}
			tun.errors <- err
			return
		}

		// 消息至少需要 14 字节（头部含 ifindex）
		if n < 14 {
			continue
		}

		// 只处理接口信息变化消息
		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		// 从偏移 6 读取接口索引（FreeBSD 上 ifm_index 在 ifm_hdrlen 之后）
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		// 调用标准库查询接口完整信息（Flags + MTU）
		iface, err := net.InterfaceByIndex(ifindex)
		if err != nil {
			tun.errors <- err
			return
		}

		// Up / Down event
		up := (iface.Flags & net.FlagUp) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

// tunName 从 /dev/tun 文件描述符读取内核分配的接口名称。
// 使用 _TUNGIFNAME ioctl，参数是 ifreqName 结构体，内核在其中填入名字。
func tunName(fd uintptr) (string, error) {
	var ifreq ifreqName
	_, _, err := unix.Syscall(unix.SYS_IOCTL, fd, _TUNGIFNAME, uintptr(unsafe.Pointer(&ifreq)))
	if err != 0 {
		return "", err
	}
	// 把 C 风格定长字节数组转成 Go 字符串（自动截断第一个 NUL 前的内容）
	return unix.ByteSliceToString(ifreq.Name[:]), nil
}

// Destroy a named system interface
// tunDestroy 显式销毁一个 FreeBSD TUN 接口。
// 当 close /dev/tunX fd 时，接口通常会自动消失；
// 但如果曾经设置过 "controlling PID"（见 _TUNSIFPID），
// 或者进程以非正常方式退出导致内核认为仍有使用者，
// 就需要通过 SIOCIFDESTROY ioctl 显式删除接口。
func tunDestroy(name string) error {
	// SIOCIFDESTROY 需要一个任意类型的 socket fd 承载 ioctl
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// ioctl 参数只需前 16 字节填接口名即可
	var ifr [32]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCIFDESTROY), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return fmt.Errorf("failed to destroy interface %s: %w", name, errno)
	}

	return nil
}

// CreateTUN 在 FreeBSD 上创建一个 TUN 接口并完成所有必要配置。
//
// 主要流程:
//  1. 打开 /dev/tun（克隆设备），内核自动分配一个未使用的 tunN；
//  2. 通过 _TUNGIFNAME 获取自动分配的名字（如 "tun2"）；
//  3. _TUNSIFHEAD=1 开启 4 字节 AF 头模式（必须，否则只支持 IPv4）；
//  4. _TUNSIFMODE 设置为 BROADCAST|MULTICAST，退出默认 PTP 模式
//     （否则 TUN 接口是 IFF_POINTOPOINT，WireGuard 运行需要
//     BROADCAST + MULTICAST 标志，使内核把它当成普通广播接口对待）；
//  5. 通过 SIOCGIFINFO_IN6 / SIOCSIFINFO_IN6 操作 nd6Req：
//     - 关闭 AUTO_LINKLOCAL（不自动分配 fe80:: LLv6 地址）；
//     - 打开 NO_DAD（跳过 IPv6 重复地址检测）；
//     这两步是为了规避 FreeBSD 内核中 TUN 接口在 attach/detach
//     链路本地 v6 地址时存在的生命周期竞态。
//  6. 如果用户指定了自定义 name（不是空串），通过 SIOCSIFNAME
//     把默认的 "tunN" 改成用户想要的名字（如 "wg0"）。
func CreateTUN(name string, mtu int) (Device, error) {
	// IFNAMSIZ=16，至少留 1 字节给 NUL，所以名称不能超过 15 字节
	if len(name) > unix.IFNAMSIZ-1 {
		return nil, errors.New("interface name too long")
	}

	// See if interface already exists
	// 如果同名接口已存在则直接报错，避免与其它工具冲突
	iface, _ := net.InterfaceByName(name)
	if iface != nil {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	// 步骤 1: 打开 FreeBSD 的克隆设备 /dev/tun。
	// 每次 open("/dev/tun") 内核都会分配一个新的未使用的 tunN。
	// 同时加上 O_CLOEXEC 防止 fd 泄漏到 exec 的子进程。
	tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	tun := NativeTun{tunFile: tunFile}
	var assignedName string
	// 步骤 2: 通过 _TUNGIFNAME ioctl 读内核给我们分配的名字
	tun.operateOnFd(func(fd uintptr) {
		assignedName, err = tunName(fd)
	})
	if err != nil {
		tunFile.Close()
		return nil, err
	}

	// Enable ifhead mode, otherwise tun will complain if it gets a non-AF_INET packet
	// 步骤 3: 开启 IFHEAD（带 AF 头）模式。这样每个报文前 4 字节为 AF。
	ifheadmode := 1
	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, _TUNSIFHEAD, uintptr(unsafe.Pointer(&ifheadmode)))
	})

	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to put into IFHEAD mode: %w", errno)
	}

	// Get out of PTP mode.
	// 步骤 4: 设置接口标志为 BROADCAST|MULTICAST。
	// 由于 WireGuard 在内核层把 TUN 当作一个普通的虚拟以太网接口
	// （虽然它实际上是 L3），需要 BROADCAST 和 MULTICAST 标志让
	// 路由与多播系统正确工作。
	ifflags := syscall.IFF_BROADCAST | syscall.IFF_MULTICAST
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(_TUNSIFMODE), uintptr(unsafe.Pointer(&ifflags)))
	})

	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to put into IFF_BROADCAST mode: %w", errno)
	}

	// Disable link-local v6, not just because WireGuard doesn't do that anyway, but
	// also because there are serious races with attaching and detaching LLv6 addresses
	// in relation to interface lifetime within the FreeBSD kernel.
	// 步骤 5: 调整 IPv6 ND6 标志。
	confd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, err
	}
	defer unix.Close(confd6)
	var ndireq nd6Req
	// 5a: 先 GET 当前 nd6 信息到 ndireq
	copy(ndireq.Name[:], assignedName)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd6), uintptr(_SIOCGIFINFO_IN6), uintptr(unsafe.Pointer(&ndireq)))
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to get nd6 flags for %s: %w", assignedName, errno)
	}
	// 5b: 修改 flags 位：清除 AUTO_LINKLOCAL；设置 NO_DAD
	ndireq.Flags = ndireq.Flags &^ _ND6_IFF_AUTO_LINKLOCAL
	ndireq.Flags = ndireq.Flags | _ND6_IFF_NO_DAD
	// 5c: 再 SET 回去
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd6), uintptr(_SIOCSIFINFO_IN6), uintptr(unsafe.Pointer(&ndireq)))
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to set nd6 flags for %s: %w", assignedName, errno)
	}

	// 步骤 6: 如果用户传入了非空 name，把接口从 "tunN" 改名到用户指定名
	if name != "" {
		confd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			tunFile.Close()
			tunDestroy(assignedName)
			return nil, err
		}
		defer unix.Close(confd)
		var newnp [unix.IFNAMSIZ]byte
		copy(newnp[:], name)
		var ifr ifreqPtr
		copy(ifr.Name[:], assignedName)
		// SIOCSIFNAME 的 ifr_data 字段需指向一个 IFNAMSIZ 缓冲区（新名字）
		ifr.Data = uintptr(unsafe.Pointer(&newnp[0]))
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd), uintptr(unix.SIOCSIFNAME), uintptr(unsafe.Pointer(&ifr)))
		if errno != 0 {
			tunFile.Close()
			tunDestroy(assignedName)
			return nil, fmt.Errorf("Failed to rename %s to %s: %w", assignedName, name, errno)
		}
	}

	// 把 tunFile 交给 CreateTUNFromFile 完成后续初始化（事件监听、MTU 等）
	return CreateTUNFromFile(tunFile, mtu)
}

// CreateTUNFromFile 从一个已经 open 好的 /dev/tun 文件对象出发，
// 完成 NativeTun 的通用初始化：
//  1. 通过 _TUNSIFPID 把当前进程设置为控制进程（进程退出自动清理接口）；
//  2. 读取接口名；
//  3. 创建 AF_ROUTE socket；
//  4. 启动事件监听 goroutine；
//  5. 设置 MTU。
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
	}

	// _TUNSIFPID(0): 把调用者当前进程设为该 TUN 接口的控制进程。
	// 当此进程退出（即使没有显式 close/destroy），内核也会自动销毁
	// TUN 接口，防止孤儿接口残留。
	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, _TUNSIFPID, uintptr(0))
	})
	if errno != 0 {
		tun.tunFile.Close()
		return nil, fmt.Errorf("unable to become controlling TUN process: %w", errno)
	}

	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

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

	// 创建 AF_ROUTE socket 用于事件监听
	tun.routeSocket, err = unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	go tun.routineRouteListener(tunIfindex)

	// 设置 MTU（FreeBSD 上默认 MTU 一般为 1500）
	err = tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

// Name 返回接口当前名称。
// 在 FreeBSD 上通过 _TUNGIFNAME ioctl 从底层 tun fd 获取接口名。
func (tun *NativeTun) Name() (string, error) {
	var name string
	var err error
	tun.operateOnFd(func(fd uintptr) {
		name, err = tunName(fd)
	})
	if err != nil {
		return "", err
	}
	tun.name = name
	return name, nil
}

// File 返回底层 TUN 设备文件对象。
func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

// Events 返回事件接收通道。
func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

// Read 从 TUN 设备读取一条 IP 报文。
// 格式详见 darwin.go Read 注释：报文前带 4 字节 AF 头。
// sizes[0] = n - 4，去掉 AF 头只保留 IP 包本身。
func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		// 从 offset-4 开始读：offset-4..offset-1 放 AF 头，offset 起放 IP 报文
		buf := bufs[0][offset-4:]
		n, err := tun.tunFile.Read(buf[:])
		if n < 4 {
			return 0, err
		}
		sizes[0] = n - 4
		return 1, err
	}
}

// Write 向 TUN 设备写入若干 IP 报文，报文前需补 4 字节 AF 头。
// 详见 darwin.go Write 注释。
func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		if len(buf) < 5 {
			return i, io.ErrShortBuffer
		}
		// 写 4 字节 AF 头：[0, 0, 0, AF]
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		// IP 版本号在 IP 首字节（buf[4]）高 4 位
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

// Close 关闭 TUN 设备。
// FreeBSD 上除了关闭 tunFile 和 routeSocket，还要显式调用 tunDestroy
// 通过 SIOCIFDESTROY 删除网络接口——因为即使关闭了 /dev/tun fd，
// 控制进程标志（_TUNSIFPID）可能使接口仍驻留在内核中。
func (tun *NativeTun) Close() error {
	var err1, err2, err3 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		// FreeBSD 特有：显式 SIOCIFDESTROY 销毁接口
		err2 = tunDestroy(tun.name)
		if tun.routeSocket != -1 {
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err3 = unix.Close(tun.routeSocket)
			tun.routeSocket = -1
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

// setMTU 设置接口 MTU。通过 SIOCSIFMTU ioctl 实现，
// 载体为 ifreqMtu 结构体。
func (tun *NativeTun) setMTU(n int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr ifreqMtu
	copy(ifr.Name[:], tun.name)
	ifr.MTU = uint32(n)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, errno)
	}
	return nil
}

// MTU 查询接口当前 MTU。使用 SIOCGIFMTU ioctl。
func (tun *NativeTun) MTU() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var ifr ifreqMtu
	copy(ifr.Name[:], tun.name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU on %s: %w", tun.name, errno)
	}
	// 虽然 ifr.MTU 类型是 uint32，但 FreeBSD 内部把 MTU 当作 signed
	// int32 存储，所以这里转成 int32 再转 int 保证符号正确。
	return int(*(*int32)(unsafe.Pointer(&ifr.MTU))), nil
}

// BatchSize 返回 1（FreeBSD 不支持批量收发）。
func (tun *NativeTun) BatchSize() int {
	return 1
}
