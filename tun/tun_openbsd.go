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

// Structure for iface mtu get/set ioctls
// ifreq_mtu 对应 OpenBSD 内核中 struct ifreq 的 MTU 变体。
// 用于 SIOCSIFMTU（设置 MTU）和 SIOCGIFMTU（获取 MTU）两个 ioctl。
// OpenBSD 的 struct ifreq 共 32 字节：前 IFNAMSIZ=16 字节是接口名，
// 紧接着是 4 字节 MTU 字段，最后 12 字节填充对齐。
type ifreq_mtu struct {
	// Name: 接口名（IFNAMSIZ=16 字节，最后一字节 NUL 终止）。
	Name [unix.IFNAMSIZ]byte
	// MTU:  MTU 值，uint32。
	MTU  uint32
	// Pad0: 12 字节填充，使整个结构体与 sizeof(struct ifreq) 对齐。
	Pad0 [12]byte
}

// _TUNSIFMODE: OpenBSD 上切换 TUN 模式的 ioctl 编号。
// 编码: IOC_IN | 4 | 't'<<8 | 0x5d = 0x8004745d。
// 参数是一个 int 指针，存放接口标志位。
// 与 FreeBSD 类似，我们用它把接口从默认 PTP（点对点）模式切换到
// BROADCAST|MULTICAST 模式，让 WireGuard 能像普通 L3 接口一样工作。
const _TUNSIFMODE = 0x8004745d

// NativeTun 是 OpenBSD 平台上 TUN 设备的 Go 层封装结构体。
// 字段含义与 darwin/freebsd 上基本一致。
type NativeTun struct {
	// name: 接口名称（如 "tun0"、"wg0"）。通过 Stat_t.Rdev 次设备号推导，
	//       或由调用者在 CreateTUN 中显式给定。
	name        string
	// tunFile: 打开 /dev/tunN 得到的文件对象。实际 IP 报文通过它读写。
	tunFile     *os.File
	// events: 事件通道（EventUp / EventDown / EventMTUUpdate），容量 10。
	events      chan Event
	// errors: 后台 goroutine 错误通道，容量 1。
	errors      chan error
	// routeSocket: AF_ROUTE 域原始 socket，用于接收内核 RTM_IFINFO 消息。
	routeSocket int
	// closeOnce: 保证 Close() 只做一次实际清理，防止并发 double close。
	closeOnce   sync.Once
}

// routineRouteListener 后台 goroutine：从 AF_ROUTE socket 读取
// 路由消息（ifmsghdr），监测本接口（tunIfindex）的 UP/DOWN 状态
// 和 MTU 变化，向 events 通道发送相应事件。
//
// OpenBSD 64 位平台上 struct ifmsghdr 在字节数组中的偏移
//（与 FreeBSD/Darwin 略有差异，OpenBSD 的 ifmsghdr 更紧凑）：
//   data[0..1]   ifm_msglen  uint16  整个消息长度
//   data[2]      ifm_version uint8   消息版本号
//   data[3]      ifm_type    uint8   消息类型（RTM_IFINFO=0x0e 等）
//   data[4..5]   ifm_hdrlen  uint16  头部长度
//   data[6..7]   ifm_index   uint16  接口索引（ifindex）
//   注意 OpenBSD 上没有显式的 ifm_flags 字段在 ifmsghdr 内，
//   flags/MTU 需要通过 net.InterfaceByIndex 查询。
//
// 实际处理流程：
//   1. 进入 check() 先做一次立即查询（初始化初始 statusUp/statusMTU 状态，
//      并在 goroutine 启动瞬间接口已 UP 时立即发事件）；
//   2. 每次 Read 到 RTM_IFINFO 且 ifindex 匹配时，再次调用 check()
//      比较并发送事件；
//   3. check() 返回 true 表示出错（写 errors 通道），主循环直接退出。
func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		// statusUp  缓存上次接口 Up 状态
		statusUp  bool
		// statusMTU 缓存上次接口 MTU 值
		statusMTU int
	)

	defer close(tun.events)

	// check: 封装一次完整的接口状态采样和事件对比逻辑
	check := func() bool {
		iface, err := net.InterfaceByIndex(tunIfindex)
		if err != nil {
			tun.errors <- err
			return true
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
		return false
	}

	// goroutine 启动时立即采样一次，避免错过启动前已存在的状态
	if check() {
		return
	}

	data := make([]byte, os.Getpagesize())
	for {
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EINTR {
				continue
			}
			tun.errors <- err
			return
		}

		// OpenBSD ifmsghdr 最小长度为 8 字节
		if n < 8 {
			continue
		}

		// 只处理 RTM_IFINFO（接口信息变更）类型
		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		// OpenBSD 上 ifindex 位于偏移 6..7（uint16）
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[6 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}
		// 匹配本接口，重新采样并比较
		if check() {
			return
		}
	}
}

// CreateTUN 在 OpenBSD 上创建并配置一个 TUN 接口。
//
// OpenBSD 与 FreeBSD 在 TUN 设备上的主要区别：
//   1. OpenBSD 没有 /dev/tun "克隆设备" 的概念，每次需要显式打开
//      /dev/tun0 ~ /dev/tun255 中某个具体的设备文件；
//   2. 若用户传 "tun"（不带编号），则从 tun0 到 tun255 依次尝试 open，
//      遇到第一个不返回 EBUSY 的即表示成功占用；
//   3. OpenBSD 不支持在用户态直接对 TUN 接口改名（没有 SIOCSIFNAME），
//      所以接口名永远是 "tunN"（N 为 0..255）。
//
// 参数:
//   - name: "tun" 或 "tunN"（N 为 0~255）。"tun" 表示自动查找空闲编号。
//   - mtu : 期望 MTU。
func CreateTUN(name string, mtu int) (Device, error) {
	// 从 name 中解析编号（如果有的话）
	ifIndex := -1
	if name != "tun" {
		_, err := fmt.Sscanf(name, "tun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("Interface name must be tun[0-9]*")
		}
	}

	var tunfile *os.File
	var err error

	if ifIndex != -1 {
		// 用户显式指定了编号，直接打开对应 /dev/tunN，
		// 若被占用（EBUSY）则直接失败，不尝试其它编号。
		tunfile, err = os.OpenFile(fmt.Sprintf("/dev/tun%d", ifIndex), unix.O_RDWR|unix.O_CLOEXEC, 0)
	} else {
		// 用户传 "tun"：从 0 到 255 依次尝试打开，跳过 EBUSY 的
		for ifIndex = 0; ifIndex < 256; ifIndex++ {
			tunfile, err = os.OpenFile(fmt.Sprintf("/dev/tun%d", ifIndex), unix.O_RDWR|unix.O_CLOEXEC, 0)
			// 打开成功，或错误不是 EBUSY（例如 ENOENT / EPERM），终止循环
			if err == nil || !errors.Is(err, syscall.EBUSY) {
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}

	// 用已打开的 tunfile 调用 CreateTUNFromFile 完成剩余初始化
	tun, err := CreateTUNFromFile(tunfile, mtu)

	// 如果是自动分配编号模式，写接口名到 WG_TUN_NAME_FILE
	// （便于外部脚本获知实际使用的 tunN）
	if err == nil && name == "tun" {
		fname := os.Getenv("WG_TUN_NAME_FILE")
		if fname != "" {
			os.WriteFile(fname, []byte(tun.(*NativeTun).name+"\n"), 0o400)
		}
	}

	return tun, err
}

// CreateTUNFromFile 从一个已经 open 好的 /dev/tunN 文件对象出发，
// 完成 NativeTun 的通用初始化工作：
//   1. 通过文件 stat 的 Rdev 次设备号得到接口名（tunN）；
//   2. 查询接口 ifindex；
//   3. 创建 AF_ROUTE socket 并启动 routineRouteListener；
//   4. 若当前 MTU != 目标 mtu，则 setMTU。
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
	}

	// 获取接口名（根据 stat 的 Rdev 次设备号推导）
	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	// 查询接口 ifindex
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

	// 创建 AF_ROUTE socket，SOCK_CLOEXEC 在 OpenBSD socket 上直接生效
	tun.routeSocket, err = unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	// 启动事件监听 goroutine
	go tun.routineRouteListener(tunIfindex)

	// 先读取当前 MTU，与目标值不同才执行 setMTU
	// （减少不必要的 ioctl，OpenBSD 上 MTU 默认值通常已为 1500）
	currentMTU, err := tun.MTU()
	if err != nil || currentMTU != mtu {
		err = tun.setMTU(mtu)
		if err != nil {
			tun.Close()
			return nil, err
		}
	}

	return tun, nil
}

// Name 返回 TUN 接口名称（如 "tun3"）。
//
// OpenBSD 上的实现非常简洁：没有 _TUNGIFNAME ioctl，而是直接
// stat() 底层设备文件，从 syscall.Stat_t.Rdev 字段取出设备号。
// Rdev 的低 8 位（Rdev % 256）就是次设备号，恰好对应 tunN 中的 N。
// （OpenBSD tun 驱动约定：次设备号 0 -> tun0, 次设备号 5 -> tun5 等。）
func (tun *NativeTun) Name() (string, error) {
	gostat, err := tun.tunFile.Stat()
	if err != nil {
		tun.name = ""
		return "", err
	}
	stat := gostat.Sys().(*syscall.Stat_t)
	// Rdev 为主次设备号编码，次设备号取模 256。
	tun.name = fmt.Sprintf("tun%d", stat.Rdev%256)
	return tun.name, nil
}

// File 返回底层 TUN 设备文件对象。
func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

// Events 返回只读事件通道。
func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

// Read 从 OpenBSD TUN 设备读取一条 IP 报文。
// 与 darwin/freebsd 完全一致：报文前 4 字节是 [0,0,0,AF] 头。
// 关于 4 字节 AF 头的详细说明见 darwin.go Read 注释。
func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		// offset-4：在 IP 报文前预留 4 字节用于读取 AF 头
		buf := bufs[0][offset-4:]
		n, err := tun.tunFile.Read(buf[:])
		if n < 4 {
			return 0, err
		}
		// sizes[0] 只计 IP 报文部分（丢弃 AF 头的 4 字节）
		sizes[0] = n - 4
		return 1, err
	}
}

// Write 把若干个 IP 报文写入 OpenBSD TUN 设备。
// 每个报文前补上 4 字节 AF 头 [0x00, 0x00, 0x00, AF_INET/AF_INET6]。
// AF 由 IP 报文第一个字节的高 4 位（Version 字段）决定：
//   4 -> AF_INET (2), 6 -> AF_INET6 (0x1c=28 on OpenBSD, 实际用 unix.AF_INET6)
func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		// 填充 4 字节 AF 头
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		// 从 IP 首字节（buf[4]）高 4 位判断版本号
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

// Close 关闭 OpenBSD TUN 设备。
// 流程：
//   1. closeOnce 保证只执行一次；
//   2. 关闭 tunFile（/dev/tunN fd），OpenBSD 关闭 fd 后接口自动消失，
//      无需像 FreeBSD 一样显式 SIOCIFDESTROY；
//   3. 关闭 routeSocket（先 shutdown 唤醒阻塞 Read，再 close）。
func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		if tun.routeSocket != -1 {
			// shutdown 强制让 routeSocket 上阻塞的 Read 立即返回
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err2 = unix.Close(tun.routeSocket)
			tun.routeSocket = -1
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

// setMTU 设置接口 MTU。
// 通过 SIOCSIFMTU ioctl 配合 ifreq_mtu 结构体，
// 以 AF_INET dgram socket 为 ioctl 载体。
func (tun *NativeTun) setMTU(n int) error {
	// open datagram socket
	// 创建临时 AF_INET SOCK_DGRAM socket 承载 ioctl

	var fd int

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call
	// 构造 ifreq_mtu，填接口名和 MTU，调用 SIOCSIFMTU

	var ifr ifreq_mtu
	copy(ifr.Name[:], tun.name)
	ifr.MTU = uint32(n)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s", tun.name)
	}

	return nil
}

// MTU 查询接口当前 MTU，通过 SIOCGIFMTU ioctl 读取。
func (tun *NativeTun) MTU() (int, error) {
	// open datagram socket
	// 以 SOCK_CLOEXEC 打开临时 socket 保证不泄漏 fd 到子进程

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call
	// 填 ifr.Name = 接口名，调用 SIOCGIFMTU，内核回填 MTU 字段
	var ifr ifreq_mtu
	copy(ifr.Name[:], tun.name)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU on %s", tun.name)
	}

	// OpenBSD 内核 MTU 实际为 signed int32，这里转 int32 再转 int 防符号错
	return int(*(*int32)(unsafe.Pointer(&ifr.MTU))), nil
}

// BatchSize 返回 1：OpenBSD TUN 驱动不支持批量收发（没有 sendmmsg/recvmmsg 式语义），
// 每次 Read/Write 只能处理一个报文。
func (tun *NativeTun) BatchSize() int {
	return 1
}
