/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// 以下常量用于 Windows 平台的收发速率调节与自旋等待策略。
// wireguard-go 通过"用户态短暂自旋 + 必要时内核事件等待"的方式在高吞吐场景下减少 syscall 开销。
const (
	// rateMeasurementGranularity 速率统计的时间粒度（单位：纳秒），默认 500ms。
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	// spinloopRateThreshold 启用自旋等待的最低速率阈值：800Mbps / 8 = 每秒 100,000,000 字节。
	spinloopRateThreshold = 800000000 / 8
	// spinloopDuration 单次自旋循环的最长时间（约 12.5 微秒），超过该值仍无数据则进入内核等待。
	spinloopDuration = uint64(time.Millisecond / 80 / time.Nanosecond)
)

// rateJuggler 用于统计 TUN 设备的瞬时吞吐量，并据此决策是否采用"忙等自旋"以减少 syscall 开销。
// 当吞吐较高（>= spinloopRateThreshold）时，Read 线程会用户态自旋一小段时间，避免频繁进入内核等待。
type rateJuggler struct {
	current       atomic.Uint64 // 当前统计窗口的吞吐速率（字节/秒）
	nextByteCount atomic.Uint64 // 下一统计窗口累计传输的字节数
	nextStartTime atomic.Int64  // 下一统计窗口的起始时间（nanotime）
	changing      atomic.Bool   // CAS 锁，避免多个 goroutine 同时更新统计值
}

// NativeTun 是 Windows 平台 TUN 设备的具体实现，
// 基于 wintun 驱动（https://www.wintun.net/）提供的用户态接口操作虚拟网卡。
type NativeTun struct {
	wt        *wintun.Adapter // wintun 虚拟网卡适配器句柄
	name      string          // 接口名称（创建时传入）
	handle    windows.Handle  // 预留的系统句柄，当前未使用，默认置为 InvalidHandle
	rate      rateJuggler     // 吞吐率统计器，用于调节自旋等待策略
	session   wintun.Session  // wintun 会话，管理无锁环形缓冲区，用于用户态和驱动之间交换报文
	readWait  windows.Handle  // 读等待事件句柄：环形缓冲区无数据时，在此事件上阻塞
	events    chan Event      // 设备事件通道（上/下线、MTU 变化等）
	running   sync.WaitGroup  // 记录当前正在进行 Read/Write 的 goroutine 数量，Close 时需等它们全部退出
	closeOnce sync.Once       // 保证 Close 只执行一次的防护
	close     atomic.Bool     // 设备是否已关闭的原子标志
	forcedMTU int             // 强制使用的 MTU 值（Windows 下驱动不会主动上报，使用静态值 1420 或用户指定）
	outSizes  []int           // 预留字段，当前 Windows 实现未使用批量写入
}

var (
	// WintunTunnelType 注册虚拟网卡时使用的隧道类型名称，
	// 对应 Windows 中网络适配器属性里的"InfSectionName"。
	WintunTunnelType = "WireGuard"
	// WintunStaticRequestedGUID 可选：为虚拟网卡指定固定的 NETGUID；默认为空由系统生成。
	WintunStaticRequestedGUID *windows.GUID
)

// procyield 直接调用 Go runtime 内部的处理器让出指令（PAUSE/YIELD），用于用户态轻量级自旋。
//
//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

// nanotime 直接调用 Go runtime 内部的高精度单调时钟（返回纳秒，不随系统时间调整）。
//
//go:linkname nanotime runtime.nanotime
func nanotime() int64

// CreateTUN 以指定名称创建（若已存在则复用）一个 Wintun 虚拟网卡并返回 TUN Device。
// mtu 若 <= 0 则使用默认值 1420。
func CreateTUN(ifname string, mtu int) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, WintunStaticRequestedGUID, mtu)
}

// CreateTUNWithRequestedGUID 与 CreateTUN 功能相同，但额外允许调用者指定虚拟网卡的 NETGUID。
// 若系统中已存在同名且同 TunnelType 的 Wintun 适配器，则直接复用现有适配器。
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int) (Device, error) {
	// 第一步：调用 wintun 创建或打开虚拟网卡适配器
	wt, err := wintun.CreateAdapter(ifname, WintunTunnelType, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %w", err)
	}

	// 第二步：确定 MTU，默认 1420（预留 WireGuard 额外封装空间）
	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	// 第三步：初始化 NativeTun 结构
	tun := &NativeTun{
		wt:        wt,
		name:      ifname,
		handle:    windows.InvalidHandle,
		events:    make(chan Event, 10), // 缓冲 10 个事件，避免短暂生产过快导致丢失
		forcedMTU: forcedMTU,
	}

	// 第四步：启动 wintun 会话，分配 8 MiB 的共享环形缓冲区（驱动 ↔ 用户态）
	tun.session, err = wt.StartSession(0x800000)
	if err != nil {
		// 会话启动失败需回滚：关闭适配器并关闭事件通道
		tun.wt.Close()
		close(tun.events)
		return nil, fmt.Errorf("Error starting session: %w", err)
	}
	// 获取读等待事件句柄，用于 Read 在环形缓冲区为空时阻塞
	tun.readWait = tun.session.ReadWaitEvent()
	return tun, nil
}

// Name 返回虚拟网卡在系统中的名称（即创建时传入的 ifname）。
func (tun *NativeTun) Name() (string, error) {
	return tun.name, nil
}

// File 返回底层文件句柄；Windows 下 Wintun 通过 IOCTL/共享内存而非文件描述符通信，故返回 nil。
func (tun *NativeTun) File() *os.File {
	return nil
}

// Events 返回设备事件通道（只读）。
func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

// Close 关闭 TUN 设备：置关闭标志、唤醒可能阻塞在 Read 上的 goroutine、等待它们退出，
// 然后关闭 wintun 会话和适配器，最后关闭事件通道。
func (tun *NativeTun) Close() error {
	var err error
	tun.closeOnce.Do(func() {
		tun.close.Store(true)          // 原子地标记"已关闭"，后续 Read/Write 立刻返回
		windows.SetEvent(tun.readWait) // 主动触发读等待事件，把阻塞在 Read 里的 goroutine 唤醒以便其退出
		tun.running.Wait()             // 等待所有活跃的 Read/Write 调用返回
		tun.session.End()              // 结束 wintun 会话，释放共享环形缓冲区
		if tun.wt != nil {
			tun.wt.Close() // 关闭 wintun 适配器
		}
		close(tun.events) // 关闭事件通道
	})
	return err
}

// MTU 返回当前使用的 MTU 值（Windows 实现中使用静态 forcedMTU，未实时从系统查询）。
func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// ForceMTU 外部强制更新 MTU，若与旧值不同则通过事件通道发出 EventMTUUpdate。
// TODO: 当前是临时实现，正确做法应该实时监听系统网卡状态变化并自动适配 MTU。
func (tun *NativeTun) ForceMTU(mtu int) {
	if tun.close.Load() {
		return
	}
	update := tun.forcedMTU != mtu
	tun.forcedMTU = mtu
	if update {
		tun.events <- EventMTUUpdate
	}
}

// BatchSize Windows 下 Wintun 当前实现尚未支持批量读写，始终返回 1。
// TODO: 后续可利用 wintun 的多包能力实现批量收发以降低系统调用开销。
func (tun *NativeTun) BatchSize() int {
	return 1
}

// 注意：当前 Read() 和 Write() 假定调用者永远单线程进入；实现内部没有加锁。
// WireGuard 的 device 包本身保证了读写各由一个独立 goroutine 串行调度，因此这里不需要互斥。

// Read 从 Wintun 环形缓冲区读取一个 IP 报文。
// 高吞吐场景下通过用户态短暂自旋减少 WaitForSingleObject 系统调用；否则直接阻塞在内核事件上。
func (tun *NativeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
retry:
	// 先检查是否已关闭，避免在关闭的设备上等待
	if tun.close.Load() {
		return 0, os.ErrClosed
	}
	start := nanotime()
	// 判定当前速率是否足够高，若是则启用"先自旋后等待"的策略以降低延迟
	shouldSpin := tun.rate.current.Load() >= spinloopRateThreshold &&
		uint64(start-tun.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2
	for {
		if tun.close.Load() {
			return 0, os.ErrClosed
		}
		// 从环形缓冲区尝试取出一个收到的报文
		packet, err := tun.session.ReceivePacket()
		switch err {
		case nil:
			// 成功拿到报文 → 拷贝到调用方缓冲，释放 wintun 内部报文，更新速率统计并返回
			n := copy(bufs[0][offset:], packet)
			sizes[0] = n
			tun.session.ReleaseReceivePacket(packet)
			tun.rate.update(uint64(n))
			return 1, nil
		case windows.ERROR_NO_MORE_ITEMS:
			// 环形缓冲当前为空：根据速率决定是继续自旋还是陷入内核等待
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(tun.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1) // 用户态让出 CPU 给同级线程，稍等再重试
			continue
		case windows.ERROR_HANDLE_EOF:
			// 会话已被另一端关闭
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			// 环形缓冲数据结构被破坏，通常是驱动异常
			return 0, errors.New("Send ring corrupt")
		}
		return 0, fmt.Errorf("Read failed: %w", err)
	}
}

// Write 将一批 IP 报文写入 Wintun 发送环形缓冲区，交由驱动发往系统协议栈。
// 当发送环满时（ERROR_BUFFER_OVERFLOW），报文会被主动丢弃（符合非阻塞流量整形语义）。
func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
	if tun.close.Load() {
		return 0, os.ErrClosed
	}

	for i, buf := range bufs {
		packetSize := len(buf) - offset
		tun.rate.update(uint64(packetSize))

		// 从发送环形区分配一个指定大小的槽位
		packet, err := tun.session.AllocateSendPacket(packetSize)
		switch err {
		case nil:
			// TODO: 未来研究通过 Wintun 的 scatter-gather 或零拷贝方式，免除此处 copy
			copy(packet, buf[offset:])
			tun.session.SendPacket(packet)
			continue
		case windows.ERROR_HANDLE_EOF:
			// 会话已关闭，返回已写报文数 + ErrClosed
			return i, os.ErrClosed
		case windows.ERROR_BUFFER_OVERFLOW:
			// 发送环已满，主动丢弃该包并继续下一个，避免阻塞整个写线程
			continue
		default:
			return i, fmt.Errorf("Write failed: %w", err)
		}
	}
	return len(bufs), nil
}

// LUID 返回 Wintun 虚拟网卡在 Windows 系统中的 Locally Unique Identifier，
// 可用于后续通过 Win32 API（如 GetAdaptersAddresses、路由 API）定位该接口。
func (tun *NativeTun) LUID() uint64 {
	tun.running.Add(1)
	defer tun.running.Done()
	if tun.close.Load() {
		return 0
	}
	return tun.wt.LUID()
}

// RunningVersion 返回当前系统实际加载的 Wintun 驱动版本号（四字节打包的主次修订）。
// 可用于打印日志或校验是否满足最低驱动版本要求。
func (tun *NativeTun) RunningVersion() (version uint32, err error) {
	return wintun.RunningVersion()
}

// update 累计一次传输的字节数；当一个统计窗口（rateMeasurementGranularity，默认 500ms）过去后，
// 计算窗口内的平均吞吐速率（字节/秒）并写入 rate.current，供 Read 决策是否启用忙等自旋。
func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := rate.nextByteCount.Add(packetLen)
	period := uint64(now - rate.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		// 通过 CAS 确保只有一个 goroutine 会执行速率计算与重置操作
		if !rate.changing.CompareAndSwap(false, true) {
			return
		}
		rate.nextStartTime.Store(now)
		// 吞吐（字节/秒） = 窗口累计字节数 × 每秒纳秒数 ÷ 窗口长度（纳秒）
		rate.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		rate.nextByteCount.Store(0)
		rate.changing.Store(false)
	}
}
