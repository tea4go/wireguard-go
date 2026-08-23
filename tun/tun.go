/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"os"
)

// Event 表示 TUN 设备上发生的事件类型，按位掩码定义，可组合使用。
type Event int

const (
	// EventUp 表示 TUN 接口已启用（网卡上线）。
	EventUp = 1 << iota
	// EventDown 表示 TUN 接口已禁用（网卡下线）。
	EventDown
	// EventMTUUpdate 表示 TUN 接口的 MTU 值发生了变化。
	EventMTUUpdate
)

// Device 是跨平台 TUN 设备的抽象接口。
// 不同操作系统（Linux/Windows/macOS/BSD 等）各自实现该接口，
// 上层 wireguard 核心逻辑只与此接口交互，无需关心平台细节。
type Device interface {
	// File 返回 TUN 设备底层对应的文件描述符（仅在类 Unix 平台有效，Windows 下通常返回 nil）。
	File() *os.File

	// Read 从 TUN 设备读取一个或多个 IP 报文（不含任何额外帧头，直接是裸 IP 包）。
	//
	// 参数：
	//   bufs   - 用于存放读取到的报文的缓冲区切片，每个元素对应一个报文缓冲区。
	//   sizes  - 输出参数，返回每个实际读到的报文长度，len(sizes) 必须 >= len(bufs)。
	//   offset - 在每个 bufs[i] 中从该偏移位置开始写入数据（用于预留给下层协议处理的头部空间）。
	//
	// 返回值：
	//   n   - 成功读取到的报文个数。
	//   err - 读取错误，例如设备关闭时返回 os.ErrClosed。
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write 向 TUN 设备写入一个或多个 IP 报文（同样不含额外帧头）。
	//
	// 参数：
	//   bufs   - 待发送的报文缓冲区切片。
	//   offset - 在每个 bufs[i] 中从该偏移位置开始读取数据（跳过前面预留的头部）。
	//
	// 返回值：
	//   成功写入的报文个数。
	Write(bufs [][]byte, offset int) (int, error)

	// MTU 返回 TUN 接口当前的最大传输单元（Maximum Transmission Unit），即单个 IP 报文的最大字节数。
	MTU() (int, error)

	// Name 返回 TUN 接口的系统名称（例如 "utun8"、"wgtun5"、"wg0" 等）。
	Name() (string, error)

	// Events 返回一个只读通道，通过该通道可以接收 TUN 设备产生的事件（上下线、MTU 变更等）。
	Events() <-chan Event

	// Close 关闭 TUN 设备，释放所有系统资源，并关闭 Events 通道。
	Close() error

	// BatchSize 返回单次 Read/Write 调用建议/最大可处理的报文数量。
	// 该值在 Device 生命周期内必须保持不变。
	// 某些平台（如 Linux）支持批量收发以减少 syscall 开销，该值会大于 1。
	BatchSize() int
}
