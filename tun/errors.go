package tun

import (
	"errors"
)

var (
	// ErrTooManySegments 表示在从 TUN 设备读取数据时，收到的数据包分片数量过多，
	// 超出了调用方提供的缓冲区数组（vec）所能容纳的长度上限。
	//
	// 【产生场景】
	// 当操作系统向 TUN 设备递交一个经过 GRO（Generic Receive Offload）或
	// LRO（Large Receive Offload）合并的超大数据包时，内核会将其拆分为多个
	// 连续的内存段（segments/scatter-gather entries）。如果段的总数超过了
	// Device.Read() 方法调用者传入的缓冲区切片长度，就会返回此错误。
	//
	// 【处理建议】
	// 这是一个非致命性错误（non-fatal error），不应该导致 TUN 设备的读取循环终止。
	// 遇到此错误时，调用方通常的处理方式是：
	//   - 丢弃本次无法完整容纳的数据包（数据已部分写入缓冲区，但不完整）
	//   - 继续下一次 Read() 调用
	//   - 如频繁触发，可考虑增大传入的缓冲区数组容量
	ErrTooManySegments = errors.New("too many segments")
)
