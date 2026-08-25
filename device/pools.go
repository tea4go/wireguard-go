/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
)

// WaitPool 是一个带有**并发数量上限**的同步对象池。
// 它在 Go 标准库 sync.Pool 的基础上扩展了以下能力：
//   - 控制同时借出的对象总数（max），当达到上限时新的 Get() 调用会阻塞等待
//   - 通过 condition variable 实现高效的等待-唤醒机制，而不是自旋轮询
//   - 归还对象时递减计数并唤醒一个正在等待的 Get() 协程
//
// WireGuard 使用该池限制消息缓冲区和队列元素的峰值内存占用，
// 防止在高并发场景下无限制分配导致 GC 抖动或 OOM。
type WaitPool struct {
	pool  sync.Pool  // 底层对象池，复用已归还的对象以减少分配开销
	cond  sync.Cond  // 条件变量，用于阻塞等待对象归还的协程
	lock  sync.Mutex // 保护 count 字段的互斥锁，同时作为 cond 的 L
	count uint32     // 已借出且尚未归还的对象数量（Get 次数 - Put 次数）
	max   uint32     // 最大并发借出数量；0 表示不限制
}

// NewWaitPool 创建并初始化一个 WaitPool。
// 参数 max 为最大并发借出对象数（0 表示不限制）；
// 参数 new 为对象构造函数，当池中没有可复用对象时会调用它分配新实例。
func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	// cond 需要绑定其内部使用的互斥锁（必须和保护 count 的锁一致）
	p.cond = sync.Cond{L: &p.lock}
	return p
}

// Get 从对象池借出一个对象。
// 当 max > 0 且已借出数量达到 max 时，调用方会阻塞，直到其他协程归还对象。
// 注意：每次成功 Get() 后，调用方必须在使用完毕后调用对应的 Put()，否则会造成永久阻塞。
func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		// 使用 for 循环而非 if，防止被虚假唤醒（spurious wakeup）后条件仍不满足
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	// 从 sync.Pool 获取一个对象（可能是复用的旧对象，也可能是调用 New 构造的新对象）
	return p.pool.Get()
}

// Put 将对象归还到对象池中。
// 若 max > 0，归还时会递减借出计数，并唤醒一个被阻塞在 Get() 上的协程。
// 为避免悬垂引用，调用 Put 前通常应手动清空对象中的引用字段（由上层负责）。
func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	// 唤醒一个正在 Get 中等待的协程（若有）
	p.cond.Signal()
}

// PopulatePools 一次性初始化 Device 的五类内存池。
// 每个池的最大并发借出量统一为 PreallocatedBuffersPerPool，
// 构造函数会根据当前设备 BatchSize() 动态分配容器容量，
// 以确保内存分配大小与实际批处理需求匹配，避免浪费。
func (device *Device) PopulatePools() {
	// 入站元素容器池：承载一批次（BatchSize 个）QueueInboundElement 指针的切片容器
	device.pool.inboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	// 出站元素容器池：承载一批次 QueueOutboundElement 指针的切片容器
	device.pool.outboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	// 原始消息缓冲区池：存放一个完整 WireGuard 消息（最大 MaxMessageSize 字节）的字节数组
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	// 入站单元素池：单个入站队列元素（QueueInboundElement）
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	// 出站单元素池：单个出站队列元素（QueueOutboundElement）
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

// GetInboundElementsContainer 从池中获取一个入站元素容器。
// 返回时会重置容器的 Mutex（池化对象可能保留了旧锁状态），避免继承脏状态。
func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	// 重置互斥锁（从池中取出的对象可能带有上一次使用遗留的锁状态）
	c.Mutex = sync.Mutex{}
	return c
}

// PutInboundElementsContainer 归还入站元素容器到池中。
// 归还前先将切片中的所有元素指针置 nil（避免引用已被单独归还的元素导致悬垂），
// 然后将切片长度裁剪为 0（保留底层数组容量，下次取出可直接复用分配好的后备数组）。
func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	// 清空元素指针，防止 GC 时因这些指针存活而无法回收其引用的对象
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0] // 保留 cap，仅重置 len
	device.pool.inboundElementsContainer.Put(c)
}

// GetOutboundElementsContainer 从池中获取一个出站元素容器。
// 与入站版本对称，返回时重置 Mutex 以清除潜在的脏锁状态。
func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	c.Mutex = sync.Mutex{}
	return c
}

// PutOutboundElementsContainer 归还出站元素容器到池中。
// 对称于入站版本：先清空所有元素指针，再裁剪切片长度。
func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

// GetMessageBuffer 从池中获取一个原始消息字节缓冲区（MaxMessageSize 字节）。
// 用于 UDP 收发、Noise 消息构造等需要承载一个完整 WireGuard 消息的场景。
func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

// PutMessageBuffer 归还原始消息缓冲区到池中。
// 注意：缓冲区内容不会被主动清零，调用方若在归还前写入了敏感数据，应自行清零。
func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

// GetInboundElement 从池中获取一个入站队列元素。
// 入站元素用于承载从 UDP/TUN 读取后，经过解密、路由，送入消费阶段的数据包元信息。
func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

// PutInboundElement 归还入站队列元素到池中。
// 归还前调用 clearPointers() 清空元素内部的引用字段（buffer、packet、peer 等），
// 防止悬垂引用导致内存泄漏或复用时读到脏数据。
func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

// GetOutboundElement 从池中获取一个出站队列元素。
// 出站元素用于承载从 TUN/UDP 读取后，经过加密、排队，送入发送阶段的数据包元信息。
func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

// PutOutboundElement 归还出站队列元素到池中。
// 对称于入站版本：先调用 clearPointers() 清理所有引用字段，再归还到池。
func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
