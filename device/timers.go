/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * 本文件基于内核实现中的 timers.c 进行了大量改造。
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// Timer 管理 WireGuard 协议中与时间相关的各项功能。
// Timer 大致复制了 Linux 内核中 struct timer_list 的接口定义。
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex // 修改状态时的读写锁，保护 isPending 字段
	runningLock   sync.Mutex   // 运行时锁，确保回调函数串行执行
	isPending     bool         // 标记定时器是否处于待触发状态
}

// NewTimer 为指定的 Peer 创建一个新的定时器。
// expirationFunction 为定时器到期时执行的回调函数。
func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	// 使用 time.AfterFunc 创建定时器，初始设置为 1 小时（不会立即触发）
	timer.Timer = time.AfterFunc(time.Hour, func() {
		// 获取运行锁，确保回调函数不会并发执行
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		// 获取修改锁，检查定时器是否仍然处于待触发状态
		timer.modifyingLock.Lock()
		if !timer.isPending {
			// 如果已被取消，直接返回不执行回调
			timer.modifyingLock.Unlock()
			return
		}
		// 标记定时器不再处于待触发状态
		timer.isPending = false
		timer.modifyingLock.Unlock()

		// 执行到期回调函数
		expirationFunction(peer)
	})
	// 立即停止定时器，等待后续 Mod 调用重新设置触发时间
	timer.Stop()
	return timer
}

// Mod 修改定时器的到期时间，将其重置为指定的持续时间后触发。
func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true // 标记为待触发
	timer.Reset(d)         // 重置定时器倒计时
	timer.modifyingLock.Unlock()
}

// Del 删除（停止）定时器，使其不再触发。
func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false // 标记为非待触发
	timer.Stop()            // 停止底层 Go 定时器
	timer.modifyingLock.Unlock()
}

// DelSync 同步删除定时器，等待当前正在执行的回调函数完成后再停止。
// 此方法确保在返回时，定时器的回调函数已经完全执行完毕。
func (timer *Timer) DelSync() {
	timer.Del()                // 先停止定时器，防止新的触发
	timer.runningLock.Lock()   // 获取运行锁，等待当前回调执行完毕
	timer.Del()                // 再次确认停止（双重保险）
	timer.runningLock.Unlock() // 释放运行锁
}

// IsPending 检查定时器当前是否处于待触发状态。
func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

// timersActive 检查当前 Peer 的定时器是否应该处于活动状态。
// 当且仅当 Peer 正在运行、关联了 device 且 device 处于启动状态时，定时器才活动。
func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

// expiredRetransmitHandshake 握手重传定时器到期回调。
// 当握手发起后长时间未收到响应时触发，用于重试或放弃握手。
func expiredRetransmitHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() > MaxTimerHandshakes {
		// 握手尝试次数超过上限，放弃握手
		peer.device.log.Warningf("%s - 经过 %d 次尝试后握手仍未完成，放弃连接", peer, MaxTimerHandshakes+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* 如果长时间尝试握手均失败，则丢弃所有没有密钥对的数据包，并不再重试。 */
		peer.FlushStagedPackets()

		/* 设置一个定时器，用于销毁部分交换过程中可能残留的任何密钥材料。 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
		}
	} else {
		// 未超过重试次数，继续重试握手
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Debug("%s - 经过 %d 秒后握手仍未完成，正在重试（第 %d 次尝试）", peer, int(RekeyTimeout.Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* 清除端点源地址，以防该地址是导致握手失败的原因。 */
		peer.markEndpointSrcForClearing()

		// 重新发送握手发起消息（true 表示重传）
		peer.SendHandshakeInitiation(true)
	}
}

// expiredSendKeepalive 发送 Keepalive 定时器到期回调。
// 当接收数据后超过 KeepaliveTimeout 未发送数据时触发。
func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive() // 发送一个 Keepalive 空数据包
	if peer.timers.needAnotherKeepalive.Load() {
		// 如果在本定时器待触发期间又收到了新数据，则需要再安排一次 Keepalive
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

// expiredNewHandshake 新建握手定时器到期回调。
// 当发送数据后超过 (KeepaliveTimeout + RekeyTimeout) 未收到任何响应时触发。
func expiredNewHandshake(peer *Peer) {
	peer.device.log.Debug("%s - 发送隧道数据后在 %d 秒内未收到新的对端认证响应，正在尝试重新握手", peer, int((KeepaliveTimeout + RekeyTimeout).Seconds()))
	/* 清除端点源地址，以防该地址是导致通信失败的原因。 */
	peer.markEndpointSrcForClearing()
	// 发送新的握手发起消息（false 表示非重传，触发新一轮密钥交换）
	peer.SendHandshakeInitiation(false)
}

// expiredZeroKeyMaterial 密钥清零定时器到期回调。
// 当会话密钥超过 RejectAfterTime * 3 仍未更新时触发，清除所有密钥材料。
func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Warningf("%s - 由于在 %d 秒内未收到新密钥，正在清除所有密钥", peer, int((RejectAfterTime * 3).Seconds()))
	peer.ZeroAndFlushAll() // 清零密钥并清空所有待发送数据包
}

// expiredPersistentKeepalive 持久化 Keepalive 定时器到期回调。
// 当配置了持久化 Keepalive 间隔时，定期发送 Keepalive 数据包。
func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		// 仅当配置了非零间隔时才发送 Keepalive
		peer.SendKeepalive()
	}
}

/* 在发送经过认证的数据包后调用。 */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		// 发送数据后，安排新建握手定时器，加入随机抖动避免同步
		peer.timers.newHandshake.Mod(KeepaliveTimeout + RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* 在收到经过认证的数据包后调用。 */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			// sendKeepalive 未挂起，直接设置定时器
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			// sendKeepalive 已挂起，标记需要再发送一次 Keepalive
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* 在发送任何类型的认证数据包（Keepalive、数据或握手）后调用。 */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		// 既然已经发送了数据包，就不再需要 sendKeepalive 定时器了
		peer.timers.sendKeepalive.Del()
	}
}

/* 在收到任何类型的认证数据包（Keepalive、数据或握手）后调用。 */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		// 既然收到了对端响应，就不再需要新建握手定时器了
		peer.timers.newHandshake.Del()
	}
}

/* 在发送握手发起消息后调用。 */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		// 握手已发起，设置重传定时器，加入随机抖动
		peer.timers.retransmitHandshake.Mod(RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* 在收到并处理握手响应消息后，或通过第一个数据消息获得密钥确认时调用。 */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		// 握手完成，取消握手重传定时器
		peer.timers.retransmitHandshake.Del()
	}
	// 重置握手尝试计数和相关标志
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	// 记录最后一次握手成功的时间戳（纳秒精度）
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
	peer.device.log.Notice("%v - 握手已完成，会话已建立", peer)
}

/* 在创建临时密钥后调用——发送握手响应之前或收到握手响应之后。 */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		// 会话已派生，设置密钥过期定时器（3 倍 RejectAfterTime 后清除密钥）
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}
}

/* 在发送认证数据包（Keepalive、数据或握手）之前，或在收到此类数据包之后调用。 */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		// 配置了持久化 Keepalive，重置其定时器
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}

// timersInit 初始化 Peer 关联的所有定时器，为每个定时器绑定对应的到期回调函数。
func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake) // 握手重传定时器
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)             // Keepalive 发送定时器
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)               // 新建握手定时器
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)         // 密钥清零定时器
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive) // 持久化 Keepalive 定时器
}

// timersStart 启动/重置与定时器相关的计数器和标志位。
func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)           // 握手尝试次数清零
	peer.timers.sentLastMinuteHandshake.Store(false) // 最后一分钟握手标志复位
	peer.timers.needAnotherKeepalive.Store(false)    // 需要额外 Keepalive 标志复位
}

// timersStop 同步停止所有定时器，确保所有定时器回调都已完全执行完毕。
func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync() // 停止握手重传定时器
	peer.timers.sendKeepalive.DelSync()       // 停止 Keepalive 发送定时器
	peer.timers.newHandshake.DelSync()        // 停止新建握手定时器
	peer.timers.zeroKeyMaterial.DelSync()     // 停止密钥清零定时器
	peer.timers.persistentKeepalive.DelSync() // 停止持久化 Keepalive 定时器
}
