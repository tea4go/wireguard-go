/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/replay"
)

/* 由于 Go 语言及 /x/crypto 库的当前限制，暂时无法安全地从内存中
 * 彻底擦除密钥材料（敏感数据在 GC 后可能残留在页面中）。
 *
 * 这一缺陷可能影响前向保密性（Forward Secrecy），
 * 一旦 Go 运行时提供可靠的内存清零原语，将在此处立即修复。
 */

// Keypair 表示一次 Noise 握手成功后协商生成的**传输密钥对**。
// 每个 Keypair 仅属于单向会话的两个对等节点之一：
//   - send    用于本端加密出站数据包
//   - receive 用于本端解密入站数据包
//
// 密钥对具有严格的生命周期，超过 RejectAfterTime（约 2880 秒）
// 后将被主动丢弃，以实现 WireGuard 前向保密性的承诺。
type Keypair struct {
	sendNonce    atomic.Uint64 // 发送计数器（ChaCha20 nonce），必须原子自增，严禁重复
	send         cipher.AEAD   // 出站加密器：用对端公钥协商出的对称密钥 AEAD 实例
	receive      cipher.AEAD   // 入站解密器：用本端私钥协商出的对称密钥 AEAD 实例
	replayFilter replay.Filter // 重放攻击防护过滤器，基于滑动窗口记录已接收过的 nonce
	isInitiator  bool          // 本端在此次握手中是否为发起方（Initiator），用于区分密钥方向
	created      time.Time     // 该密钥对的创建时间，用于判定是否过期（超过 RejectAfterTime 被拒绝）
	localIndex   uint32        // 本端会话索引（4 字节），出现在 Data 包头部 Receiver Index 字段
	remoteIndex  uint32        // 对端会话索引（4 字节），出现在本端发出 Data 包的 Receiver Index 字段
}

// Keypairs 维护某一对等节点在任意时刻可能生效的三组传输密钥对：
//   - current  当前主用密钥对：绝大多数数据包使用其加解密
//   - previous 上一代密钥对：仅用于接收一小段时间窗口内的延迟/乱序数据包（不允许再用其加密发送）
//   - next     下一代密钥对：原子指针，正在进行的新握手产生的新密钥对，Ready 后切换为 current
//
// 三槽滑动设计确保在重新握手期间不会丢包，支持平滑的密钥轮换。
type Keypairs struct {
	sync.RWMutex
	current  *Keypair                // 当前主用传输密钥对
	previous *Keypair                // 上一代传输密钥对（仅用于接收）
	next     atomic.Pointer[Keypair] // 下一代即将生效的密钥对（原子指针，支持无锁预加载）
}

// Current 以读锁方式返回当前主用的 Keypair 指针快照。
// 注意：返回的仅是调用时刻的快照，调用后 current 可能在并发下被替换。
func (kp *Keypairs) Current() *Keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}

// DeleteKeypair 从全局索引表中删除指定密钥对对应的本地会话索引。
// 调用后，携带该 localIndex 的入站 Data 包将无法再查找到对应密钥对，从而被丢弃。
// 一般在密钥对过期、对等节点移除或设备关闭时调用。
func (device *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		device.indexTable.Delete(key.localIndex)
	}
}
