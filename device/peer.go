/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type Peer struct {
	Name              string         // 自定义名称，若设置则在 String() 中优先显示
	isRunning         atomic.Bool    // 运行状态标记，原子操作：true=正在运行，false=已停止
	keypairs          Keypairs       // 密钥对集合（发送/接收密钥，含前向安全轮换）
	handshake         Handshake      // 握手状态机（噪声协议相关：临时密钥、静态密钥等）
	device            *Device        // 所属的 WireGuard 设备指针
	stopping          sync.WaitGroup // 等待所有 goroutine 优雅退出的等待组
	txBytes           atomic.Uint64  // 发送给对端的总字节数（累计统计）
	rxBytes           atomic.Uint64  // 从对端接收的总字节数（累计统计）
	lastHandshakeNano atomic.Int64   // 上次成功握手完成时间（Unix 纳秒时间戳）

	endpoint struct { // 对端网络端点（地址+端口）
		sync.Mutex                   // 保护 val 的并发读写
		val            conn.Endpoint // 当前有效的 UDP 端点（含 IP 和端口）
		clearSrcOnTx   bool          // 下次发包前是否调用 ClearSrc() 清除源地址
		disableRoaming bool          // 是否禁用端点漫游（即不响应 IP 变化）
	}

	timers struct { // 所有定时器集合
		retransmitHandshake     *Timer        // 握手消息重传定时器
		sendKeepalive           *Timer        // Keepalive 发送定时器
		newHandshake            *Timer        // 触发新握手的定时器（超时重协商）
		zeroKeyMaterial         *Timer        // 密钥材料清零定时器（超时后丢弃密钥）
		persistentKeepalive     *Timer        // 持久化 Keepalive 周期定时器（穿透 NAT）
		handshakeAttempts       atomic.Uint32 // 握手尝试次数（达到上限后触发更慢的重传节奏）
		needAnotherKeepalive    atomic.Bool   // 是否需要额外再发一次 Keepalive
		sentLastMinuteHandshake atomic.Bool   // 最近一分钟内是否已发起过握手（避免频繁握手）
	}

	state struct { // 启停状态锁
		sync.Mutex // 防止 Start/Stop 并发执行
	}

	queue struct { // 数据包队列
		staged   chan *QueueOutboundElementsContainer // 暂存队列：握手完成前无法发送的出站包
		outbound *autodrainingOutboundQueue           // 出站队列：按顺序交付 UDP 发送
		inbound  *autodrainingInboundQueue            // 入站队列：按顺序交付 Tun 写入
	}

	cookieGenerator             CookieGenerator // Cookie 生成器（用于 DoS 防护的应答机制）
	trieEntries                 list.List       // AllowedIPs 前缀在路由树中的节点链表（方便按 Peer 批量删除）
	persistentKeepaliveInterval atomic.Uint32   // 持久化 Keepalive 间隔（秒），0 表示禁用
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	peer := new(Peer)

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// map public key
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// init timers
	peer.timersInit()

	// add
	device.peers.keyMap[pk] = peer

	return peer, nil
}

func (peer *Peer) SendBuffers(buffers [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	err := peer.device.net.bind.Send(buffers, endpoint)
	if err == nil {
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

func (peer *Peer) String() string {
	var allowedIPs []string
	peer.device.allowedips.EntriesForPeer(peer,
		func(prefix netip.Prefix) bool {
			ip := prefix.Addr().String()
			cidr := prefix.Bits()
			if prefix.Addr().Is4() {
				parts := strings.Split(ip, ".")
				if len(parts) == 4 {
					ip = parts[2] + "." + parts[3]
				}
			} else {
				parts := strings.Split(ip, ":")
				if n := len(parts); n >= 2 {
					ip = parts[n-2] + ":" + parts[n-1]
				}
			}
			allowedIPs = append(allowedIPs, fmt.Sprintf("%s/%d", ip, cidr))
			return true
		})

	if peer.Name != "" {
		if len(allowedIPs) == 0 {
			return fmt.Sprintf("Peer(%s)", peer.Name)
		}
		return fmt.Sprintf("Peer(%s-%s)", peer.Name, strings.Join(allowedIPs, ","))
	} else {
		src := peer.handshake.remoteStatic
		b64 := func(input byte) byte {
			return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
		}
		b := []byte("Peer(____")
		const first = len("peer(")
		b[first+0] = b64((src[0] >> 2) & 63)
		b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
		b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
		b[first+3] = b64(src[2] & 63)

		if len(allowedIPs) == 0 {
			return fmt.Sprintf("%s)", string(b))
		}
		return fmt.Sprintf("%s-%s)", string(b), strings.Join(allowedIPs, ","))
	}
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Debug("%v - 正在启动", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	// Use the device batch size, not the bind batch size, as the device size is
	// the size of the batch pools.
	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	peer.isRunning.Store(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Notice("%v - 正在停止", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.disableRoaming {
		return
	}
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}
