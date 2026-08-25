/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

/* 出站数据处理流水线（每个数据包按此顺序流动）
 *
 * 1. TUN 读取队列        — 从操作系统虚拟网卡批量读取原始 IP 包
 * 2. 路由选择（串行）     — 根据目的 IP 查找 AllowedIPs，确定目标对等节点
 * 3. Nonce 分配（串行）   — 按发送顺序为每个包分配递增的 AEAD nonce，保证全局唯一
 * 4. 加密运算（并行）     — 每个 CPU 核心一个加密协程，对 IP 包执行 ChaCha20-Poly1305 AEAD 加密
 * 5. 网络发送（串行）     — 按原始入队顺序通过 UDP socket 发送（保证对端收到顺序与发送一致）
 *
 * 本文件中的函数（大致）按上述处理顺序排列。
 *
 * 加锁机制、生产者与消费者
 *
 * 每个 Peer 的数据包必须严格保持原有顺序；但加密步骤是并行执行的（可能乱序完成）。
 * 因此设计了以下协调机制：
 *   - 每个批次的元素容器（QueueOutboundElementsContainer）自带 Mutex，初始处于未加锁状态
 *   - 串行消费者（顺序发送器）在从队列取出后会尝试 Lock 该容器，若加密尚未完成则阻塞等待
 *   - 并行加密工作线程在完成一个批次的加密后，调用 Unlock 释放，唤醒串行消费者继续发送
 *   - 元素被放入加密队列时，其 buffer 前会预留足够的空间（MessageTransportHeaderSize）
 *     以便直接在原地构建传输消息头部，避免一次额外的内存拷贝
 */

// QueueOutboundElement 表示一个待发送的出站队列元素。
// 每个元素对应一个 IP 数据包，贯穿整个出站处理流水线：
// TUN 读取 → 路由 → Nonce 分配 → 加密 → 顺序发送 → 回收。
type QueueOutboundElement struct {
	buffer  *[MaxMessageSize]byte // 底层原始消息缓冲区（从 messageBuffers 池借出），包含头部预留空间
	packet  []byte                // 指向 buffer 中实际数据包起始位置的切片（始终是 buffer 的子切片）
	nonce   uint64                // AEAD 加密使用的 nonce（96 位中的低 64 位），必须严格递增不重复
	keypair *Keypair              // 加密该包使用的传输密钥对（含 send AEAD 实例）
	peer    *Peer                 // 该包对应的目标对等节点（路由查找结果）
}

// QueueOutboundElementsContainer 是一批出站元素的容器。
// 每个容器对应一次从 TUN 批量读取中属于同一 Peer 的所有元素，
// 内嵌 Mutex 用于实现「加密并行执行、发送串行保序」的协调机制：
// 工作线程完成该容器所有元素加密后 Unlock，顺序发送协程 Lock 后才允许发送。
type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement // 本批次的所有出站元素
}

// NewOutboundElement 构造一个全新的出站元素。
// 从池中借出 QueueOutboundElement 结构体本身和 MaxMessageSize 字节缓冲区，
// 重置 nonce 为 0；其他引用字段依赖 clearPointers 在归还时清零，此处无需重复设置。
func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers 清空 elem 中所有包含指针的字段。
// 目的：
//   - 减少 GC 扫描压力，避免因对象池保留引用导致其他对象无法被及时回收
//   - 防止 use-after-free 类 bug 的潜在次生破坏（错误地通过悬垂指针访问已被释放的对象）
//   - 复用前确保元素处于干净的「裸状态」
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* 当对等节点没有其他已排队的数据包时，排入一个空的保活包。
 * 保活包长度为 0（加密后仍具 16 字节 Poly1305 标签），用于维持 NAT 端口映射的活跃状态。
 */
func (peer *Peer) SendKeepalive() {
	// 仅在 staged 队列当前为空、且 Peer 处于运行状态时才发送（避免冗余保活）
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Verbosef("%v - 正在发送保活数据包", peer)
		default:
			// staged 队列已满，丢弃本次保活，回收资源
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	// 尝试立即推送已入队的数据包
	peer.SendStagedPackets()
}

// SendHandshakeInitiation 向对等节点发送 Noise IK 握手的「发起方消息」(Initiation)。
// 参数 isRetry 表示是否为重试：首次调用传 false，将尝试计数重置为 0；内部定时器重试时传 true。
// 函数内置两层 check-then-act 保护（读锁 + 写锁），保证在高并发重入场景下 RekeyTimeout 窗口内不会重复发送。
// 发送成功后会启动「握手已发起」定时器（指数退避重试、超时放弃等后续动作由此驱动）。
func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	// 第一层快速检查：读锁判断是否仍在冷却窗口内
	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	// 第二层确认：写锁内再次检查，防止 TOCTOU 竞态
	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Debug("%v - 正在发送握手发起消息", peer)

	// 构造 Initiation 消息载荷（含 Ephemeral、Static、Timestamp、MAC1/MAC2 等字段）
	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - 创建握手发起消息失败, %v", peer, err)
		return err
	}

	// 序列化为线性格式并附加 MAC1/MAC2（DoS 防护校验码）
	packet := make([]byte, MessageInitiationSize)
	_ = msg.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	// 更新与「经过 NAT」和「已发送认证包」相关的定时器
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - 发送握手发起消息失败, %v", peer, err)
	}
	// 启动握手定时器：若在 RekeyAttemptTime 内未收到 Response，将触发重试
	peer.timersHandshakeInitiated()

	return err
}

// SendHandshakeResponse 向发起方回复 Noise IK 握手的「响应方消息」(Response)。
// 这是握手流程的关键节点：成功发送后，本端（响应方）会立即派生传输密钥对，
// 进入可加密收发数据的就绪状态（发起方需等到收到 Response 并验证后才会派生）。
func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Info("%v - 正在发送握手响应消息", peer)

	// 构造 Response 消息（含响应方 Ephemeral、Empty（填充用）、MAC1/MAC2）
	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - 创建握手响应消息失败, %v", peer, err)
		return err
	}

	packet := make([]byte, MessageResponseSize)
	_ = response.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	// 派生传输密钥对（根据双方静态/临时密钥按 Noise IK 流程计算），并挂载到 peer.keypairs.next
	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - 派生密钥对失败, %v", peer, err)
		return err
	}

	// 刷新会话派生、NAT 保活、认证包发送相关定时器
	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - 发送握手响应消息失败, %v", peer, err)
	}
	return err
}

// SendHandshakeCookie 回复 Cookie Reply 消息。
// 当设备处于高负载（IsUnderLoad）时，会拒绝处理 Initiation/Response 消息，
// 改为向发起方回复一个带「负载证明」Cookie 的 Reply，要求发起方后续消息携带该 Cookie。
// 参数 initiatingElem 是触发该回复的原始握手消息（含源端点、sender index 等上下文）。
func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("正在为被拒绝的握手消息向 %v 发送 cookie 响应", initiatingElem.endpoint.DstToString())

	// 提取 Initiation/Response 包中的 Sender Index（4 字节，偏移 4）
	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	// 基于原始握手包 + sender + 端点地址生成带 MAC 签名的 Cookie Reply
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("创建 cookie 回复失败, %v", err)
		return err
	}

	packet := make([]byte, MessageCookieReplySize)
	_ = reply.marshal(packet)
	// TODO: allocation could be avoided
	// 直接通过 bind 发送到触发来源的端点（不走 SendBuffers 流程，Cookie Reply 无需经 Peer 关联）
	device.net.bind.Send([][]byte{packet}, initiatingElem.endpoint)

	return nil
}

// keepKeyFreshSending 在每次发送数据后检查传输密钥对是否需要轮换。
// 触发密钥重协商的两个条件（任一满足即发起）：
//  1. 该密钥对累计发送的数据包数超过 RekeyAfterMessages（约 2^60 包，实际为安全阈值）
//  2. 发起方端的密钥对创建时间超过 RekeyAfterTime（约 120 秒，响应方不主动发起，等待被重握手）
func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

// RoutineReadFromTUN 是「TUN 读取协程」的主循环。
// 职责：
//  1. 从操作系统 TUN 设备批量读取 IP 包
//  2. 按 IP 版本（v4/v6）从目的地址字段查 AllowedIPs，确定目标 Peer
//  3. 按 Peer 分组，逐个送入对应 Peer 的 staged 队列
//  4. 触发 SendStagedPackets 推进后续加密/发送流程
//  5. 遇到不可恢复的 TUN 读取错误时，触发整个 Device 的 Close
//
// 该协程也是加密队列的生产者（退出时调用 encryption.wg.Done），是设备状态组的成员。
func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("例程：TUN 读取器 - 已停止")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("例程：TUN 读取器 - 已启动")

	var (
		batchSize   = device.BatchSize()                                         // 单次批量读取的最大包数，与 bind/tun 较大者一致
		readErr     error                                                        // 最近一次 Read 的错误
		elems       = make([]*QueueOutboundElement, batchSize)                   // 预分配的元素槽（每个槽对应一个读入缓冲区）
		bufs        = make([][]byte, batchSize)                                  // 传给 TUN Read 的缓冲区切片
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize) // 按 Peer 分组的暂存映射
		count       = 0                                                          // 本次 Read 实际读入的包数
		sizes       = make([]int, batchSize)                                     // 每个包的实际字节数
		offset      = MessageTransportHeaderSize                                 // 在 buffer 中预留的传输消息头部长度（IP 包从这里开始）
	)

	// 一次性初始化所有读取槽，后续循环中按消耗补充（用完一个立刻补齐一个）
	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	// 协程退出前回收所有尚未被消费的元素与缓冲区
	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// read packets
		// 批量从 TUN 读取；每个包写入 bufs[i] 的 offset 起始位置，尺寸存于 sizes[i]
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			// packet 指向实际 IP 包的起始位置（跳过传输头预留空间）
			elem.packet = bufs[i][offset : offset+sizes[i]]

			// lookup peer
			// 根据 IP 版本从目的地址查路由
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
				peer = device.allowedips.Lookup(dst)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
				peer = device.allowedips.Lookup(dst)

			default:
				device.log.Warningf("收到 IP 版本未知的数据包")
			}

			// 路由未命中则直接丢弃（WireGuard 不做默认路由行为）
			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				// 首次遇到该 Peer，申请一个容器承载其本批次的元素
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			// 该槽已被消费，立即补齐新的空元素与新的 buf 引用，下次 Read 可复用
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		// 将分组后的批次送入对应 Peer 的 staged 队列并尝试推进发送
		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				// Peer 已停止，批量回收资源
				for _, elem := range elemsForPeer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// UDP GSO/GRO 场景下分段数过多属于可恢复错误，仅记录警告继续循环
				device.log.Warningf("多分段读取时丢弃了部分数据包, %v", readErr)
				continue
			}
			if !device.isClosed() {
				// 除了「设备已关闭」的正常错误（os.ErrClosed）外，都打印错误日志
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("从 TUN 设备读取数据包失败, %v", readErr)
				}
				// 触发整个设备的优雅关闭（TUN 层错误视为致命）
				go device.Close()
			}
			return
		}
	}
}

// StagePackets 将一个批次的出站元素送入 Peer 的 staged 队列。
// staged 是有界缓冲 channel；若队列已满则主动丢弃队列中最旧的一批数据包（队头），
// 为新批次腾出空间——这是 WireGuard 的主动丢包策略，避免积压过久的过期包占用窗口。
// 丢包后继续尝试入队，直到成功将本批次送入为止。
func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		// 队列满，丢弃最旧的一批，为新批次腾出空间
		select {
		case tooOld := <-peer.queue.staged:
			for _, elem := range tooOld.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

// SendStagedPackets 尝试从 staged 队列取出批次、分配 nonce，并分别送入：
//   - peer.queue.outbound.c  （顺序发送器的输入）
//   - device.queue.encryption.c （并行加密工作线程的输入）
//
// 这是「串行分配 nonce + 并行加密 + 串行发送」流水线的调度核心。
// 特殊处理：若当前批次的某些元素在分配 nonce 时已超过 RejectAfterMessages 安全阈值，
// 会被收集到一个「超容容器」中单独重新入队（这些包需要等重握手新密钥对生效后再发送）。
func (peer *Peer) SendStagedPackets() {
top:
	// 队列为空或设备未 up，直接返回
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	// 取当前主用密钥对；若不存在或已超过发送条数/时间上限，先发起重握手
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer // 超容（超出 nonce 上限）容器
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0 // 有效元素数量计数器（剔除超容元素后）
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				// 原子自增 nonce 并获取分配到的值（Add 返回加后值，因此减 1）
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					// 将 nonce 钉死在上限，防止后续继续分配溢出；本元素进入超容队列等待重握手
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					// 正常元素按紧凑顺序放回原切片前部
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			// 容器加锁：顺序发送协程取出时将再次 Lock，从而阻塞直到加密完成
			elemsContainer.Lock()
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				// 将超容元素重新入队（它们将在下一轮循环中等待新密钥对）
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				// 本容器没有有效元素，直接回收并跳到顶端检查是否还有批次
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			// 同时投递到两个队列：
			//   encryption.c → 加密工作线程（并行，谁先完成不一定）
			//   outbound.c   → 顺序发送器（严格按入队顺序取出，但会等加密 Lock 完成）
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					peer.device.PutMessageBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				// 有超容元素需要等待新密钥对，回到顶部重新处理
				goto top
			}
		default:
			return
		}
	}
}

// FlushStagedPackets 清空 Peer 的 staged 队列，将其中所有元素与容器归还到对象池。
// 通常在 Peer 停止（Stop）时调用，以避免内存泄漏。
func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			for _, elem := range elemsContainer.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

// calculatePaddingSize 计算在给定 MTU 下需要附加的填充字节数，使加密后的数据部分长度为 PaddingMultiple（16）的倍数。
// WireGuard 填充的目的：通过模糊数据包真实长度，降低基于包长的流量分析攻击面。
// 算法：
//   - 若 MTU = 0，直接把 packetSize 向上取整到 16 的倍数
//   - 否则以 packetSize 对 MTU 取模后的值作为「最后一单元」大小，同样向上取整，但不得超过 MTU
func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* 加密队列中的元素，由该函数并行完成 AEAD 加密运算，
 * 并通过释放容器的 Mutex 标记该批次已可被顺序消费者（发送器）取出。
 *
 * 备注：每个 CPU 核心独立运行一个该协程实例，实现多核并行加密。
 */
func (device *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte     // 预分配的零字节数组，用于一次性追加填充
	var nonce [chacha20poly1305.NonceSize]byte // ChaCha20-Poly1305 的 96-bit nonce 空间

	defer device.log.Verbosef("例程：加密工作线程 %3d - 已停止", id)
	device.log.Verbosef("例程：加密工作线程 %3d - 已启动", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// populate header fields
			// 直接在 buffer 的头部预留空间中构造传输消息头部（避免后续拷贝）
			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)         // 4 字节消息类型：传输数据
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex) // 4 字节接收方索引（对端 localIndex）
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)                  // 8 字节窗口 nonce（仅用低 64 位）

			// pad content to multiple of 16
			// 数据部分末尾追加零填充至 16 字节的倍数，防止基于包长的侧信道分析
			paddingSize := calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

			// encrypt content and release to consumer
			// 将 nonce 放入大端偏移 4..12 的位置（符合 WireGuard 规范：4 字节零 + 8 字节实际 nonce）
			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			// Seal 直接将密文写到 header 后面（dst=header 作为头部前缀），形成完整的「头部+密文+标签」
			elem.packet = elem.keypair.send.Seal(
				header,      // dst：密文会追加到 header 之后
				nonce[:],    // 96-bit nonce
				elem.packet, // plaintext：原始 IP 包 + 填充
				nil,         // 无附加认证数据（AAD）
			)
		}
		// 释放容器锁：顺序发送协程 Lock 时会解除阻塞，表示本批次加密完成
		elemsContainer.Unlock()
	}
}

// RoutineSequentialSender 是每个 Peer 的「顺序发送协程」。
// 严格按 peer.queue.outbound.c 的入队顺序取出批次，并在发送前通过 elemsContainer.Lock()
// 等待该批次加密完成。因此即使加密工作线程以任意顺序完成，
// 最终的 UDP 发送顺序仍与从 TUN 读取的顺序一致，避免对端乱序接收。
// 发送完成后根据数据发送状态刷新各类定时器（keepalive / key 轮换 / NAT 保活等）。
func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - 例程：顺序发送器 - 已停止", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - 例程：顺序发送器 - 已启动", peer)

	bufs := make([][]byte, 0, maxBatchSize) // 批次发送的切片缓冲，容量取自单次最大批大小

	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			// 收到 nil 哨兵元素表示通道关闭，协程正常退出
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			// Peer 已停止，跳过发送直接回收资源
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}
		dataSent := false // 本批次是否包含实际数据（非 keepalive 空包）
		// 等待加密完成：若该批次仍在被加密线程持有，此处 Lock 会阻塞
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)
		}

		// 更新：经过 NAT 与 认证包发送 相关的定时器
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs)
		if dataSent {
			// 本批次有真实数据，刷新「数据发送」定时器（启动 keepalive 倒计时）
			peer.timersDataSent()
		}
		// 回收每个元素与容器
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		device.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			// 若底层是因为「UDP GSO 被禁用」而失败，降级为非 GSO 重试错误并保留
			if errors.As(err, &errGSO) {
				device.log.Warningf("发送数据包时发生错误, %v", err)
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - 发送数据包失败, %v", peer, err)
			continue
		}

		// 每批发送成功后，检查密钥对是否需要重轮换
		peer.keepKeyFreshSending()
	}
}
