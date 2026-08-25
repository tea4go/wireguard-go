/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/rwcancel"
	"golang.zx2c4.com/wireguard/tun"
)

// Device 是 WireGuard 设备的核心结构体，代表一个完整的 VPN 隧道设备实例。
// 它封装了虚拟网卡(TUN)、网络绑定(UDP socket)、加密密钥、对等节点管理、
// 消息队列、内存池、速率限制等所有运行时所需的组件。
type Device struct {
	// state 管理设备的运行状态（关闭/启动/停止）及状态转换的同步控制。
	// 所有状态变更操作必须持有 state.mu 互斥锁。
	state struct {
		// state 以原子方式存储设备的当前状态（实际为 deviceState 枚举值）。
		// 使用 device.deviceState() 方法读取该值，该方法不加锁，仅获取快照。
		// 状态转换过程中，state 变量会先于设备实际状态更新，因此它可能代表
		// 当前状态或预期的未来状态（例如调用 Up() 期间 state 会先设为 deviceStateUp）。
		// 注意：不保证预期状态一定会成为实际状态（Up() 可能失败），
		// 且状态在检查与使用之间可能发生多次变化，因此无锁读取仅作参考。
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping 等待组，用于阻塞直至 Device 的所有输入源（如 TUN 读取、网络接收等）均已关闭。
		stopping sync.WaitGroup
		// mu 互斥锁，保护状态变更操作的线程安全。
		sync.Mutex
	}

	// net 管理网络层相关的配置与资源，包括 UDP 套接字绑定、监听端口、防火墙标记等。
	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind          // 底层网络绑定接口，负责 UDP socket 的收发
		netlinkCancel *rwcancel.RWCancel // 用于取消路由变更监听（netlink）
		port          uint16             // UDP 监听端口号
		fwmark        uint32             // 防火墙标记值（0 表示禁用），用于策略路由
		brokenRoaming bool               // 是否存在异常漫游状态标记
	}

	// staticIdentity 存储本设备的静态身份密钥对（私钥与公钥），属于 Noise 协议框架的一部分。
	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey // 本设备私钥，仅在本地使用，绝对不对外传输
		publicKey  NoisePublicKey  // 本设备公钥，用于与对等端进行身份认证
	}

	// peers 管理所有已配置的对等节点（Peer），通过公钥索引快速查找。
	peers struct {
		sync.RWMutex                          // protects keyMap
		keyMap       map[NoisePublicKey]*Peer // 公钥到对等节点实例的映射表
	}

	// rate 提供速率限制与高负载检测功能，用于防御 DoS 攻击。
	rate struct {
		underLoadUntil atomic.Int64            // 高负载状态的截止时间戳（UnixNano）
		limiter        ratelimiter.Ratelimiter // 令牌桶速率限制器
	}

	allowedips    AllowedIPs    // 允许的 IP 路由表，用于根据目的 IP 查找对应的对等节点
	indexTable    IndexTable    // 会话索引表，将 4 字节索引映射到对应的加密会话
	cookieChecker CookieChecker // Cookie 校验器，用于抵御拒绝服务攻击（DoS）

	// pool 管理各类内存对象池，通过复用缓冲区减少 GC 压力，提升性能。
	pool struct {
		inboundElementsContainer  *WaitPool // 入站消息元素容器池
		outboundElementsContainer *WaitPool // 出站消息元素容器池
		messageBuffers            *WaitPool // 消息原始字节缓冲区池
		inboundElements           *WaitPool // 入站队列元素池
		outboundElements          *WaitPool // 出站队列元素池
	}

	// queue 定义三类核心消息队列，分别对应加密、解密和握手处理流程。
	queue struct {
		encryption *outboundQueue  // 出站加密队列：待加密的明文数据包
		decryption *inboundQueue   // 入站解密队列：待解密的加密数据包
		handshake  *handshakeQueue // 握手消息队列：Noise 握手协议相关消息
	}

	// tun 管理虚拟网卡设备及 MTU 配置。
	tun struct {
		device tun.Device   // TUN 虚拟网卡接口，负责与操作系统内核的 IP 层交互
		mtu    atomic.Int32 // 最大传输单元（原子读取），决定单个 IP 数据包的最大字节数
	}

	ipcMutex sync.RWMutex  // IPC（进程间通信）操作的读写锁，防止与设备状态变更竞争
	closed   chan struct{} // 设备关闭信号通道，Close() 时关闭，可被 Wait() 监听
	log      *Logger       // 日志记录器，分级输出调试、信息、警告、错误日志
}

// deviceState 表示 Device 的运行状态枚举。
// 存在三种状态：down（停止）、up（运行中）、closed（已关闭/不可恢复）。
// 合法的状态转换路径：
//
//	down ←→ up
//	  ↓
//	closed
//
// 注意：closed 是终态，一旦进入 closed 无法再转换回其他状态。
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown   deviceState = iota // 停止状态：虚拟网卡与网络套接字均未激活
	deviceStateUp                        // 运行状态：设备正常工作，可以收发数据包
	deviceStateClosed                    // 已关闭状态：设备已销毁，所有资源已释放，不可重新启动
)

// deviceState 以无锁方式原子读取设备当前状态（快照）。
// 返回值是 state.state 字段的 deviceState 类型转换结果。
// 注意：该值仅代表读取时刻的状态快照，状态可能随时变化。
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed 报告设备是否已处于 closed 状态（或正在进入 closed 状态）。
// 参考 state.state 字段的注释了解该值的语义。
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp 报告设备是否已处于 up 状态（或正在尝试进入 up 状态）。
// 参考 state.state 字段的注释了解该值的语义。
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// removePeerLocked 从设备中移除指定的对等节点。
// 调用前置条件：必须已持有 device.peers 写锁。
// 执行操作：
//  1. 从 AllowedIPs 路由表中移除该对等节点的所有 IP，停止其数据包路由
//  2. 调用 peer.Stop() 停止该对等节点的所有后台协程与会话
//  3. 从 peers.keyMap 映射表中删除该公钥对应的条目
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState 尝试将设备状态变更为目标状态 want。
// 该方法是状态机的核心入口，负责：
//   - 状态合法性校验（已 closed 的设备忽略任何变更请求）
//   - 去重处理（目标状态与当前状态相同则直接返回）
//   - 调用 upLocked/downLocked 执行实际的启停操作
//   - 当 Up 失败时，自动回退到 down 状态，保证状态一致性
//
// 参数 want 为目标状态，返回执行过程中发生的错误（如有）。
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()

	old := device.deviceState()
	if old == deviceStateClosed {
		device.log.Info("接口已关闭，忽略请求的状态 %s", want)
		return nil
	}
	switch want {
	case old:
		// 当前状态已是目标状态，无需操作
		return nil
	case deviceStateUp:
		// 先更新状态标记，再执行启动逻辑（即使启动失败也能保证状态反映预期）
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		// 启动失败，自动回退至 down 状态（继续执行下面的 deviceStateDown 分支）
		fallthrough
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		// 优先保留启动时的原始错误；若启动无错但停止出错，则返回停止错误
		if err == nil {
			err = errDown
		}
	}
	device.log.Info("状态 [%s -> %s]，当前为 %s", old, want, device.deviceState())
	return
}

// upLocked 执行设备启动逻辑，报告是否成功。
// 调用前置条件：必须已持有 device.state.mu 互斥锁，且由调用方负责更新 state.state 标记。
// 主要职责：
//  1. 调用 BindUpdate() 重新绑定 UDP 网络套接字到监听端口
//  2. 持有 ipcMutex 写锁，避免与并发的 IPC Set 操作竞争（IPC 创建对等节点后需要 Start）
//  3. 遍历所有已配置的对等节点，调用 Start() 启动其后台协程
//  4. 对于配置了持久保活间隔的节点，立即发送一次保活数据包以激活 NAT 映射
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		return err
	}
	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start()
		// 若配置了持久保活间隔，则立即发送一次保活包以加速隧道建立
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked 执行设备停止逻辑。
// 调用前置条件：必须已持有 device.state.mu 互斥锁，且由调用方负责更新 state.state 标记。
// 主要职责：
//  1. 调用 BindClose() 关闭 UDP 网络套接字，停止接收网络数据包
//  2. 遍历所有对等节点，调用 Stop() 停止其所有后台协程与会话
//
// 返回 BindClose() 执行过程中可能产生的错误。
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("关闭绑定失败, %v", err)
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

// Up 启动设备，使其进入运行状态。
// 这是对外暴露的公开 API，内部委托 changeState() 完成状态机转换。
// 启动成功后设备将开始从 TUN 和 UDP 套接字读取并处理数据包。
func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

// Down 停止设备，使其进入停止状态。
// 这是对外暴露的公开 API，内部委托 changeState() 完成状态机转换。
// 停止后设备将关闭 UDP 套接字并停止所有对等节点的活动，但资源未完全释放，可再次 Up()。
func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

// IsUnderLoad 报告设备当前是否处于高负载状态。
// 高负载判定策略（双重标准）：
//  1. 即时判定：握手队列积压长度达到或超过队列容量的 1/8，则判定为高负载
//  2. 持续判定：若最近一次高负载发生后未超过 UnderLoadAfterTime 时间窗口，仍视为高负载
//
// 该机制用于在高负载下触发更激进的防御策略（如要求客户端提供 Cookie 证明）。
func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	// 握手队列长度达到容量的 1/8 即判定为当前高负载
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		// 更新高负载截止时间，延长高负载状态窗口
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	// 检查是否仍处于最近的高负载时间窗口内
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

// SetPrivateKey 设置本设备的静态私钥，并同步更新相关的加密状态。
// 这是一个重量级操作，会触发以下连锁反应：
//  1. 验证新私钥与当前私钥是否相同，相同则直接返回避免无效操作
//  2. 移除所有远程公钥与新公钥冲突的对等节点（不允许自己连接自己）
//  3. 更新 staticIdentity 中的密钥对，并重新初始化 CookieChecker
//  4. 对所有对等节点重新计算 静态-静态 Diffie-Hellman 预共享密钥
//  5. 使所有对等节点当前的密钥对失效，强制进行新的握手协商
func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	// 密钥未变更，无需执行任何操作
	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	// 预先锁定所有对等节点的握手读锁，防止在密钥变更过程中握手状态被修改
	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys
	// 移除远程公钥等于本地新公钥的对等节点（自连接场景，否则 DH 计算会出问题）

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material
	// 更新本地静态身份密钥材料

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations
	// 对所有对等节点重新计算静态-静态 Diffie-Hellman 预共享密钥（握手计算的核心部分）

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		// 使用新私钥与每个对等节点的公钥计算共享密钥
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	// 释放所有对等节点的握手读锁
	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	// 使所有对等节点当前的传输密钥对失效，强制进行新一轮握手
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

// NewDevice 创建并初始化一个全新的 WireGuard 设备实例。
// 这是构造函数，负责：
//  1. 分配并初始化 Device 结构体的所有字段（状态、队列、映射表、索引表等）
//  2. 从 TUN 设备读取当前 MTU，失败则回退到默认值 DefaultMTU
//  3. 初始化各类内存池对象（PopulatePools）
//  4. 创建加密/解密/握手三类消息队列
//  5. 根据 CPU 核心数启动加密协程、解密协程、握手协程（每个 CPU 各一个）
//  6. 启动 TUN 读取协程和 TUN 事件监听协程
//
// 参数：
//   - tunDevice: 虚拟网卡接口实现（操作系统 TUN 设备的抽象）
//   - bind: 网络绑定接口实现（UDP socket 的抽象）
//   - logger: 日志记录器实例
//
// 返回已初始化且后台协程已启动的 Device 指针。
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown)) // 初始状态为 down
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	// 尝试读取 TUN 设备的 MTU，失败则使用默认值
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Warningf("无法确定 MTU，使用默认值, %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues
	// 初始化三类核心消息队列

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers
	// 启动各类并发处理协程，数量按 CPU 核心数伸缩以充分利用多核

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	// 每个 RoutineHandshake 协程会在结束时调用 encryption.wg.Done()
	device.queue.encryption.wg.Add(cpus) // One for each RoutineHandshake
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1) // 出站加密协程：从 TUN 读取的明文包 -> 加密 -> UDP 发送
		go device.RoutineDecryption(i + 1) // 入站解密协程：从 UDP 读取的密文包 -> 解密 -> TUN 写入
		go device.RoutineHandshake(i + 1)  // 握手处理协程：处理 Noise 协议握手消息
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN: TUN 读取协程
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN 也是加密队列的生产者
	go device.RoutineReadFromTUN()    // 持续从 TUN 设备读取 IP 数据包，推入加密队列
	go device.RoutineTUNEventReader() // 监听 TUN 设备事件（如 MTU 变更）

	return device
}

// BatchSize 返回设备整体的批处理大小（单次批量处理的最大数据包数量）。
// 取网络绑定（bind）和 TUN 设备两者批处理大小的最大值。
// 该值决定了内存池分配的缓冲区数量，在设备整个生命周期内保持不变。
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

// LookupPeer 根据给定的公钥 pk 查找对应的对等节点实例。
// 使用 peers 读锁保护 keyMap 的并发访问。
// 返回找到的 Peer 指针；若未找到则返回 nil。
func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

// RemovePeer 根据指定的公钥 key 从设备中移除对应的对等节点。
// 若该公钥不存在则静默返回。
// 内部会调用 removePeerLocked() 完成实际的清理工作（停止路由、停止协程、从映射表删除）。
func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

// RemoveAllPeers 移除设备中所有已配置的对等节点。
// 遍历 keyMap 中的每个条目逐一调用 removePeerLocked()，
// 最后重新分配一个空的映射表以彻底释放旧 map 引用。
func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

// Close 永久关闭设备，释放所有相关资源。
// 这是不可恢复的操作（终态 closed），关闭后设备无法再通过 Up() 重新启动。
// 执行顺序严格保证资源安全释放：
//  1. 双重锁保护（state 锁 + ipcMutex 锁），确保不与并发操作竞争
//  2. 状态标记为 closed，已关闭则直接返回
//  3. 关闭 TUN 设备（使 TUN 读取协程退出）
//  4. 调用 downLocked() 停止所有对等节点并关闭 UDP 套接字
//  5. 移除所有对等节点（释放资源）
//  6. 关闭所有队列（使各处理协程有序退出）
//  7. 等待所有输入协程（stopping 组）完全退出
//  8. 关闭速率限制器
//  9. 关闭 closed 通道，通知所有 Wait() 监听者
func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if device.isClosed() {
		// 防止重复调用
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Info("正在关闭设备")

	// 关闭 TUN 设备，使 RoutineReadFromTUN 从阻塞读取中返回并退出
	device.tun.device.Close()
	device.downLocked()

	// 移除所有对等节点并释放相关资源
	device.RemoveAllPeers()

	// 递减各队列的 WaitGroup，使处理协程在队列清空后退出
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait() // 阻塞等待所有输入源协程退出完毕

	device.rate.limiter.Close()

	device.log.Info("设备已关闭")
	close(device.closed) // 广播关闭信号，所有 <-device.Wait() 的监听者将被唤醒
}

// Wait 返回一个通道，该通道会在设备完全关闭（Close() 执行完毕）时被关闭。
// 调用方可以通过 `<-device.Wait()` 阻塞等待设备关闭完成。
func (device *Device) Wait() chan struct{} {
	return device.closed
}

// SendKeepalivesToPeersWithCurrentKeypair 向所有拥有当前有效密钥对的对等节点发送保活包。
// 当前有效密钥对的判定标准：
//   - keypairs.current 不为 nil（存在当前传输密钥对）
//   - 该密钥对的创建时间加上 RejectAfterTime（密钥拒绝时间窗口）尚未过期
//
// 该方法用于网络切换等场景下主动唤醒隧道，避免因 NAT 映射超时而丢包。
func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		// 判断当前密钥对是否在有效期内（未超过 RejectAfterTime）
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// HandleNetworkChange 处理底层网络环境发生变化的通知（如切换 Wi-Fi、移动网络等）。
// 执行以下恢复操作：
//  1. 刷新 UDP 套接字绑定（BindUpdate），重新分配端口和 socket
//  2. 对拥有有效密钥对的对等节点发送保活包以快速重建 NAT 映射
//  3. 对没有有效密钥对的对等节点主动发起新的握手，避免等待用户流量触发时才重建连接
//
// 这样可以在网络切换后迅速恢复会话，用户几乎感知不到中断。
func (device *Device) HandleNetworkChange() error {
	if !device.isUp() {
		return nil
	}
	// 重新绑定 UDP 端口（可能因网络切换导致原 socket 失效）
	if err := device.BindUpdate(); err != nil {
		return err
	}

	now := time.Now()
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		// 检查该对等节点是否拥有尚未过期的当前密钥对
		hasCurrentKeypair := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(now)
		peer.keypairs.RUnlock()

		if hasCurrentKeypair {
			// 有有效密钥对：发送保活包即可恢复隧道传输
			peer.SendKeepalive()
			continue
		}
		// 无有效密钥对：主动发起握手 Initiator 消息以建立新会话
		peer.SendHandshakeInitiation(false)
	}
	device.peers.RUnlock()
	return nil
}

// closeBindLocked 关闭设备的网络绑定（net.bind）及相关资源。
// 调用前置条件：必须已持有 device.net 写锁。
// 关闭顺序：
//  1. 取消路由变更监听器（netlinkCancel）
//  2. 调用 bind.Close() 关闭底层 UDP socket
//  3. 等待所有 net 后台协程（RoutineReceiveIncoming）退出
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

// Bind 返回当前设备的网络绑定接口（conn.Bind）。
// 使用 net 读锁保证并发安全。
func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

// BindSetMark 设置 UDP 套接字的防火墙标记（fwmark / SO_MARK）。
// 防火墙标记通常用于配合策略路由（policy routing），使 WireGuard 流量按照特定路由表转发。
// 执行逻辑：
//  1. 标记值未变更则直接返回
//  2. 更新缓存的 fwmark 值
//  3. 若设备处于 up 状态，则立即将标记应用到现有 socket
//  4. 清除所有对等节点缓存的源地址，使其在下一次发送时重新选择源地址
func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	// 标记变更可能导致路由选择变化，清除所有对等节点的源地址缓存以便重新探测
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

// BindUpdate 关闭旧的 UDP socket 并重新打开新的 socket 绑定。
// 这是设备启动或网络切换时的核心网络恢复操作，执行流程：
//  1. 关闭现有 socket（含路由监听），等待接收协程退出
//  2. 若当前设备非 up 状态，直接返回（无需新 socket）
//  3. 调用 bind.Open() 打开新的 UDP socket，获取接收函数列表和监听端口
//  4. 启动路由变更监听器（startRouteListener），监听系统路由表变化
//  5. 应用 fwmark 防火墙标记（如已配置）
//  6. 清除所有对等节点的源地址缓存
//  7. 为每个接收函数启动一个 RoutineReceiveIncoming 协程负责接收网络数据包
//  8. 递增解密和握手队列的 WaitGroup 计数（每个接收协程都是生产者）
func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	// 先关闭现有 socket 和路由监听器，等待所有接收协程退出
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	// 设备未启动，无需打开新 socket
	if !device.isUp() {
		return nil
	}

	// bind to new port
	// 在原有端口上重新打开 socket（若原端口为 0 则由系统分配）
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	// 启动路由变更监听协程，系统路由变化时可自动响应
	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
		netc.port = 0
		return err
	}

	// set fwmark
	// 对新 socket 应用之前配置的防火墙标记
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// clear cached source addresses
	// socket 重建意味着源地址可能变化，清除所有对等节点的源地址缓存
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// start receiving routines
	// 启动每个 ReceiveFunc 对应的接收协程，负责持续从 socket 读取数据包
	device.net.stopping.Add(len(recvFns))
	// 每个接收协程会向解密队列和握手队列写入数据，因此需递增其 WaitGroup
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Info("UDP 绑定已更新为端口 %d", netc.port)
	return nil
}

// BindClose 关闭设备的网络绑定（对外公开 API）。
// 内部以 net 写锁保护 closeBindLocked 的调用。
func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}
