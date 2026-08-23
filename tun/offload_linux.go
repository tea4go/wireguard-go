/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// tcpFlagsOffset 是 TCP 头部中 flags 字段相对于 TCP 头部起始位置的字节偏移量。
// TCP 头部结构：
//
//	0-3:   源端口(2) + 目的端口(2)
//	4-7:   序列号(4)
//	8-11:  确认号(4)
//	12:    数据偏移(4位) + 保留位(4位)
//	13:    TCP flags
const tcpFlagsOffset = 13

// TCP flags 常量定义，对应 TCP 头部第 13 字节的各个比特位。
// 这些标志位用于控制 TCP 连接的状态转移和数据传输行为。
const (
	tcpFlagFIN uint8 = 0x01 // FIN: Finish，结束连接标志，位 0（0b00000001）
	tcpFlagPSH uint8 = 0x08 // PSH: Push，推送标志，要求接收方立即将数据交给应用层，位 3（0b00001000）
	tcpFlagACK uint8 = 0x10 // ACK: Acknowledgment，确认标志，表示确认号字段有效，位 4（0b00010000）
)

// virtioNetHdr 对应 Linux 内核中 include/uapi/linux/virtio_net.h 定义的
// struct virtio_net_hdr（内核符号名 virtio_net_hdr）。
// 这是 TUN/TAP 设备使用 virtio-net 协议时，每个数据包前面附加的元数据头。
// 当 TUN 设备启用 IFF_VNET_HDR 标志时，每次 read/write 都需要携带这个头部。
//
// 字段内核语义详解：
//
//	flags:
//	  VIRTIO_NET_HDR_F_NEEDS_CSUM(1) = 表示传输层 checksum 未完成计算，
//	  只包含了伪首部的校验和（CHECKSUM_PARTIAL），接收方/内核需要完成剩余计算。
//	  0 表示 checksum 已完整计算。
//
//	gsoType:
//	  表示该数据包的 GSO（Generic Segmentation Offload，发送侧大包分段）类型。
//	  常见值：
//	    VIRTIO_NET_HDR_GSO_NONE(0)    = 无 GSO，普通单包
//	    VIRTIO_NET_HDR_GSO_TCPV4(1)   = IPv4 TCP GSO 大包
//	    VIRTIO_NET_HDR_GSO_UDP(3)     = UDP GSO（旧）
//	    VIRTIO_NET_HDR_GSO_TCPV6(4)   = IPv6 TCP GSO 大包
//	    VIRTIO_NET_HDR_GSO_UDP_L4(5)  = UDP GSO（新，L4 全量 checksum）
//	  当 GRO（Generic Receive Offload，接收侧包合并）完成合并后，
//	  此字段会被设置为对应类型，表示该包是一个需要由内核/网卡再分段的超级包。
//
//	hdrLen:
//	  GSO 数据包的 L2+L3+L4 头部总长度（字节）。
//	  在 gsoSplit 拆分 GSO 大包时，每个分段都会复用这个长度之前的头部模板。
//	  简单理解：从报文开头到传输层 payload 开始之前的字节数。
//
//	gsoSize:
//	  GSO 拆分时，除最后一段外，每个分段的传输层 payload 大小（字节）。
//	  换句话说，拆分后每个分段的 TCP/UDP payload 最大是 gsoSize 字节。
//	  GRO 合并时，该字段记录合并后 GSO 分段的标准 MSS 大小。
//
//	csumStart:
//	  从报文开头到需要进行 checksum 计算的起始位置（即传输层头部开始位置）。
//	  对于 CHECKSUM_PARTIAL 来说，内核会从 csumStart 开始计算 checksum。
//	  通常 csumStart = IP 头部长度（iphLen）。
//
//	csumOffset:
//	  从 csumStart 算起，到 checksum 字段存放位置的字节偏移。
//	    - TCP: TCP 头部 checksum 字段位于 TCP 头部第 16-17 字节，故 csumOffset=16
//	    - UDP: UDP 头部 checksum 字段位于 UDP 头部第 6-7 字节，故 csumOffset=6
//	  内核最终会在 csumStart + csumOffset 的位置写入完整 checksum。
type virtioNetHdr struct {
	flags      uint8  // virtio_net_hdr.flags，标志位（如 NEEDS_CSUM）
	gsoType    uint8  // virtio_net_hdr.gso_type，GSO 类型（TCP/UDP/IPv4/IPv6/无）
	hdrLen     uint16 // virtio_net_hdr.hdr_len，头部总长度（网络层+传输层头）
	gsoSize    uint16 // virtio_net_hdr.gso_size，每个分段最大传输层 payload 大小
	csumStart  uint16 // virtio_net_hdr.csum_start，checksum 计算起始偏移（传输层头起点）
	csumOffset uint16 // virtio_net_hdr.csum_offset，checksum 字段相对 csumStart 的偏移
}

// decode 将字节切片 b 中的前 virtioNetHdrLen 字节解码到 v 结构体中。
// 使用 unsafe.Pointer 直接做内存拷贝，保证与 C 语言的 struct virtio_net_hdr 二进制兼容。
// 要求 b 的长度至少为 virtioNetHdrLen，否则返回 io.ErrShortBuffer。
func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	// unsafe.Slice 将指针转换为切片，然后 copy 从 b 拷贝到结构体内存
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

// encode 将 v 结构体编码到字节切片 b 的前 virtioNetHdrLen 字节中。
// 与 decode 对称，使用 unsafe.Pointer 做内存拷贝以确保 C ABI 兼容。
// 要求 b 的长度至少为 virtioNetHdrLen，否则返回 io.ErrShortBuffer。
func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

const (
	// virtioNetHdrLen 是 virtioNetHdr 结构体的字节长度。
	// 使用 unsafe.Sizeof 计算，与 C ABI 中 sizeof(struct virtio_net_hdr) 保持一致。
	// 在当前字段布局下为 10 字节（1+1+2+2+2+2）。
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
)

// tcpFlowKey 是 TCP 流的唯一标识键。
// GRO 合并时，只有同一个流（即五元组相同 + ACK 号相同）的包才可能被合并。
// 其中 ACK 号也被纳入键中，因为 ACK 号变化（如对端发送的确认变化）意味着
// 这些包在语义上不属于同一批，合并后可能导致协议行为异常。
type tcpFlowKey struct {
	srcAddr, dstAddr [16]byte // 源/目的 IP 地址；IPv4 使用前 4 字节，IPv6 使用全部 16 字节
	srcPort, dstPort uint16   // 源/目的 TCP 端口（网络字节序提取）
	rxAck            uint32   // TCP 头部中的 ACK 确认号（接收方向的 ACK）；不同 ACK 不合并，视为不同流
	isV6             bool     // 是否为 IPv6 流（同时也决定了地址字段取前 4 还是 16 字节）
}

// tcpGROTable 是 TCP GRO（接收侧合并）的核心哈希表结构。
// 它以 tcpFlowKey 为键，将同一个 TCP 流的多个待合并包组织起来。
// 同时使用内存池（itemsPool）来减少反复分配 [][]tcpGROItem 切片造成的 GC 压力。
type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem // 流键 -> 该流所有待合并包的记账信息切片
	itemsPool   [][]tcpGROItem              // 空闲的 []tcpGROItem 切片内存池，循环复用
}

// newTCPGROTable 构造并初始化一个 TCP GRO 表。
// 预分配 conn.IdealBatchSize 个条目，对应一个批量读循环的理想包数量，
// 使 map 和内存池都能充分复用，避免频繁扩容。
func newTCPGROTable() *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]tcpGROItem, conn.IdealBatchSize),
	}
	// 预先分配每个池中的切片容量为 conn.IdealBatchSize，后续 append 无需扩容
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, conn.IdealBatchSize)
	}
	return t
}

// newTCPFlowKey 根据一个 IPv4/IPv6 TCP 报文 pkt 的字节内容，
// 提取出对应的 tcpFlowKey。
// 参数：
//
//	srcAddrOffset:  IP 头部中源地址字段的起始偏移（IPv4=12，IPv6=8）
//	dstAddrOffset:  IP 头部中目的地址字段的起始偏移（IPv4=16，IPv6=24）
//	tcphOffset:     TCP 头部起始偏移（= IP 头部长度）
//
// 通过 dstAddrOffset - srcAddrOffset 得出地址长度，区分 IPv4(4) 和 IPv6(16)。
func newTCPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset int) tcpFlowKey {
	key := tcpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	// 拷贝源/目的 IP 地址到键的 16 字节数组中（IPv4 只用前 4 字节，剩余保持零）
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	// TCP 端口：源端口占前 2 字节，目的端口占接下来 2 字节
	key.srcPort = binary.BigEndian.Uint16(pkt[tcphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[tcphOffset+2:])
	// ACK 号在 TCP 头部偏移 8-11 字节
	key.rxAck = binary.BigEndian.Uint32(pkt[tcphOffset+8:])
	// 地址大小为 16 字节即为 IPv6
	key.isV6 = addrSize == 16
	return key
}

// lookupOrInsert 尝试在表中查找与给定报文匹配的 TCP 流。
// 若找到对应流，返回该流的 []tcpGROItem 和 true。
// 若未找到，调用 insert 将新报文插入表中，返回 nil 和 false。
// 返回值的第二个 bool 表示「是否已有该流」。
// 注意：当前实现中 insert 内部会再次做一次 map 查找，存在可优化空间（TODO 注释已注明）。
func (t *tcpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	t.insert(pkt, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert 将一个新的 TCP 报文作为新的 GRO 条目插入到对应流的 items 列表中。
// 若该流尚不存在，会先从 itemsPool 里取一个空切片（避免新分配）作为该流的容器。
// 提取的元数据包括：序列号、bufs 索引、payload 大小（gsoSize）、IP/TCP 头长度、PSH 标志。
func (t *tcpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, tcphOffset, tcphLen, bufsIndex int) {
	key := newTCPFlowKey(pkt, srcAddrOffset, dstAddrOffset, tcphOffset)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),                              // 原始 bufs 切片中的索引，用于定位报文数据
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),          // 该报文 TCP payload 的字节长度
		iphLen:    uint8(tcphOffset),                              // IP 头部长度（= TCP 头在报文中的起始偏移）
		tcphLen:   uint8(tcphLen),                                 // TCP 头部长度（含 TCP options）
		sentSeq:   binary.BigEndian.Uint32(pkt[tcphOffset+4:]),    // TCP 序列号（本报文首字节数据的 seq）
		pshSet:    pkt[tcphOffset+tcpFlagsOffset]&tcpFlagPSH != 0, // 该报文 TCP 头是否设置了 PSH 标志
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		// 该流首次出现，从内存池中拿一个空闲的 []tcpGROItem 切片
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

// updateAt 用新的 item 覆盖键 item.key 对应流中第 i 个条目。
// 在 TCP 合并成功后，需要更新原条目的 numMerged/gsoSize/pshSet/sentSeq 等字段时调用。
func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items, _ := t.itemsByFlow[item.key]
	items[i] = item
}

// deleteAt 删除键 key 对应流中第 i 个条目。
// 典型场景：某个已存在的条目的 checksum 校验失败，说明该包不能参与合并，
// 也不能作为后续合并的基础，必须从表中移除。
func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items, _ := t.itemsByFlow[key]
	// 将 i 之后的元素前移覆盖，实现原地删除
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

// tcpGROItem 是单个 TCP 报文在 GRO 过程中的记账信息。
// 它不保存完整的报文内容（报文本身存放在外部的 bufs 切片中），
// 而是保存定位报文、判断可否合并、写回合并结果所需的元数据。
type tcpGROItem struct {
	key       tcpFlowKey // 该报文所属的流键，用于反向索引回 table
	sentSeq   uint32     // 该报文第一个 TCP payload 字节对应的序列号（即 TCP 头中的 seq 字段）
	bufsIndex uint16     // 报文数据在外部 bufs [][]byte 中的索引；bufs[bufsIndex] 就是这个包的数据
	numMerged uint16     // 已经成功合并到该条目的报文数量（0 表示未合并，独立的包）
	gsoSize   uint16     // 该条目作为 GSO 分段时，每段 TCP payload 的大小（MSS 等价物）
	iphLen    uint8      // IP 头部长度（字节），用于快速定位 TCP 头
	tcphLen   uint8      // TCP 头部长度（字节，含 options），用于快速定位 TCP payload
	pshSet    bool       // 该条目的 TCP 头（或合并后尾部）是否设置了 PSH 标志；PSH 只能在合并链的最后一个包上
}

// newItems 从内存池中取出一个空闲的 []tcpGROItem 切片。
// 采用栈式分配：每次从 itemsPool 末尾弹出一个切片。
// 对应归还操作在 reset() 中执行（将清空的切片放回池尾部）。
func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

// reset 清空整个 TCP GRO 表，将所有流的 []tcpGROItem 切片归还给内存池。
// 每次批量 handleGRO 处理完一批 bufs 之后都应当调用 reset，
// 保证下一轮批量处理时状态干净，同时内存池不断循环复用。
func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		// 只清空长度（保留已分配的底层数组容量）
		items = items[:0]
		// 归还给内存池尾部
		t.itemsPool = append(t.itemsPool, items)
		// 从 map 中移除该流键
		delete(t.itemsByFlow, k)
	}
}

// udpFlowKey 是 UDP 流的唯一标识键。
// 与 tcpFlowKey 相比，UDP 没有 ACK 号，因此只需要四元组（src/dst addr + src/dst port）。
type udpFlowKey struct {
	srcAddr, dstAddr [16]byte // 源/目的 IP 地址；IPv4 使用前 4 字节，IPv6 使用全部 16 字节
	srcPort, dstPort uint16   // 源/目的 UDP 端口
	isV6             bool     // 是否为 IPv6 流
}

// udpGROTable 是 UDP GRO（接收侧合并）的核心哈希表结构。
// 结构、内存池策略与 tcpGROTable 完全相同，只是条目类型换成 udpGROItem，键换成 udpFlowKey。
type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem // 流键 -> 该流所有待合并包的记账信息切片
	itemsPool   [][]udpGROItem              // 空闲的 []udpGROItem 切片内存池，循环复用
}

// newUDPGROTable 构造并初始化一个 UDP GRO 表，预分配 conn.IdealBatchSize 个条目。
func newUDPGROTable() *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, conn.IdealBatchSize),
		itemsPool:   make([][]udpGROItem, conn.IdealBatchSize),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, conn.IdealBatchSize)
	}
	return u
}

// newUDPFlowKey 从一个 IPv4/IPv6 UDP 报文中提取出 udpFlowKey。
// 参数含义与 newTCPFlowKey 相同，tcphOffset 替换为 udphOffset（UDP 头部起始偏移 = IP 头部长度）。
func newUDPFlowKey(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset int) udpFlowKey {
	key := udpFlowKey{}
	addrSize := dstAddrOffset - srcAddrOffset
	copy(key.srcAddr[:], pkt[srcAddrOffset:dstAddrOffset])
	copy(key.dstAddr[:], pkt[dstAddrOffset:dstAddrOffset+addrSize])
	// UDP 头部前 4 字节依次为：源端口(2) + 目的端口(2)
	key.srcPort = binary.BigEndian.Uint16(pkt[udphOffset:])
	key.dstPort = binary.BigEndian.Uint16(pkt[udphOffset+2:])
	key.isV6 = addrSize == 16
	return key
}

// lookupOrInsert 对 UDP 表执行与 TCP 表同名方法相同的逻辑。
// 找到流 -> 返回 items + true；未找到 -> insert + 返回 nil + false。
func (u *udpGROTable) lookupOrInsert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	u.insert(pkt, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex, false)
	return nil, false
}

// insert 将一个新的 UDP 报文作为新的 GRO 条目插入对应流中。
// 参数 cSumKnownInvalid 表示该报文的 UDP checksum 是否已知为非法（例如上一次合并校验时已确认失败），
// 这样下次该条目作为合并目标时，可跳过 checksum 验证直接走失败分支，避免重复计算。
func (u *udpGROTable) insert(pkt []byte, srcAddrOffset, dstAddrOffset, udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	key := newUDPFlowKey(pkt, srcAddrOffset, dstAddrOffset, udphOffset)
	item := udpGROItem{
		key:              key,
		bufsIndex:        uint16(bufsIndex),                     // 报文在 bufs 中的索引
		gsoSize:          uint16(len(pkt[udphOffset+udphLen:])), // UDP payload 长度（= 报文总长度 - IP头 - UDP头）
		iphLen:           uint8(udphOffset),                     // IP 头部长度（= UDP头起始偏移）
		cSumKnownInvalid: cSumKnownInvalid,                      // UDP 校验和是否已知无效（false 仅表示未知，不代表合法）
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

// updateAt 用新的 item 覆盖键 item.key 对应流中第 i 个条目（UDP 版）。
func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items, _ := u.itemsByFlow[item.key]
	items[i] = item
}

// udpGROItem 是单个 UDP 报文在 GRO 过程中的记账信息。
type udpGROItem struct {
	key              udpFlowKey // 所属流键
	bufsIndex        uint16     // 报文数据在外部 bufs [][]byte 中的索引
	numMerged        uint16     // 已合并的报文数（0 表示未合并）
	gsoSize          uint16     // 该条目作为 GSO 分段时，每段 UDP payload 的大小
	iphLen           uint8      // IP 头部长度（字节），用于快速定位 UDP 头
	cSumKnownInvalid bool       // UDP 校验和是否已知无效；为 false 时仅表示状态未知，不表示校验和一定正确
}

// newItems 从 UDP 内存池中取出一个空闲的 []udpGROItem 切片（与 TCP 版相同，栈式弹出）。
func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

// reset 清空整个 UDP GRO 表，并将所有切片归还内存池（与 TCP 版相同）。
func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, k)
	}
}

// canCoalesce 表示「两个包是否可以合并」以及「合并方向」的三态枚举。
// 因为当两个 TCP 包在序列号上相邻时，新包可能在老包之后（append），
// 也可能乱序出现在老包之前（prepend），需要区分处理。
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1 // 可合并，新包应当作为头部，拼接到已有条目前面
	coalesceUnavailable canCoalesce = 0  // 不可合并（五元组不同/序号不相邻/PSH 限制等）
	coalesceAppend      canCoalesce = 1  // 可合并，新包应当作为尾部，拼接到已有条目后面
)

// ipHeadersCanCoalesce 检查两个报文 pktA 和 pktB 的 IP 头部字段是否满足 GRO 合并条件。
// 对于 IPv4：要求 ToS（服务类型）、DF 位+保留位、TTL（生存时间）三者完全一致。
//
//	（MF 更多分片位不在此检查，由上层调用者处理）
//
// 对于 IPv6：要求 TC（Traffic Class 流量类别）、Hop Limit（跳数限制）完全一致。
// 这些字段不一致的包合并后会破坏协议语义（例如 TTL 不同代表经过了不同路径），
// 所以必须严格一致才允许合并。
func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	// 先保证至少有 9 字节（刚好覆盖 IPv4 ToS/TTL/Flags 或 IPv6 TC/HopLimit 的读取）
	if len(pktA) < 9 || len(pktB) < 9 {
		return false
	}
	if pktA[0]>>4 == 6 {
		// IPv6：版本号=6
		// 字节 0（高 4 位=版本，低 4 位=TC 高 4 位）+ 字节 1（高 4 位=TC 低 4 位）
		// => TC = ((pkt[0] & 0x0F) << 4) | (pkt[1] >> 4)
		// 这里同时要求版本号相同（pktA[0]==pktB[0]）和 TC 的高/低 4 位分别一致
		if pktA[0] != pktB[0] || pktA[1]>>4 != pktB[1]>>4 {
			// cannot coalesce with unequal Traffic class values
			return false
		}
		// IPv6 字节 7 = Hop Limit（跳数限制）
		if pktA[7] != pktB[7] {
			// cannot coalesce with unequal Hop limit values
			return false
		}
	} else {
		// IPv4：版本号=4
		// IPv4 字节 1 = Type of Service（服务类型 + ECN）
		if pktA[1] != pktB[1] {
			// cannot coalesce with unequal ToS values
			return false
		}
		// IPv4 字节 6 = Flags(高3位) + Fragment Offset 高5位
		// 字节 6 高 3 位中：bit2=DF(Don't Fragment)，bit1=保留位，bit0=MF(More Fragments)
		// 这里 pktA[6]>>5 取最高三位，要求 DF 和保留位一致。
		// MF（更多分片）位在上层已过滤分片包，所以这里不严格要求。
		if pktA[6]>>5 != pktB[6]>>5 {
			// cannot coalesce with unequal DF or reserved bits. MF is checked
			// further up the stack.
			return false
		}
		// IPv4 字节 8 = TTL（Time To Live，生存时间）
		if pktA[8] != pktB[8] {
			// cannot coalesce with unequal TTL values
			return false
		}
	}
	return true
}

// udpPacketsCanCoalesce 判断待合并 UDP 报文 pkt 是否可以 append 到已有条目 item 之后。
// （UDP 由于无序号概念，只支持 append 方向，不支持 prepend，以避免包重排）
// 参数：
//
//	pkt:       新到的待合并 UDP 报文（完整的 IP + UDP + payload）
//	iphLen:    新报文 IP 头长度
//	gsoSize:   新报文 UDP payload 长度
//	item:      该流已存在的最后一个 GRO 条目
//	bufs:      外部报文缓冲区切片（定位 item 对应的原始报文）
//	bufsOffset:bufs 中每个元素的实际报文数据起始偏移（= virtioNetHdrLen 大小）
func udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16, item udpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	// 定位到已有条目对应的完整报文（跳过 virtioNetHdr 前缀）
	pktTarget := bufs[item.bufsIndex][bufsOffset:]

	// 先检查 IP 头部的 ToS/TTL/DF 等是否可合并
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	// 已有条目合并后累计的 payload 必须是 gsoSize 的整数倍。
	// 否则说明最后已经有一个比 gsoSize 小的收尾包，后面不能再接任何包（否则 MSS 含义被破坏）。
	if len(pktTarget[iphLen+udphLen:])%int(item.gsoSize) != 0 {
		// A smaller than gsoSize packet has been appended previously.
		// Nothing can come after a smaller packet on the end.
		return coalesceUnavailable
	}
	// 要求非递增：新包的 payload 不能比已有的 gsoSize 大。
	// 合并后的 gsoSize 取最大的那一个（作为拆分的 MSS），如果出现递增，
	// 意味着之前的包 payload 更小，会出现 "大包-小包-大包" 的结构，无法用统一 gsoSize 拆分。
	if gsoSize > item.gsoSize {
		// We cannot have a larger packet following a smaller one.
		return coalesceUnavailable
	}
	// UDP 由于没有序列号，只能按到达顺序 append，不支持 prepend。
	return coalesceAppend
}

// tcpPacketsCanCoalesce 判断 TCP 报文 pkt 与已有条目 item 是否可以合并，并返回合并方向。
// 合并条件参考内核 GRO 自测（tools/testing/selftests/net/gro.c）的行为。
// 参数：
//
//	pkt:       新到的 TCP 报文（完整的 IP + TCP + payload）
//	iphLen:    新报文 IP 头长度
//	tcphLen:   新报文 TCP 头长度（含 options）
//	seq:       新报文第一个 payload 字节的 TCP 序列号
//	pshSet:    新报文是否设置 PSH 标志
//	gsoSize:   新报文 TCP payload 长度
//	item:      已存在的 TCP GRO 条目
//	bufs:      外部报文缓冲区切片
//	bufsOffset:每个 buf 的有效数据起始偏移（= virtioNetHdrLen）
func tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8, seq uint32, pshSet bool, gsoSize uint16, item tcpGROItem, bufs [][]byte, bufsOffset int) canCoalesce {
	pktTarget := bufs[item.bufsIndex][bufsOffset:]

	// 条件1：TCP 头长度必须相等。如果一个带 TCP options 一个不带，不能合并。
	if tcphLen != item.tcphLen {
		// cannot coalesce with unequal tcp options len
		return coalesceUnavailable
	}
	// 条件2：TCP options 的具体内容必须完全一致。
	// TCP 基础头长 20 字节，超过的部分就是 options。
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen], pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			// cannot coalesce with unequal tcp options
			return coalesceUnavailable
		}
	}
	// 条件3：IP 头部字段 ToS/TTL/DF 等必须可合并。
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}

	// 条件4：TCP 序列号相邻。
	// 先计算 item 所代表报文（含已合并的）最后一个 payload 字节之后的下一序号。
	// lhsLen = 单次 gsoSize + 已合并包数 * gsoSize = (numMerged+1) * gsoSize，
	// 即当前合并后的 TCP payload 总长度。
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize

	if seq == item.sentSeq+uint32(lhsLen) {
		// 分支 A：append - 新包正好接在已合并数据的尾部之后
		if item.pshSet {
			// PSH 只能在合并链的最后一个包上；已有条目已带 PSH，说明它是尾包，不能再 append。
			// We cannot append to a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		// 已有 payload 必须是 gsoSize 的整数倍（最后不能有比 gsoSize 小的残留段）
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			// A smaller than gsoSize packet has been appended previously.
			// Nothing can come after a smaller packet on the end.
			return coalesceUnavailable
		}
		// 新包 payload 不能比现有 gsoSize 更大（保持「gsoSize 非递增」约束）
		if gsoSize > item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq {
		// 分支 B：prepend - 新包正好接在已合并数据的前面（乱序到达）
		if pshSet {
			// 若新包本身带 PSH，它无法作为被 prepend 的头段（因为 PSH 只允许在尾段）
			// We cannot prepend with a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		// prepend 要求：新包的 payload >= 现有 gsoSize（否则出现前面小、后面大，违反非递增语义）
		if gsoSize < item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		// 如果之前有过合并（numMerged>0），且新包 gsoSize 更大，则不允许 prepend。
		// 因为 prepend 后新 gsoSize 会变大，但之前已经合并了较小的段，
		// 会导致拆分后的分段大小不均等（先有若干小包，再有大包），不符合 gsoSize 的定义。
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			// There's at least one previous merge, and we're larger than all
			// previous. This would put multiple smaller packets on the end.
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

// checksumValid 验证传输层（TCP/UDP）报文的 checksum 是否正确。
// 计算方法：构造 IP 伪首部 -> 计算伪首部的一补和 -> 将伪首部和与传输层头+payload 做一补和累加
//
//	-> 最终取反，若结果为 0 则校验通过。
//
// 参数：
//
//	pkt:    完整的 IP + 传输层 + payload
//	iphLen: IP 头长度（字节）
//	proto:  传输层协议号（unix.IPPROTO_TCP 或 unix.IPPROTO_UDP）
//	isV6:   是否为 IPv6
func checksumValid(pkt []byte, iphLen, proto uint8, isV6 bool) bool {
	srcAddrAt := ipv4SrcAddrOffset
	addrSize := 4
	if isV6 {
		srcAddrAt = ipv6SrcAddrOffset
		addrSize = 16
	}
	// 伪首部中用到的「L4 总长度」= 整个报文长度 - IP 头长度
	lenForPseudo := uint16(len(pkt) - int(iphLen))
	// 第一步：计算伪首部的一补和（不累加到 16 位，保留 64 位累加值）
	cSum := pseudoHeaderChecksumNoFold(proto, pkt[srcAddrAt:srcAddrAt+addrSize], pkt[srcAddrAt+addrSize:srcAddrAt+addrSize*2], lenForPseudo)
	// 第二步：将伪首部和与传输层头+payload 的一补和合并，并最终取反。
	// 取反后等于 0 表示 checksum 正确。
	return ^checksum(pkt[iphLen:], cSum) == 0
}

// coalesceResult 表示「尝试合并两个 UDP 或 TCP 包」的详细结果枚举。
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota // 0：目标 buffer 底层数组容量不足，无法 append，拒绝合并（避免分配新内存）
	coalescePSHEnding                             // 1：PSH 标志冲突导致无法合并（仅 TCP prepend 分支触发）
	coalesceItemInvalidCSum                       // 2：已有合并目标（item）的 checksum 非法
	coalescePktInvalidCSum                        // 3：新待合并包（pkt）的 checksum 非法
	coalesceSuccess                               // 4：合并成功
)

// coalesceUDPPackets 尝试将新的 UDP 报文 pkt append 合并到已存在的 item 条目上。
// 与 TCP 版不同，UDP 只支持 append（防止包重排）。
// 合并成功后，item 的报文 buffer（bufs[item.bufsIndex]）会被扩展并追加 pkt 的 payload。
//
// 工作流程：
//  1. 估算合并后的总长度，检查底层数组容量是否足够；不足则直接返回（不扩容）。
//  2. 如果是首次合并（numMerged==0），先校验已有 item 的 checksum 是否有效。
//  3. 校验新 pkt 的 checksum 是否有效。
//  4. 将 pkt 的 payload 部分（跳过 IP 头和 UDP 头）拷贝到 item 报文 buffer 的末尾。
//  5. item.numMerged++，标记合并次数。
func coalesceUDPPackets(pkt []byte, item *udpGROItem, bufs [][]byte, bufsOffset int, isV6 bool) coalesceResult {
	pktHead := bufs[item.bufsIndex][bufsOffset:] // 已合并条目对应的完整报文（含 IP 头+UDP 头）
	headersLen := item.iphLen + udphLen          // 本次合并需要剥离的头部长度（IP头+UDP头）
	// 合并后，item 对应 buffer 的新总长度 = 原报文长度 + 新报文 payload 长度（不含双头部）
	coalescedLen := len(bufs[item.bufsIndex][bufsOffset:]) + len(pkt) - int(headersLen)

	// 容量检查：底层数组的总容量（cap()）减去偏移后必须能容纳新报文，
	// 否则 append 会触发 Go 运行时重新分配底层数组——为了极致性能，这里宁愿放弃合并。
	if cap(pktHead)-bufsOffset < coalescedLen {
		// We don't want to allocate a new underlying array if capacity is
		// too small.
		return coalesceInsufficientCap
	}
	// 若该条目尚未合并过任何包，它自身的 checksum 还没校验过；为避免把坏包合并进去，这里先校验一次。
	if item.numMerged == 0 {
		if item.cSumKnownInvalid || !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_UDP, isV6) {
			return coalesceItemInvalidCSum
		}
	}
	// 校验新来的 pkt 的 UDP checksum
	if !checksumValid(pkt, item.iphLen, unix.IPPROTO_UDP, isV6) {
		return coalescePktInvalidCSum
	}
	// 计算需要新增多少字节（即 pkt 的 UDP payload 长度）
	extendBy := len(pkt) - int(headersLen)
	// 将 bufs[item.bufsIndex] 切片扩展 extendBy 字节（注意操作的是含 virtioNetHdr 前缀的完整 buf）
	bufs[item.bufsIndex] = append(bufs[item.bufsIndex], make([]byte, extendBy)...)
	// 把 pkt 的 payload 拷贝到扩展后的尾部；起点 = bufsOffset + 原报文长度
	copy(bufs[item.bufsIndex][bufsOffset+len(pktHead):], pkt[headersLen:])

	item.numMerged++
	return coalesceSuccess
}

// coalesceTCPPackets 尝试将新的 TCP 报文 pkt 与已有条目 item 合并。
// 参数 mode 指定 append 或 prepend。
// 对于 prepend 模式，由于外部已记录了 item.bufsIndex 为最终输出索引，
// 合并后必须交换 bufs[item.bufsIndex] 和 bufs[pktBuffsIndex]，保持最终输出的索引不变。
//
// 工作流程：
//  1. 根据合并模式确定「最终位于头部的报文」pktHead。
//  2. 容量检查 + checksum 验证（首次合并时需验证 item，两种模式都要验证 pkt）。
//  3. append 模式：把 pkt payload 追加到 item 报文尾部；若 pkt 带 PSH，则同时设置合并后的 PSH。
//  4. prepend 模式：把 item 的 payload 拼接到 pkt 报文尾部，随后交换两个 buf 在 bufs 中的位置。
//  5. 更新 item.gsoSize（取更大的）和 item.numMerged。
func coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int, gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, bufs [][]byte, bufsOffset int, isV6 bool) coalesceResult {
	var pktHead []byte                       // 最终合并结果中，位于最前面的那部分报文数据（含完整 IP+TCP 头）
	headersLen := item.iphLen + item.tcphLen // 需要剥离的 IP+TCP 头总长度
	// 合并后「头部报文」所在 buf 的总长度
	coalescedLen := len(bufs[item.bufsIndex][bufsOffset:]) + len(pkt) - int(headersLen)

	// Copy data
	if mode == coalescePrepend {
		// ============ prepend 分支：新包在前，已有条目在后 ============
		pktHead = pkt
		// 容量检查：新包所在 buffer 必须有足够剩余空间
		if cap(pkt)-bufsOffset < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		// PSH 只能在尾部；若作为头部的新包自身带 PSH，显然违规（prepend 前 tcpPacketsCanCoalesce 已检查，这里是双保险）
		if pshSet {
			return coalescePSHEnding
		}
		// 首次合并时校验已有 item 的 checksum
		if item.numMerged == 0 {
			if !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		// 校验新包 pkt 的 checksum
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		// 合并后首字节的 seq 就是新包的 seq
		item.sentSeq = seq
		// 需要在 pkt 后面追加多少字节 = 总目标长度 - 新包原长度
		extendBy := coalescedLen - len(pktHead)
		bufs[pktBuffsIndex] = append(bufs[pktBuffsIndex], make([]byte, extendBy)...)
		// 把 item 的 payload（跳过 IP+TCP 头）拷贝到新扩展的尾部
		copy(bufs[pktBuffsIndex][bufsOffset+len(pkt):], bufs[item.bufsIndex][bufsOffset+int(headersLen):])
		// 关键：交换两个 buffer 在 bufs 中的位置，确保最终输出索引仍是 item.bufsIndex
		// Flip the slice headers in bufs as part of prepend. The index of item
		// is already being tracked for writing.
		bufs[item.bufsIndex], bufs[pktBuffsIndex] = bufs[pktBuffsIndex], bufs[item.bufsIndex]
	} else {
		// ============ append 分支：已有条目在前，新包在后 ============
		pktHead = bufs[item.bufsIndex][bufsOffset:]
		// 容量检查：item 所在 buffer 必须有足够剩余空间
		if cap(pktHead)-bufsOffset < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		// 首次合并时校验 item
		if item.numMerged == 0 {
			if !checksumValid(bufs[item.bufsIndex][bufsOffset:], item.iphLen, unix.IPPROTO_TCP, isV6) {
				return coalesceItemInvalidCSum
			}
		}
		// 校验新包 pkt
		if !checksumValid(pkt, item.iphLen, unix.IPPROTO_TCP, isV6) {
			return coalescePktInvalidCSum
		}
		// 如果新包带 PSH 标志，这正好允许作为尾包；合并结果的 PSH 也应当被设置。
		if pshSet {
			// We are appending a segment with PSH set.
			item.pshSet = pshSet
			// 直接把合并后首段 TCP 头的 PSH 位置上（拆分 GSO 时再由 gsoSplit 重置为只在尾段有 PSH）
			pktHead[item.iphLen+tcpFlagsOffset] |= tcpFlagPSH
		}
		// 追加多少字节 = 新包 payload 长度
		extendBy := len(pkt) - int(headersLen)
		bufs[item.bufsIndex] = append(bufs[item.bufsIndex], make([]byte, extendBy)...)
		copy(bufs[item.bufsIndex][bufsOffset+len(pktHead):], pkt[headersLen:])
	}

	// 合并后，gsoSize 取两者较大值（保证拆分段时最大不超过这个值）
	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}

	item.numMerged++
	return coalesceSuccess
}

// ipv4FlagMoreFragments 是 IPv4 头部 Flags 字段（字节 6 的高 3 位）中 MF 位的掩码。
// 0x20 = 0b00100000，即字节 6 的第 2 位（从 0 开始计最高位为 bit 7，则 MF = bit 5）。
// MF=1 表示「后面还有更多分片」，该报文是 IP 分片的非最后一片，此时不做 GRO 合并。
const (
	ipv4FlagMoreFragments uint8 = 0x20
)

// IP 头部中源地址字段的起始偏移常量：
//
//	IPv4：头部结构中，第 12 字节起是 4 字节的源 IP 地址
//	IPv6：头部结构中，第 8 字节起是 16 字节的源 IPv6 地址
//
// 目的地址 = 源地址偏移 + 地址长度（IPv4: 12+4=16，IPv6: 8+16=24）
// maxUint16 = 65535，是 IPv4/IPv6 报文理论最大长度（因为 IP 头的总长度字段是 16 bit）。
const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
	maxUint16         = 1<<16 - 1
)

// groResult 表示 GRO 处理单个报文的结果枚举。
type groResult int

const (
	groResultNoop        groResult = iota // 0：不做任何处理（不是 GRO 候选包/校验失败等）
	groResultTableInsert                  // 1：已插入表中作为独立条目（后续可能继续被合并）
	groResultCoalesced                    // 2：已成功合并到某个已有条目中（不需要再单独输出）
)

// tcpGRO 评估 bufs 中第 pktI 个位置的 TCP 报文，尝试与 table 中已存在的同流包合并。
// 返回：
//   - groResultNoop：       该报文不参与 GRO（非法/非候选/分片/checksum 失败等）
//   - groResultTableInsert：该报文被当作新条目插入表（或 checksum 失败独立存在）
//   - groResultCoalesced：  该报文已成功合并到某已有条目上
//
// 执行流程：
//  1. 基本合法性校验：包长、IP 头长度、IPv4 TotalLen / IPv6 PayloadLen 与实际长度一致。
//  2. TCP 头合法性校验：头长在 [20,60] 字节之间，报文有足够 payload。
//  3. 分片过滤：IPv4 报文若 MF=1 或 Fragment Offset != 0 则跳过。
//  4. Flags 过滤：只接受纯 ACK 或 ACK+PSH 两种组合。任何带 SYN/FIN/RST/URG 的包都不合并。
//  5. 计算 gsoSize（TCP payload 长度），至少 1 字节（纯 ACK 无数据的不合并）。
//  6. 查表：lookupOrInsert，若表中不存在同流则直接插入并返回 TableInsert。
//  7. 若存在同流，从该流 items 的末尾向前遍历（包通常按到达顺序，倒序更快命中；
//     且遇到 checksum 失败可直接 deleteAt 而不会导致索引错乱），
//     逐个调用 tcpPacketsCanCoalesce 判断可否合并。
//  8. 可合并则调用 coalesceTCPPackets 执行实际合并：
//     - 成功：updateAt 写回 item，返回 Coalesced。
//     - ItemInvalidCSum：删除原条目（并清空对应的 virtioNetHdr 防止被当作 GSO 输出）。
//     - PktInvalidCSum：直接返回 Noop（不插入，因为已知 checksum 无效也不能合并）。
//     - 其他：继续尝试下一个 item。
//  9. 若遍历完仍未合并成功，将新报文作为独立条目 insert 到表中，返回 TableInsert。
func tcpGRO(bufs [][]byte, offset int, pktI int, table *tcpGROTable, isV6 bool) groResult {
	pkt := bufs[pktI][offset:] // 跳过 virtioNetHdr 前缀，拿到纯 IP 报文
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	// 计算 IP 头长度：IPv4 头第 0 字节低 4 位（IHL）*4；IPv6 固定 40 字节
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		// IPv6 Payload Length = 报文字节 4-5，应等于实际报文除去 40 字节头后的长度
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		// IPv4 Total Length = 报文字节 2-3，应等于实际报文长度
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	// 报文至少要有一个完整的 IP 头
	if len(pkt) < iphLen {
		return groResultNoop
	}
	// TCP 头长度：TCP 头第 12 字节高 4 位（数据偏移）*4；合法值为 20~60 字节
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	// 报文至少要有完整 IP 头 + TCP 头
	if len(pkt) < iphLen+tcphLen {
		return groResultNoop
	}
	// IPv4 分片过滤：
	//   - 字节 6 & 0x20 != 0 => MF 位为 1（还有更多分片）
	//   - 字节 6 << 3 != 0    => Flags 其余位+Fragment Offset 高 5 位非零（有偏移）
	//   - 字节 7 != 0         => Fragment Offset 低 8 位非零
	// 以上任一满足，说明是分片（或不是第一片），不做 GRO。
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	// 提取 TCP flags
	tcpFlags := pkt[iphLen+tcpFlagsOffset]
	var pshSet bool
	// 仅允许两种 flags 组合参与 GRO：
	//   1) 纯 ACK (0x10)
	//   2) ACK+PSH (0x18)
	// 任何带 SYN/FIN/RST/URG/ECE/CWR 的包都直接跳过。
	if tcpFlags != tcpFlagACK {
		if pkt[iphLen+tcpFlagsOffset] != tcpFlagACK|tcpFlagPSH {
			return groResultNoop
		}
		pshSet = true
	}
	// 本包 TCP payload 长度 = 总长度 - IP头 - TCP头
	gsoSize := uint16(len(pkt) - tcphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	// TCP 序列号（seq 字段位于 TCP 头偏移 4-7）
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	// 根据协议版本计算源地址偏移和地址长度
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	// 查表：不存在则插入
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	// 存在同流，倒序尝试合并（优先与最近到达的包合并，应对乱序更高效）
	for i := len(items) - 1; i >= 0; i-- {
		// In the best case of packets arriving in order iterating in reverse is
		// more efficient if there are multiple items for a given flow. This
		// also enables a natural table.deleteAt() in the
		// coalesceItemInvalidCSum case without the need for index tracking.
		// This algorithm makes a best effort to coalesce in the event of
		// unordered packets, where pkt may land anywhere in items from a
		// sequence number perspective, however once an item is inserted into
		// the table it is never compared across other items later.
		item := items[i]
		can := tcpPacketsCanCoalesce(pkt, uint8(iphLen), uint8(tcphLen), seq, pshSet, gsoSize, item, bufs, offset)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(can, pkt, pktI, gsoSize, seq, pshSet, &item, bufs, offset, isV6)
			switch result {
			case coalesceSuccess:
				// 合并成功，更新表中 item 的元数据（numMerged/gsoSize/pshSet/sentSeq 等）
				table.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidCSum:
				// 已有条目 checksum 无效，删除该条目。为了防止后续 applyTCPCoalesceAccounting
				// 误认为它仍需输出 GSO，先把其 virtioNetHdr 清零（等同于写入零值）。
				// delete the item with an invalid csum
				table.deleteAt(item.key, i)
				// The deleted item will not be re-visited in applyTCPCoalesceAccounting,
				// so we must zero the virtioNetHdr. clear() is the equivalent of
				// encoding a zero value virtioNetHdr.
				clear(bufs[item.bufsIndex][offset-virtioNetHdrLen : offset])
			case coalescePktInvalidCSum:
				// 新来的 pkt checksum 无效，没必要再插入表（因为它也无法合并其他包）
				// no point in inserting an item that we can't coalesce
				return groResultNoop
			default:
			}
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	// 遍历完所有已存在条目但未能合并，将新报文作为独立条目插入。
	table.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, tcphLen, pktI)
	return groResultTableInsert
}

// applyTCPCoalesceAccounting 在所有 TCP GRO 合并完成后被调用。
// 遍历 table 中每个 TCP 流的所有条目：
//   - 若该条目经过了合并（numMerged > 0）：
//     1. 构造 virtioNetHdr：设置 NEEDS_CSUM 标志（让内核做 CHECKSUM_PARTIAL）、
//     填写 hdrLen/gsoSize/csumStart/csumOffset，根据协议版本填 gsoType=TCPV4/TCPV6。
//     2. 更新合并后 IP 头：
//   - IPv4：重算 Total Len、清零 hdr checksum 字段后重新计算 IPv4 header checksum。
//   - IPv6：重写 Payload Length 字段（IPv6 无 header checksum）。
//     3. 将 virtioNetHdr 编码写回报文前缀（offset - virtioNetHdrLen 开始）。
//     4. 计算「IP 伪首部」的一补和（仅含 src/dst addr + proto + L4 总长度），
//     将结果写入 TCP 头的 checksum 字段。这一步即实现 CHECKSUM_PARTIAL：
//     用户态提供伪首部和，内核/网卡在发送时再与 TCP 头+payload 求和完成最终 checksum。
//   - 若该条目没有合并（numMerged == 0）：
//     直接清空 virtioNetHdr，标记为普通单包输出（无 GSO 无 NEEDS_CSUM）。
func applyTCPCoalesceAccounting(bufs [][]byte, offset int, table *tcpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				// 构造 virtio net header
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,   // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + item.tcphLen), // 头总长度 = IP头 + TCP头
					gsoSize:    item.gsoSize,                       // 每段 MSS 等价大小
					csumStart:  uint16(item.iphLen),                // checksum 起始 = TCP 头起点
					csumOffset: 16,                                 // TCP checksum 字段相对 TCP 头偏移 = 16
				}
				pkt := bufs[item.bufsIndex][offset:]

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					// IPv6 Payload Length = 报文总长度 - IPv6 头长
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					// 先清零 IPv4 头 checksum 字段（偏移 10-11），避免求和时把旧 checksum 算进去
					pkt[10], pkt[11] = 0, 0
					// 写回新的 Total Length
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					// 计算 IPv4 头 checksum：对整个 IP 头做一补和，然后取反
					iphCSum := ^checksum(pkt[:item.iphLen], 0)    // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum) // set IPv4 header checksum field
				}
				// 把构造好的 virtioNetHdr 编码写入报文前缀
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}

				// Calculate the pseudo header checksum and place it at the TCP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the tcp header and payload checksum.
				// 计算「IP 伪首部」一补和，写入 TCP checksum 字段（实现 CHECKSUM_PARTIAL）
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				// 注意：实际报文在 bufs 中是从 offset 开始的（前面带了 virtioNetHdr），
				// 所以访问地址字段时需要在全局偏移基础上加 addrOffset。
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				// TCP 伪首部 = src addr + dst addr + 0 + proto + TCP segment 总长度
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				// 将伪首部和（未折叠）直接写入 TCP checksum 字段；
				// checksum([]byte{}, psum) 将 64 位累加值折叠成 16 位一补值。
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))
			} else {
				// 未合并的普通包：清空 virtioNetHdr（等效于写入全零）
				clear(bufs[item.bufsIndex][offset-virtioNetHdrLen : offset])
			}
		}
	}
	return nil
}

// applyUDPCoalesceAccounting 与 applyTCPCoalesceAccounting 对应，是 UDP 版的合并结果写回函数。
// 差异点：
//   - gsoType = VIRTIO_NET_HDR_GSO_UDP_L4（UDP L4 GSO，要求每个分段 checksum 全量计算）
//   - csumOffset = 6（UDP 头第 6 字节为 UDP checksum）
//   - hdrLen = iphLen + 8（UDP 固定头长 udphLen=8）
//   - 需要额外更新合并后 UDP 头部的 Length 字段（偏移 4-5）
func applyUDPCoalesceAccounting(bufs [][]byte, offset int, table *udpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + udphLen),    // 头总长度 = IP头 + UDP头(8)
					gsoSize:    item.gsoSize,                     // UDP 每段 payload 大小
					csumStart:  uint16(item.iphLen),              // checksum 起始 = UDP 头起点
					csumOffset: 6,                                // UDP checksum 相对 UDP 头偏移 = 6
				}
				pkt := bufs[item.bufsIndex][offset:]

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					// IPv6：更新 Payload Length
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					// IPv4：清零 checksum 字段 + 更新 Total Length + 重算 IPv4 头校验和
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					iphCSum := ^checksum(pkt[:item.iphLen], 0)            // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)         // set IPv4 header checksum field
				}
				err := hdr.encode(bufs[item.bufsIndex][offset-virtioNetHdrLen:])
				if err != nil {
					return err
				}

				// Recalculate the UDP len field value
				// UDP 头长度字段（偏移 4-5）表示 UDP 头 + UDP payload 的总长度 = 合并后报文尾部总长 - IP头
				binary.BigEndian.PutUint16(pkt[item.iphLen+4:], uint16(len(pkt[item.iphLen:])))

				// Calculate the pseudo header checksum and place it at the UDP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the udp header and payload checksum.
				// 伪首部 + 写回 UDP checksum 字段（CHECKSUM_PARTIAL 语义）
				addrLen := 4
				addrOffset := ipv4SrcAddrOffset
				if item.key.isV6 {
					addrLen = 16
					addrOffset = ipv6SrcAddrOffset
				}
				srcAddrAt := offset + addrOffset
				srcAddr := bufs[item.bufsIndex][srcAddrAt : srcAddrAt+addrLen]
				dstAddr := bufs[item.bufsIndex][srcAddrAt+addrLen : srcAddrAt+addrLen*2]
				psum := pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, srcAddr, dstAddr, uint16(len(pkt)-int(item.iphLen)))
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:], checksum([]byte{}, psum))
			} else {
				// 未合并包：清零 virtioNetHdr
				clear(bufs[item.bufsIndex][offset-virtioNetHdrLen : offset])
			}
		}
	}
	return nil
}

// groCandidateType 标识一个 IP 报文是否为可参与 GRO 的候选包，以及具体类型。
type groCandidateType uint8

const (
	notGROCandidate  groCandidateType = iota // 0：非候选
	tcp4GROCandidate                         // 1：IPv4 TCP
	tcp6GROCandidate                         // 2：IPv6 TCP
	udp4GROCandidate                         // 3：IPv4 UDP（需 canUDPGRO 开关）
	udp6GROCandidate                         // 4：IPv6 UDP（需 canUDPGRO 开关）
)

// packetIsGROCandidate 根据报文字节内容快速判断是否是 GRO 候选。
// 仅做版本号、IP 头格式、协议号、最小包长等快速判断，不做 checksum/flag 等深检。
// 参数 canUDPGRO 表示当前 TUN 设备是否支持 UDP GRO（新内核支持 UDP GRO_L4 才开启）。
func packetIsGROCandidate(b []byte, canUDPGRO bool) groCandidateType {
	// 28 = IPv4 头(20) + UDP头(8)；任何合法 IPv4 UDP 至少 28 字节
	if len(b) < 28 {
		return notGROCandidate
	}
	if b[0]>>4 == 4 {
		// IPv4：
		// 带 IP options 的包（IHL > 5）不参与 GRO（简化处理，实际内核也通常不合并带选项的包）
		if b[0]&0x0F != 5 {
			// IPv4 packets w/IP options do not coalesce
			return notGROCandidate
		}
		// IPv4 字节 9 = 协议号；TCP 要求至少 40 字节（20+20），UDP 无额外长度要求
		if b[9] == unix.IPPROTO_TCP && len(b) >= 40 {
			return tcp4GROCandidate
		}
		if b[9] == unix.IPPROTO_UDP && canUDPGRO {
			return udp4GROCandidate
		}
	} else if b[0]>>4 == 6 {
		// IPv6：字节 6 = Next Header（协议号）；
		//   最小 IPv6 TCP = 40 + 20 = 60 字节
		//   最小 IPv6 UDP = 40 + 8  = 48 字节
		if b[6] == unix.IPPROTO_TCP && len(b) >= 60 {
			return tcp6GROCandidate
		}
		if b[6] == unix.IPPROTO_UDP && len(b) >= 48 && canUDPGRO {
			return udp6GROCandidate
		}
	}
	return notGROCandidate
}

// udphLen = UDP 头部固定长度（8 字节）：源端口(2)+目的端口(2)+长度(2)+校验和(2)
const (
	udphLen = 8
)

// udpGRO 评估 bufs 中第 pktI 个位置的 UDP 报文，尝试与同流条目合并。
//
// 与 tcpGRO 的关键区别：UDP 没有序列号，为了避免包重排，只允许与同流「最后一个条目」比较。
// 逻辑与 tcpGRO 整体一致，简化点包括：
//   - 不需要校验 TCP flags / TCP options
//   - 只取 items[len(items)-1] 判断一次（不是倒序遍历所有）
//   - 合并方向仅 append（不支持 prepend）
//   - 若条目 item 的 checksum 已知无效，仅跳过不删除（后续的包还可能继续 append 到新条目上）
//   - 若新包 pkt 的 checksum 已知无效，仍插入表中（但标记 cSumKnownInvalid=true，避免重复校验）
func udpGRO(bufs [][]byte, offset int, pktI int, table *udpGROTable, isV6 bool) groResult {
	pkt := bufs[pktI][offset:]
	if len(pkt) > maxUint16 {
		// A valid IPv4 or IPv6 packet will never exceed this.
		return groResultNoop
	}
	// IP 头长度与报文总长度合法性（与 tcpGRO 相同）
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	// 至少要有完整的 UDP 头（8 字节）
	if len(pkt) < iphLen+udphLen {
		return groResultNoop
	}
	// IPv4 分片过滤（与 tcpGRO 相同）
	if !isV6 {
		if pkt[6]&ipv4FlagMoreFragments != 0 || pkt[6]<<3 != 0 || pkt[7] != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	// UDP payload 长度
	gsoSize := uint16(len(pkt) - udphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	srcAddrOffset := ipv4SrcAddrOffset
	addrLen := 4
	if isV6 {
		srcAddrOffset = ipv6SrcAddrOffset
		addrLen = 16
	}
	items, existing := table.lookupOrInsert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	// With UDP we only check the last item, otherwise we could reorder packets
	// for a given flow. We must also always insert a new item, or successfully
	// coalesce with an existing item, for the same reason.
	// UDP：只与流中最后一项比较（防止包重排）
	item := items[len(items)-1]
	can := udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, item, bufs, offset)
	var pktCSumKnownInvalid bool
	if can == coalesceAppend {
		result := coalesceUDPPackets(pkt, &item, bufs, offset, isV6)
		switch result {
		case coalesceSuccess:
			// 合并成功：更新最后一项的元数据
			table.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidCSum:
			// 已有条目 checksum 无效：不删除也不报错，继续往下走到 insert，
			// 将新包作为新的独立条目。旧条目后续不会再被访问（因为只比较最后一个）。
			// If the existing item has an invalid csum we take no action. A new
			// item will be stored after it, and the existing item will never be
			// revisited as part of future coalescing candidacy checks.
		case coalescePktInvalidCSum:
			// 新包 checksum 无效：仍然插入表中（保证输出），但记录已知无效，避免重复校验
			// We must insert a new item, but we also mark it as invalid csum
			// to prevent a repeat checksum validation.
			pktCSumKnownInvalid = true
		default:
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, srcAddrOffset, srcAddrOffset+addrLen, iphLen, pktI, pktCSumKnownInvalid)
	return groResultTableInsert
}

// handleGRO 是对外的 GRO 总入口函数。对一批 bufs 中的每个报文依次执行候选判断 + GRO 合并。
// 参数：
//
//	bufs:       一批报文 buffer，每个元素的结构是 [virtioNetHdrLen 字节前缀][offset 指向这里开始的实际 IP 报文...]
//	offset:     每个 buf 中实际 IP 报文开始的偏移（必须 >= virtioNetHdrLen，否则无前缀空间写回）
//	tcpTable:   TCP GRO 哈希表（调用方可复用，用完后再 reset）
//	udpTable:   UDP GRO 哈希表
//	canUDPGRO:  是否允许 UDP GRO
//	toWrite:    出参；GRO 处理后，需要被真正写入 TUN 设备的 bufs 索引会 append 到这里。
//	            未合并的独立包和合并后的总包都会出现在 toWrite 中；
//	            被合并掉的包（返回 Coalesced 的那些）不会出现在 toWrite 中。
//
// 流程：
//  1. 遍历 bufs[i]：先校验 offset 合法；
//  2. packetIsGROCandidate 判断是 TCP4/TCP6/UDP4/UDP6/非候选；
//  3. 按类型分派 tcpGRO / udpGRO；
//  4. 根据返回结果：
//     - Noop：       清零 virtioNetHdr，放入 toWrite（当作普通包写回）
//     - TableInsert：放入 toWrite（后续 apply 会把对应的 virtioNetHdr 写回）
//     - Coalesced：  不放入 toWrite（已经合并到别的条目上，由对方负责写回）
//  5. 遍历结束后，调用 applyTCPCoalesceAccounting + applyUDPCoalesceAccounting，
//     把所有合并结果的 virtioNetHdr / IP 头 / L4 checksum 全部写回。
func handleGRO(bufs [][]byte, offset int, tcpTable *tcpGROTable, udpTable *udpGROTable, canUDPGRO bool, toWrite *[]int) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var result groResult
		switch packetIsGROCandidate(bufs[i][offset:], canUDPGRO) {
		case tcp4GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, true)
		case udp4GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, false)
		case udp6GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, true)
		}
		switch result {
		case groResultNoop:
			// 非 GRO 候选：清空 virtioNetHdr，仍要写回
			clear(bufs[i][offset-virtioNetHdrLen : offset])
			fallthrough
		case groResultTableInsert:
			// 插入到表中的独立条目（合并或未合并最终都会对应一个输出包）
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(bufs, offset, tcpTable)
	errUDP := applyUDPCoalesceAccounting(bufs, offset, udpTable)
	return errors.Join(errTCP, errUDP)
}

// gsoSplit 是 GSO（发送侧大包分段）函数，执行与 GRO 相反的工作。
// 输入：一个带 virtioNetHdr 的超级大包 in（经过 GRO 合并产生，或应用层直接下发的 GSO 包），
//
//	hdr 是 in 的 virtioNetHdr（已提前 decode 好）。
//
// 输出：将 in 拆成若干个 MTU 以内（不超过 hdrLen + gsoSize）的普通小包，
//
//	放入 outBuffs[outOffset:] 开始的缓冲，每个小包的长度写入 sizes[i]。
//
// 返回：实际使用了多少个 outBuffs 元素（= 分段数量），以及可能的错误 ErrTooManySegments。
//
// 拆分要点：
//
//	(A) IP 层：
//	 - IPv4：每个分段的 IP ID 逐段 +1（保证分片/分段 ID 唯一性）；
//	         重算 Total Length；重算 IPv4 头 checksum。
//	 - IPv6：每个分段重写 Payload Length（无 IP ID 字段、无 header checksum）。
//	(B) 传输层：
//	 - TCP：每个分段的序列号递增 gsoSize；FIN/PSH 标志仅在最后一个分段上保留。
//	 - UDP：每个分段的 UDP Length = 本分段 UDP 头 + UDP payload。
//	(C) 传输层 checksum：
//	 因为 gsoSplit 在用户态执行，下游不再有机会做硬件 offload，
//	 所以每个分段都会全量计算「伪首部 + 传输层头 + 传输层 payload」的 checksum，
//	 写入 TCP/UDP 的 checksum 字段（不再使用 NEEDS_CSUM）。
func gsoSplit(in []byte, hdr virtioNetHdr, outBuffs [][]byte, sizes []int, outOffset int, isV6 bool) (int, error) {
	iphLen := int(hdr.csumStart) // 这里 csumStart 就是 IP 头长度（因为 L4 头 = L4 checksum 起点）

	// 计算 IP 地址字段的偏移与长度，为后续伪首部计算准备
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if !isV6 {
		in[10], in[11] = 0, 0 // 先清零输入中的 IPv4 header checksum，避免影响分段计算（不过我们是拷贝头，可忽略，但保险起见）
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	// 传输层 checksum 字段位置（相对 in 的起始偏移）
	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	in[transportCsumAt], in[transportCsumAt+1] = 0, 0 // 清空中输入报文的 TCP/UDP checksum（后续我们为每段独立计算）

	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		// 取首个分段的起始序列号（TCP 头偏移 4-7 字节）
		firstTCPSeqNum = binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}

	// 下一段 payload 在 in 中的起始位置；从 hdrLen 开始（=IP头+L4头，正好是第一个 payload 字节）
	nextSegmentDataAt := int(hdr.hdrLen)
	i := 0 // 已分段数量
	for ; nextSegmentDataAt < len(in); i++ {
		// 分段输出 buffer 不够，返回已完成的分段数 + ErrTooManySegments
		if i == len(outBuffs) {
			return i - 1, ErrTooManySegments
		}
		// 计算本段 payload 的结束位置：通常 = 下一起始 + gsoSize；如果超出 in 末尾则截断（尾段更小）
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt // 本段 L4 payload 长度
		totalLen := int(hdr.hdrLen) + segmentDataLen         // 本段完整报文长度（不含 virtioNetHdr）
		sizes[i] = totalLen
		out := outBuffs[i][outOffset:] // 在输出 buffer 中的目标区域（跳过 outOffset 字节的 virtioNetHdr 前缀）

		// ========== IP 头拷贝与更新 ==========
		copy(out, in[:iphLen]) // 拷贝 IP 头模板
		if !isV6 {
			// IPv4：
			//   第 1 段（i==0）直接用原 ID；第 2 段起 ID += i（每段 ID 不同）
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			// 更新 IPv4 Total Length
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			// 计算 IPv4 header checksum
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// IPv6：更新 Payload Length = totalLen - iphLen
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		// ========== 传输层头拷贝与更新 ==========
		// copy transport header（从 csumStart = L4 头起始，到 hdrLen = L4 头末尾）
		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])

		if protocol == unix.IPPROTO_TCP {
			// TCP：序列号 = 首段 seq + i * gsoSize
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(in) {
				// 非尾段：清除 FIN 和 PSH 标志（只能在最后一段保留）
				// FIN and PSH should only be set on last segment
				clearFlags := tcpFlagFIN | tcpFlagPSH
				out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			// UDP：写入本段 UDP Length = UDP头(8) + 本段 UDP payload
			binary.BigEndian.PutUint16(out[hdr.csumStart+4:], uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		// ========== payload 拷贝 ==========
		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		// ========== 传输层 checksum 全量计算 ==========
		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)       // L4 头长度
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen) // 伪首部中的 L4 总长度
		// 1) 计算 IP 伪首部的一补和
		transportCSumNoFold := pseudoHeaderChecksumNoFold(protocol, in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], lenForPseudo)
		// 2) 将伪首部和 + L4 头+payload 做一补和累加，最后取反得到最终 checksum
		transportCSum := ^checksum(out[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], transportCSum)

		// 推进下一段 payload 起点
		nextSegmentDataAt += int(hdr.gsoSize)
	}
	return i, nil
}

// gsoNoneChecksum 处理一种特殊场景：
//
//	virtioNetHdr.gsoType == VIRTIO_NET_HDR_GSO_NONE，
//	但 flags 中设置了 VIRTIO_NET_HDR_F_NEEDS_CSUM（= CHECKSUM_PARTIAL）。
//
// 这种情况通常是：报文不是 GSO 大包，但希望由「下游」来补全 checksum。
// 然而 wireguard-go 的用户态路径上没有硬件/内核再帮我们做 offload，
// 因此我们需要自己把 checksum 补全。
//
// 计算方式：
//  1. 读取 csum 字段中的「初始值」——这是调用方预先写入的伪首部和。
//  2. 清空 csum 字段。
//  3. 从 csumStart 开始到报文末尾（= L4 头 + payload），与伪首部初始值一起做一补和校验，
//     最终取反后写回 csum 字段，得到完整的全量 checksum。
func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := cSumStart + cSumOffset
	// The initial value at the checksum offset should be summed with the
	// checksum we compute. This is typically the pseudo-header checksum.
	// 读取初始的伪首部和（调用方预先写入的 CHECKSUM_PARTIAL 值）
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	// 清零 csum 字段，避免在求和过程中把自身算进去
	in[cSumAt], in[cSumAt+1] = 0, 0
	// 从 csumStart 开始累加，最后把伪首部 initial 也加进去，取反写入
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum(in[cSumStart:], uint64(initial)))
	return nil
}
