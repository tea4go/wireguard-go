package tun

import (
	"encoding/binary"
	"math/bits"
)

// checksumNoFold 执行 TCP/IP 协议栈校验和算法的「未折叠求和阶段」，
// 对输入字节切片 b 以 16 位为单位进行一的补码（one's complement）累加，
// 返回 64 位宽度的未折叠累加和（尚未将高 16 位回折折叠到低 16 位）。
//
// 【算法意图】
// RFC 1071 / RFC 1141 定义的互联网校验和核心步骤是「将所有 16 位字相加，
// 然后将和的高 16 位与低 16 位反复相加（折叠），最终取反得到校验值」。
// 本函数只负责第一步：高效地完成大量 16 位字的累加。
//
// 为提升性能，函数以 64 位（8 字节）为单位进行块读取和加法，利用 bits.Add64
// 同时处理 64 位加法及其进位，最后通过字节序转换确保结果等价于按 16 位大端累加。
// 主循环采用 Duff-like 手动展开（128/64/32/16/8 字节分块），减少分支跳转开销。
//
// 【字节序处理说明（非常关键）】
// TCP/IP 校验和规定按「大端字节序」将两个字节组合成 16 位字再相加。
// 但为了性能，本函数在累加过程中并不逐字节重组大端，而是采取以下技巧：
//   1. 初始值 initial 先被从主机序（NativeEndian）解释为 uint64 写入 tmp，
//      再以 BigEndian 读出，等价于对 initial 的每个 16 位半字做字节交换。
//   2. 数据块使用 NativeEndian 读取为 uint64/uint32/uint16，直接参与累加。
//      虽然此时读出的整数在数值上与大端解释不同，但由于校验和的「按 16 位相加
//      再折叠」性质，只要折叠时转回大端，结果与真正按大端 16 位相加完全一致。
//   3. 返回前再次将累加和 ac 用 NativeEndian 写入 tmp，再用 BigEndian 读出，
//      把结果调整回「等价于按大端 16 位累加」的正确形态。
//   该技巧避免了逐字字节序转换，显著提升大缓冲区校验性能。
//
// 【使用场景】
// 通常不会直接被外部调用，而是作为 checksum() 和 pseudoHeaderChecksumNoFold()
// 的底层累加器使用。当需要拼接多个独立的校验和（如伪首部 + 负载）时，可以
// 把前一次的返回值作为下一次的 initial 传入，实现累加链而无需重算全部数据。
//
// 参数：
//   b       - 待校验的字节切片（长度任意，含 0）
//   initial - 初始累加值（用于拼接多段校验，无前置数据时传 0）
// 返回：
//   64 位未折叠累加和，需调用方在最后调用者或 checksum() 执行折叠与取反
func checksumNoFold(b []byte, initial uint64) uint64 {
	tmp := make([]byte, 8)
	binary.NativeEndian.PutUint64(tmp, initial)
	ac := binary.BigEndian.Uint64(tmp)
	var carry uint64

	// 128 字节块主循环：一次读 16 个 64 位字，依次累加（含前一步进位）
	for len(b) >= 128 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[64:72]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[72:80]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[80:88]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[88:96]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[96:104]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[104:112]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[112:120]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[120:128]), carry)
		ac += carry // 把块内最后一次产生的进位合并到累加器
		b = b[128:]
	}
	// 以下分块按大小递减，处理剩余不足 128 字节的尾部
	if len(b) >= 64 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[32:40]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[40:48]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[48:56]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[56:64]), carry)
		ac += carry
		b = b[64:]
	}
	if len(b) >= 32 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[16:24]), carry)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[24:32]), carry)
		ac += carry
		b = b[32:]
	}
	if len(b) >= 16 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[8:16]), carry)
		ac += carry
		b = b[16:]
	}
	if len(b) >= 8 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac += carry
		b = b[8:]
	}
	if len(b) >= 4 {
		// 4 字节尾部：以 32 位整数读取后提升到 64 位参与累加
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint32(b[:4])), 0)
		ac += carry
		b = b[4:]
	}
	if len(b) >= 2 {
		// 2 字节尾部：以 16 位整数读取后提升到 64 位参与累加
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint16(b[:2])), 0)
		ac += carry
		b = b[2:]
	}
	if len(b) == 1 {
		// 1 字节尾部：奇数长度时，最后 1 字节按「高 8 位为字节值、低 8 位为 0」
		// 方式组成 16 位字参与累加（RFC 1071 第 4.1 节规定）
		tmp := binary.NativeEndian.Uint16([]byte{b[0], 0})
		ac, carry = bits.Add64(ac, uint64(tmp), 0)
		ac += carry
	}

	// 把累加结果从主机序视角切换回「等价大端 16 位累加」视角（与入口处对称）
	binary.NativeEndian.PutUint64(tmp, ac)
	return binary.BigEndian.Uint64(tmp)
}

// checksum 计算并返回完整的 RFC 1071 互联网校验和（16 位）。
//
// 【算法意图】
// 封装 checksumNoFold() 负责的未折叠累加阶段，并在此基础上执行「折叠（fold）」
// 操作：将 64 位累加和的高 16 位反复加到低 16 位上，直到高 16 位全为 0，
// 得到最终的 16 位校验字段（注：按惯例，上层在使用时需再对结果取反 ^0xffff，
// 具体取决于调用场景——是「生成校验和填入报文」还是「接收端验证校验和」）。
//
// 本函数内 4 次重复执行同样的折叠表达式是有意义的：
//   第 1 次折叠：64 位 -> 最大 20 位（16+4，最多 4 位进位）
//   第 2 次折叠：20 位 -> 最大 17 位
//   第 3 次折叠：17 位 -> 最大 16 位
//   第 4 次折叠：保险收敛，保证高 16 位必然为 0（极端多次进位兜底）
//
// 【使用场景】
// 需要得到最终可直接用于 IP/ICMP/UDP/TCP 报文校验字段（或验证）时调用。
// 若后续还要和其他片段（如伪首部）继续累加，应改用 checksumNoFold()
// 保留未折叠结果，待全部拼接完毕后再调用 checksum() 做一次最终折叠。
//
// 参数：
//   b       - 待校验的完整字节流
//   initial - 初始累加值（如已经计算过伪首部校验和，可从此处继续）
// 返回：
//   16 位校验和（未取反，调用方按需 ^0xffff）
func checksum(b []byte, initial uint64) uint16 {
	ac := checksumNoFold(b, initial)
	// 将 64 位累加和的高 16 位回折加至低 16 位，重复执行直至收敛
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}

// pseudoHeaderChecksumNoFold 计算 L4（TCP/UDP）伪首部（pseudo header）的
// 未折叠校验和，用于在 TCP/UDP 校验和计算中加入源地址、目的地址、协议号、
// 总长度等 L3 信息，避免 L3/L4 之间因地址篡改导致校验失效。
//
// 【伪首部结构（RFC 793 / RFC 768）】
//   +--------+--------+--------+--------+
//   |           源 IP 地址 (4B/16B)     |  <- srcAddr（4 字节 IPv4 或 16 字节 IPv6）
//   +--------+--------+--------+--------+
//   |          目的 IP 地址 (4B/16B)    |  <- dstAddr
//   +--------+--------+--------+--------+
//   |  零填充  | 协议号 |  TCP/UDP 总长度 |  <- protocol=6(TCP)/17(UDP)，totalLen 大端
//   +--------+--------+--------+--------+
//   （注：IPv6 场景下伪首部略有扩展，本函数按「地址即字节」方式通用处理，
//    只要调用方传入对应长度的 IPv6 地址即可。）
//
// 【字节序处理说明】
//   - srcAddr / dstAddr 本身在报文中就按网络字节序（大端）存储，
//     直接作为字节串送入 checksumNoFold() 即可，无需额外字节序转换。
//   - {零填充, 协议号} 两字节按大端顺序构造 []byte{0, protocol}，
//     因为校验和按 16 位字组合时，高 8 位在前（0）、低 8 位在后（protocol）。
//   - totalLen（16 位）使用 binary.BigEndian.PutUint16 写入 2 字节缓冲区，
//     保证按网络字节序参与累加。
//
// 【使用场景】
// 在对 TCP/UDP 报文做离线校验和计算（如 TUN 模式下软件封装/解封装需要
// 重算 L4 校验）时，先调用本函数得到伪首部的未折叠和，再把该值作为 initial
// 传入 checksumNoFold() 对 TCP/UDP 头部+负载继续累加，最后用 checksum()
// 折叠并取反，得到最终填入报文的校验字段。
//
// 参数：
//   protocol - L4 协议号（IPv4 header 中的 protocol 字段，如 6=TCP、17=UDP）
//   srcAddr  - 源 IP 地址字节序列（4 字节 IPv4 或 16 字节 IPv6）
//   dstAddr  - 目的 IP 地址字节序列（同上）
//   totalLen - TCP/UDP 报文总长度（头部+数据，单位字节，主机序 uint16）
// 返回：
//   伪首部的 64 位未折叠校验和，可直接作为 checksum / checksumNoFold 的 initial
func pseudoHeaderChecksumNoFold(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint64 {
	// 累加源地址
	sum := checksumNoFold(srcAddr, 0)
	// 累加目的地址（在前一次和的基础上继续累加）
	sum = checksumNoFold(dstAddr, sum)
	// 累加零填充(1 字节) + 协议号(1 字节)，组成一个 16 位大端字
	sum = checksumNoFold([]byte{0, protocol}, sum)
	// 将 totalLen 转换为大端 2 字节并累加（网络字节序）
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumNoFold(tmp, sum)
}
