package tun

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/sys/unix"
)

// checksumRef 是 RFC 1071 "Internet Checksum"（互联网校验和）算法的
// 朴素（naive）参考实现，用于和生产代码中的优化版 checksum 函数
// 做交叉验证（cross-validation）。
//
// 算法步骤（RFC 1071 §1.2 "Computation of the Checksum"）：
//   1. 将待计算字节流视作一串 16 位大端序（network byte order）字序列
//   2. 对所有 16 位字做 one's complement sum（反码和），即溢出位回卷加法）
//   3. 若字节总数为奇数，末尾补 8 个零位凑成 16 位（左移 8 位）后再累加
//   4. 累加结束后反复对高 16 位与低 16 位相加折叠（fold），直到高 16 位为 0
//   5. 最终结果取反码即得到校验和（注意：此函数返回的是"反码和本身，
//      调用方按需取反；某些协议栈会在设置校验和时再取反）
//
// 与生产代码 checksum() 函数的差异：
//   - checksumRef：每轮 binary.BigEndian.Uint16 逐 16 位 naive 读取，
//     每次只处理 2 字节，零技巧，是 RFC 算法的直接翻译。
//   - 生产代码 checksum()：典型快路径优化，使用 32/64 位整数一次读多个字，
//     减少循环次数，并在最后统一折叠，用 unsafe 对齐加速、
//     handling 小批量处理。二者必须在任意长度、任意初始值、任意数据上结果严格一致。
//
// 参数：
//   - b: 待计算校验和的字节切片
//   - initial: 初始累加值（用于将伪首部校验和作为初值传入，实现"叠加计算"）
//
// 返回值：16 位校验和（反码和，未取反，调用方按需取反）
//
// 回归防护的性质（作为测试辅助函数）：
//   提供一个"简单到不可能出错"的黄金参考实现（O(n)朴素算法），
//   让任何长度、任何数据上结果严格一致。
func checksumRef(b []byte, initial uint16) uint16 {
	// 使用 64 位累加器：避免中间溢出（最多处理 9001 字节 ≈ 4501 个 16 位字，
	// 最大值 4501*0xFFFF ≈ 0x1199 ，64 位足够安全）
	ac := uint64(initial)

	// 逐 16 位大端读取累加 — 每次循环 2 字节
	for len(b) >= 2 {
		ac += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	// 处理剩余的最后一个单字节（奇数字节流末尾）
	// 左移 8 位等价于"补零凑高位字节，形成 16 位字：
	// RFC 1071：最后一个字节作为高字节，低字节补 0
	if len(b) == 1 {
		ac += uint64(b[0]) << 8
	}

	// 折叠（fold）阶段：反复把溢出的高 16 位加回低 16 位
	// 例如 ac = 0x1ABCD → 第一次：高 16 位 = 0x0001，低 16 位 = 0xABCD
	//                 → 第二次：(0x0001 + 0xABCD = 0xABCE，高 16 位为 0，结束
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(ac)
}

// pseudoHeaderChecksumRefNoFold 计算 TCP/UDP 伪首部（pseudo header）校验和，
// 是生产代码 pseudoHeaderChecksumNoFold 的朴素参考实现。
//
// TCP/UDP 校验和的计算需要引入 IP 层信息（源地址、目的地址、协议号、传输层总长度），
// 这些字段组合成"伪首部"参与校验和累加，目的是防止 IP 层路由错误导致数据包被错误
// 递送到错误的主机或协议处理函数（即使传输层自身校验和正确）。
//
// 伪首部组成（按 RFC 793 / RFC 768）：
//   对于 IPv4：
//     - 源 IP 地址（4 字节）+ 目的 IP 地址（4 字节）
//     - 保留字节（0）+ 协议号（1 字节，如 IPPROTO_TCP=6、IPPROTO_UDP=17）
//     - TCP/UDP 总长度（2 字节，含传输层头部和 payload）
//
//   对于 IPv6：结构相同，但地址为 16 字节
//
// "NoFold" 含义：此函数返回后不做最终取反，结果作为"初始累加值继续叠加到
//   传输层头部+payload 的校验和，由 checksum/checksumRef 中传入。
//
// 参数：
//   - protocol: 传输层协议号（unix.IPPROTO_TCP 或 unix.IPPROTO_UDP）
//   - srcAddr: 源 IP 地址（4 字节 v4 或 16 字节 v6）
//   - dstAddr: 目的 IP 地址
//   - totalLen: TCP/UDP 报文总长度（头部+payload，单位字节）
//
// 返回值：伪首部 16 位反码和（未取反，继续叠加使用）
//
// 回归防护的性质（作为测试辅助函数）：
//   提供伪首部校验和的朴素参考实现，用于验证生产代码
//   pseudoHeaderChecksumNoFold 的正确性。
func pseudoHeaderChecksumRefNoFold(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint16 {
	// 按伪首部字段顺序依次累加：源地址 → 目的地址 → 协议号 → 总长度
	sum := checksumRef(srcAddr, 0)
	sum = checksumRef(dstAddr, sum)
	// 保留字节（0）+ protocol：大端 16 位 = 0x00<<8 | protocol = [0, protocol]
	sum = checksumRef([]byte{0, protocol}, sum)
	// 将 16 位 totalLen 转大端写入临时 2 字节切片后累加
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumRef(tmp, sum)
}

// TestChecksum 穷尽遍历 0 到 9001 字节的所有长度，对相同随机种子生成的数据，
// 验证 checksum() 优化实现与 checksumRef() 朴素参考实现输出严格一致。
//
// 长度选择理由：
//   - 0：边界：空输入
//   - 1：奇数最小长度，覆盖单字节剩余分支
//   - 2、3：覆盖各种 2 字节对齐、1 字节剩余
//   - 64/128/...：典型应用层小包
//   - 1500：典型以太网 MTU（不含 L2/L3 头）
//   - 9000/9001：巨型帧（Jumbo Frame）典型 MTU 边界，9001 是故意超 9000 1 字节
//   - 9001 同时选择覆盖"长度=奇数且很大"的场景，考验折叠逻辑正确性
//
// 随机种子固定为 1：保证每次运行的数据包字节完全相同，
//   可重复性（deterministic），失败时可稳定复现。
// 初始累加值固定为 0x1234：验证"非零初值"场景下的正确性
// （checksum/checksumRef 初值分支代码路径）。
//
// 回归防护的性质：
//   保证生产代码 checksum() 在[0, 9001] 范围内的所有长度、所有字节数据、
//   非零初值下与朴素参考实现字节级一致，避免快路径优化中常见错误：
//   - 偶数字节时最后一个字读越界
//   - 奇数末尾单字节移位方向错误（应左移 8 位）
//   - 折叠次数不够导致高位未清零
//   - 初值叠加时位宽截断错误
//   - unsafe 批量读时字节序（应大端，小端平台上会错）
func TestChecksum(t *testing.T) {
	// 遍历 length = 0..9001 共 9002 种长度，逐一验证
	for length := 0; length <= 9001; length++ {
		// 分配当前长度的缓冲区
		buf := make([]byte, length)
		// 固定种子 1：每次运行生成相同随机字节，保证测试可复现
		rng := rand.New(rand.NewSource(1))
		rng.Read(buf)
		// 生产代码：优化版 checksum，初值 0x1234
		csum := checksum(buf, 0x1234)
		// 参考实现：朴素 checksumRef，相同初值
		csumRef := checksumRef(buf, 0x1234)
		if csum != csumRef {
			t.Error("Expected checksum", csumRef, "got", csum)
		}
	}
}

// TestPseudoHeaderChecksum 验证伪首部校验和 + 传输层数据校验和的端到端正确性。
// 对 IPv4（地址长 4 字节）和 IPv6（地址长 16 字节）两种地址族均覆盖。
//
// 测试覆盖维度：
//   1. 地址族：IPv4（4 字节地址）和 IPv6（16 字节地址）
//      — 覆盖伪首部地址长度变化引起的累加次数差异
//   2. 长度：0..9001，与 TestChecksum 相同的长度矩阵
//      — 伪首部总长度字段写入大端序编码正确性
//   3. 协议号：固定为 IPPROTO_TCP=6
//      — 覆盖 [0, protocol] 两字节合成正确性
//
// 组合逻辑：
//   - 生产代码路径：pseudoHeaderChecksumNoFold(伪首部累加) → checksum(数据+伪首叠加)
//   - 参考实现路径：pseudoHeaderChecksumRefNoFold → checksumRef
//   两者最终结果必须严格相等。
//
// 回归防护的性质：
//   保证生产代码 pseudoHeaderChecksumNoFold 对 v4/v6 两种伪首部编码、
//   任意长度下的正确性。
//   同时验证"伪首部校验和作为初值叠加传入 checksum"的组合接口契约正确，
//   防止拆分两段累加顺序错误或截断进位丢失。
func TestPseudoHeaderChecksum(t *testing.T) {
	// addrLen 两种：4 = IPv4 地址，16 = IPv6 地址
	for _, addrLen := range []int{4, 16} {
		for length := 0; length <= 9001; length++ {
			srcAddr := make([]byte, addrLen)
			dstAddr := make([]byte, addrLen)
			buf := make([]byte, length)
			// 固定种子 1：每次运行 srcAddr/dstAddr/buf 完全相同可复现
			rng := rand.New(rand.NewSource(1))
			rng.Read(srcAddr)
			rng.Read(dstAddr)
			rng.Read(buf)
			// 生产代码：伪首部 → 叠加数据
			phSum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(length))
			csum := checksum(buf, phSum)
			// 参考实现：伪首部 → 叠加数据
			phSumRef := pseudoHeaderChecksumRefNoFold(unix.IPPROTO_TCP, srcAddr, dstAddr, uint16(length))
			csumRef := checksumRef(buf, phSumRef)
			if csum != csumRef {
				t.Error("Expected checksumRef", csumRef, "got", csum)
			}
		}
	}
}

// BenchmarkChecksum 对常见网络报文长度做基准测试（benchmark），
// 用于衡量生产代码 checksum() 的性能表现，防止后续优化/重构导致性能回退。
//
// 长度选择理由（按网络栈典型场景）：
//   - 64: TCP ACK / TCP SYN / 最小 TCP 报文（不含数据）
//   - 128: 小 HTTP 请求头 / DNS 响应
//   - 256: SSH 控制报文
//   - 512: 典型 DNS/UDP 应答上限（EDNS前）
//   - 1024: 中等大小应用层数据
//   - 1500: 标准以太网 MTU（不含 IP+IPsec+WireGuard 头后约 1420 有效载荷）
//   - 2048: 较大应用层 PDU
//   - 4096: 4KB 页大小的典型块传输
//   - 8192: 8KB 块
//   - 9000: 巨型帧 Jumbo Frame 标准 MTU
//   - 9001: 超巨型帧边界 1 字节，检查边界性能
//
// 每个长度子测试（b.Run）内部：
//   - 分配对应长度 buf，填相同随机数据（种子 1，确保跨 benchmark 数据一致可对比）
//   - b.ResetTimer()：重置计时，排除内存分配与随机数生成开销，只计 checksum 本身
//   - 循环 b.N 次（testing.B 框架自适应 b.N 达到统计显著）反复调 checksum(buf, 0)
//
// 回归防护的性质（作为基准测试）：
//   保证 checksum 在所有常见报文长度上的性能有可测量基线，
//   若提交后对比 ns/op（每操作纳秒数）显著上升即性能回退，
//   需检查优化是否失效。通常 checksum 在热路径上（每包必算），
//   性能下降会直接影响吞吐。
func BenchmarkChecksum(b *testing.B) {
	// 覆盖典型网络报文长度矩阵
	lengths := []int{
		64,
		128,
		256,
		512,
		1024,
		1500,
		2048,
		4096,
		8192,
		9000,
		9001,
	}

	// 每种长度单独跑 benchmark 基准
	for _, length := range lengths {
		b.Run(fmt.Sprintf("%d", length), func(b *testing.B) {
			// 分配并填充随机数据（种子 1）
			buf := make([]byte, length)
			rng := rand.New(rand.NewSource(1))
			rng.Read(buf)
			// 重置计时器：去掉分配和随机数填充时间不算在内
			b.ResetTimer()
			// 核心循环：b.N 次调用 checksum
			for i := 0; i < b.N; i++ {
				checksum(buf, 0)
			}
		})
	}
}
