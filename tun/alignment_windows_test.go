/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"reflect"
	"testing"
	"unsafe"
)

// checkAlignment 校验结构体中指定偏移处的字段是否满足 64 位（8 字节）对齐。
//
// 参数：
//   - t: testing.T，测试框架对象，用于输出错误信息
//   - name: 被检查字段的可读名称（如 "rateJuggler.current"），用于错误消息中定位
//   - offset: 字段在结构体中的字节偏移量，通常由 unsafe.Offsetof() 计算得到
//
// 背景与原理：
//   - Go 标准库 sync/atomic 包在 32 位架构（如 386、arm）上要求所有 64 位原子操作
//     （AddUint64、LoadUint64、StoreUint64、SwapUint64、CompareAndSwapUint64）
//     的操作数必须 64 位对齐。
//   - 原因是 32 位 CPU 没有单条指令能原子地读写 64 位字，只能通过"读高 32 位 + 读低 32 位"
//     两条指令模拟。若数据未按 64 位边界对齐，这两次读取可能跨越两个缓存行甚至两个
//     内存页，在此期间若另一个 CPU 并发写入该位置，读到的结果可能是"上半新+下半旧"
//     或反之（torn read/撕裂读），破坏原子性语义。
//   - 更严重的是，某些 32 位 ARM 芯片在访问未对齐的 64 位字时会直接抛出
//     alignment fault（对齐异常），表现为硬 segfault 段错误，程序立即崩溃。
//   - 64 位架构（amd64、arm64）天然保证最小 8 字节对齐，因此本测试主要是为
//     32 位平台的回归防护。
//
// 回归防护的性质：
//   保证所有需要被 sync/atomic 操作的 64 位字段在结构体中的偏移始终是 8 的倍数，
//   防止字段重排/新增/删除时无意中破坏对齐，导致 32 位构建崩溃。
func checkAlignment(t *testing.T, name string, offset uintptr) {
	t.Helper()
	// 检查 offset 模 8 是否等于 0：偏移量必须能被 8 整除（64 位对齐）
	if offset%8 != 0 {
		t.Errorf("offset of %q within struct is %d bytes, which does not align to 64-bit word boundaries (missing %d bytes). Atomic operations will crash on 32-bit systems.", name, offset, 8-(offset%8))
	}
}

// TestRateJugglerAlignment 检查 rateJuggler 结构体中所有需要原子访问的字段
// 是否严格按 64 位边界对齐。
//
// 回归防护的性质：
//   保证 rateJuggler 结构体的 current（当前速率）、nextByteCount（下一段字节计数）、
//   nextStartTime（下一段起始时间戳）这三个被 atomic.AddUint64 / atomic.LoadUint64
//   操作的字段在 32 位系统上不会因对齐问题触发 segfault 或数据撕裂。
//
// 测试过程：
//   1. 通过 reflect.TypeOf 反射获取 rateJuggler 的运行时类型信息
//   2. 遍历所有字段并以日志形式打印每列信息（便于开发者调试对齐问题）：
//      - field.Name: 字段名（如 current、nextByteCount、nextStartTime、mu、closing...）
//      - field.Offset: 该字段相对结构体起始地址的字节偏移量
//      - field.Type.Size(): 该字段自身类型占用的字节数（如 uint64 为 8、bool 为 1）
//      - field.Type.Align(): 该字段类型自身的对齐要求（uint64 类型本身要求 8 对齐，
//        但在 32 位平台上 Go 编译器可能只按 4 字节对齐结构体中的 uint64，
//        这正是本测试要抓出的矛盾）
//   3. 对三个原子字段逐一调用 checkAlignment 断言其偏移是 8 的倍数
func TestRateJugglerAlignment(t *testing.T) {
	var r rateJuggler

	// Elem() 解引用指针类型，拿到结构体本身的 reflect.Type
	typ := reflect.TypeOf(&r).Elem()
	// 打印整个结构体的总字节大小（含编译器插入的 padding 填充字节）
	t.Logf("Peer type size: %d, with fields:", typ.Size())
	// 逐字段打印布局信息：这是调试对齐偏差时的关键排查依据
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Logf("\t%30s\toffset=%3v\t(type size=%3d, align=%d)",
			field.Name,      // 字段名：一眼看出是哪个字段
			field.Offset,    // 偏移：结构体起始到字段首字节的距离，核心对齐指标
			field.Type.Size(), // 类型大小：字段占多少字节，辅助理解 padding
			field.Type.Align(), // 类型对齐要求：该字段自身需按多少字节对齐
		)
	}

	// 以下三个字段是 rateJuggler 中使用 atomic 包读写的 64 位计数器/时间戳
	checkAlignment(t, "rateJuggler.current", unsafe.Offsetof(r.current))
	checkAlignment(t, "rateJuggler.nextByteCount", unsafe.Offsetof(r.nextByteCount))
	checkAlignment(t, "rateJuggler.nextStartTime", unsafe.Offsetof(r.nextStartTime))
}

// TestNativeTunAlignment 检查 NativeTun 结构体中所有需要原子访问的字段
// 是否严格按 64 位边界对齐。
//
// 回归防护的性质：
//   保证 NativeTun.rate（内嵌的 rateJuggler）作为一个整体，其起始偏移在
//   NativeTun 结构体内 64 位对齐，从而间接保证 rateJuggler 内部三个原子字段
//   的对齐（因为 rateJuggler 自身第一个字段 current 偏移为 0，只要整体起始
//   地址对齐，内部字段也就对齐）。
//
// 打印列含义同 TestRateJugglerAlignment：
//   - field.Name: NativeTun 各字段名（如 fd、rate、closing、readOp、events...）
//   - field.Offset: 字段在 NativeTun 内的字节偏移
//   - field.Type.Size(): 字段自身的字节大小
//   - field.Type.Align(): 字段类型要求的最小对齐
func TestNativeTunAlignment(t *testing.T) {
	var tun NativeTun

	typ := reflect.TypeOf(&tun).Elem()
	t.Logf("Peer type size: %d, with fields:", typ.Size())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Logf("\t%30s\toffset=%3v\t(type size=%3d, align=%d)",
			field.Name,
			field.Offset,
			field.Type.Size(),
			field.Type.Align(),
		)
	}

	// tun.rate 是内嵌的 rateJuggler，只要它的起始偏移 64 位对齐，
	// 其内部 current/nextByteCount/nextStartTime 的偏移就也满足对齐
	checkAlignment(t, "NativeTun.rate", unsafe.Offsetof(tun.rate))
}
