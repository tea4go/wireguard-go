//go:build darwin || freebsd
//
// 【Build Tag 适用平台说明】
// 本文件仅在目标 OS 为 darwin（macOS）或 freebsd 时参与编译。
// 原因在于：这两种 BSD 系系统上创建 TUN 设备后，需要对其底层文件描述符（fd）
// 执行额外的 BSD 专属 ioctl/sysctl 操作（如设置接口名、配置 tun 模式、
// 调整 ifcap 能力位等），因此需要一个统一的「在持有原始 fd 的安全上下文中
// 执行任意回调」的辅助方法 operateOnFd()。
// Linux 和 Windows 等平台通过各自独立的实现文件（tun_linux.go / tun_windows.go）
// 直接处理设备 fd，因此不需要该方法，也不会编译本文件。

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
)

// operateOnFd 以「安全、可移植、符合 Go runtime 文件描述符生命周期」的方式，
// 获取 NativeTun 设备底层操作系统文件描述符（fd），并把该 fd 传入用户回调 fn 中执行。
// 典型用途：执行 ioctl、fcntl、setsockopt 等需要原始 fd 的底层系统调用。
//
// 【为什么必须通过 SyscallConn.Control 而非直接调用 tun.tunFile.Fd()？】
//
// Go 1.x 的 *os.File（tun.tunFile 的类型）在 Go runtime 内部有一套独立的
// 「finalizer + 轮询器（poller）」管理机制。直接使用 Fd() 存在三大致命问题：
//
//   1) 【非阻塞模型破坏】Go 的 netpoller 默认把所有 *os.File fd 设置为非阻塞模式
//      并由 epoll/kqueue 统一调度。直接 Fd() 取出后，外部若用阻塞式系统调用
//      操作该 fd，会导致 OS 级阻塞，进而让 Go 调度器的 M（系统线程）被卡住，
//      无法复用去承载其它 G（goroutine），极端情况下会耗尽线程池，
//      出现「程序看似挂死但仍在运行」的现象。
//
//   2) 【文件描述符被 runtime 意外关闭】*os.File 对象被 GC 回收时，其上注册的
//      finalizer 会调用 close(fd) 关闭底层描述符。如果调用者保存了 Fd()
//      返回的 uintptr 但没有同时持有 *os.File 的强引用，GC 可能在系统调用
//      执行中途关闭 fd，导致后续 ioctl 等操作作用于错误的、已被复用的 fd
//      （这是经典的 "TOCTOU + fd reuse" 安全漏洞形态）。
//
//   3) 【写时复制（fork）竞态】Go runtime 在需要创建 OS 线程（如 cgo 回调、
//      系统调用包装）时并不持有外部的 fork 锁。直接裸用 Fd() + syscall.Syscall
//      组合，在高并发 fork（如 exec.Command 密集）场景下，会出现父子进程
//      间 fd 继承、dup2 重定向等竞态问题。
//
// 【SyscallConn.Control(fn) 的工作原理（Go 1.11+，syscall.Conn 接口）】
//
//   - 调用 tunFile.SyscallConn() 获取实现了 syscall.Conn 的 RawConn 对象。
//   - RawConn.Control(fn) 内部会：
//       a. 先通过 runtime.PollDescriptor 获取对该 fd 的互斥访问权；
//       b. 执行 fn(uintptr(fd))，此时 fn 内的系统调用由 Go runtime 保证
//          该 fd 不会被关闭/复用，且 netpoller 会正确处理阻塞；
//       c. 返回后释放访问权，继续让 fd 受 Go runtime 托管。
//   - 这样做既拿到了原生 fd 给 ioctl 等使用，又完全在 Go 的文件生命周期模型内。
//
// 【错误处理】
// 无论是获取 SyscallConn 失败，还是 Control() 执行回调时出错，都会把错误包装后
// 写入 tun.errors 通道，由上层设备事件循环统一收集。本函数不直接返回 error，
// 是为了和其它平台同名（或同用途）方法签名保持一致，方便统一的上层调用模式。
func (tun *NativeTun) operateOnFd(fn func(fd uintptr)) {
	// 从 *os.File 中取出 syscall.RawConn 接口，用于后续安全地操作原始 fd
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		tun.errors <- fmt.Errorf("unable to find sysconn for tunfile: %s", err.Error())
		return
	}
	// 在 Go runtime 的 fd 生命周期保护下执行用户回调 fn，fn 内可以放心执行 ioctl 等
	err = sysconn.Control(fn)
	if err != nil {
		tun.errors <- fmt.Errorf("unable to control sysconn for tunfile: %s", err.Error())
	}
}
