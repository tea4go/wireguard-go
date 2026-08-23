/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"log"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// TODO: replace these with actual standard windows error numbers from the win package
const (
	IpcErrorIO        = -int64(5)
	IpcErrorProtocol  = -int64(71)
	IpcErrorInvalid   = -int64(22)
	IpcErrorPortInUse = -int64(98)
	IpcErrorUnknown   = -int64(55)
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	return l.listener.Close()
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

var UAPISecurityDescriptor *windows.SECURITY_DESCRIPTOR
var FallbackUAPISecurityDescriptor *windows.SECURITY_DESCRIPTOR

func init() {
	var err error
	UAPISecurityDescriptor, err = windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
	if err != nil {
		panic(err)
	}
	FallbackUAPISecurityDescriptor, err = windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		panic(err)
	}
}

// 启用高特权命名管道所需的特权名
// 注：golang.org/x/sys/windows 未导出这些字符串常量，按 Windows SDK 规范直接字面量指定。
const (
	seRestorePrivilege  = "SeRestorePrivilege"
	seSecurityPrivilege = "SeSecurityPrivilege"
)

// enableRequiredPrivileges 尝试启用当前进程 token 中创建高特权命名管道所需的特权：
//   - SeRestorePrivilege：允许将对象 Owner 设置为 SYSTEM（SD 中 O:SY 需要）
//   - SeSecurityPrivilege：允许设置对象的 SACL（SD 中 S:(ML...) 需要）
//
// 注意：即便是管理员提升后的 token，这两项特权默认也是 Disabled，必须显式启用。
// 若当前 token 根本不具备某项特权（例如普通用户运行），该函数会跳过该项并继续尝试其他项。
func enableRequiredPrivileges() {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		log.Printf("[UAPI] 无法打开当前进程 token, %v，将直接尝试创建管道。", err)
		return
	}
	defer token.Close()

	privs := []string{seRestorePrivilege, seSecurityPrivilege}
	for _, name := range privs {
		name16, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, name16, &luid); err != nil {
			continue
		}
		tp := windows.Tokenprivileges{
			PrivilegeCount: 1,
			Privileges: [1]windows.LUIDAndAttributes{
				{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
			},
		}
		// AdjustTokenPrivileges 即便部分特权启用失败也不会返回错误（仅设置 ERROR_NOT_ALL_ASSIGNED）；
		// 因此这里忽略返回值，尽量启用，启用不了的后面靠 fallback SD 兜底。
		_ = windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	}
}

func UAPIListen(name string) (net.Listener, error) {
	pipePath := `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + name
	enableRequiredPrivileges()
	listener, err := (&namedpipe.ListenConfig{
		SecurityDescriptor: UAPISecurityDescriptor,
	}).Listen(pipePath)
	if err != nil {
		rootErr := err
		for {
			unwrapped := errors.Unwrap(rootErr)
			if unwrapped == nil {
				break
			}
			rootErr = unwrapped
		}
		if errors.Is(rootErr, windows.ERROR_INVALID_OWNER) || errors.Is(rootErr, windows.ERROR_PRIVILEGE_NOT_HELD) {
			log.Printf("[UAPI] 高特权安全描述符创建失败（当前进程无 SE_RESTORE/SeSecurity 特权），将使用兼容描述符重试, %v", err)
			listener, err = (&namedpipe.ListenConfig{
				SecurityDescriptor: FallbackUAPISecurityDescriptor,
			}).Listen(pipePath)
		}
		if err != nil {
			return nil, err
		}
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)

	return uapi, nil
}
