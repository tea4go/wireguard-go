//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	execplus "github.com/tea4go/gh/execplus"
	logs "github.com/tea4go/gh/log4go"
	"golang.org/x/sys/windows"
)

const (
	DETACHED_PROCESS = 0x00000008
	CREATE_NO_WINDOW = 0x08000000
)

// IsRunningAsAdmin 检测当前进程是否以管理员权限（elevated）运行
func IsRunningAsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		logs.Warning("[权限] AllocateAndInitializeSid 失败: %v", err)
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.GetCurrentProcessToken()
	member, err := token.IsMember(sid)
	if err != nil {
		logs.Warning("[权限] CheckTokenMembership 失败: %v", err)
		return false
	}
	return member
}

// duplicatePrimaryToken 复制当前进程的主访问令牌，用于传递给子进程以确保权限继承
func duplicatePrimaryToken() (windows.Token, error) {
	hProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess 失败, %w", err)
	}
	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess,
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|
			windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|
			windows.TOKEN_ADJUST_SESSIONID,
		&hToken)
	if err != nil {
		return 0, fmt.Errorf("OpenProcessToken 失败, %w", err)
	}
	defer hToken.Close()

	var dupToken windows.Token
	err = windows.DuplicateTokenEx(hToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken)
	if err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx 失败, %w", err)
	}
	return dupToken, nil
}

// setDaemonSysProcAttr 设置 Windows 守护进程的进程属性
// 显式传递当前进程的访问令牌，确保子进程继承管理员权限
func setDaemonSysProcAttr(cmd *execplus.CmdPlus) {
	attr := &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW,
	}

	isAdmin := IsRunningAsAdmin()
	logs.Notice("[权限] 当前进程管理员权限: %v", isAdmin)

	if isAdmin {
		dupToken, err := duplicatePrimaryToken()
		if err != nil {
			logs.Warning("[权限] 复制访问令牌失败，将使用默认继承: %v", err)
		} else {
			logs.Notice("[权限] 已复制访问令牌并传递给守护子进程（Token=0x%X）", uintptr(dupToken))
			attr.Token = syscall.Token(dupToken)
		}
	}

	cmd.SysProcAttr = attr
}

// EnableAllPrivileges 尝试在当前 token 中启用所有可用特权（用于驱动安装等操作）
func EnableAllPrivileges() error {
	hProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess, %w", err)
	}
	var token windows.Token
	err = windows.OpenProcessToken(hProcess,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken, %w", err)
	}
	defer token.Close()

	var bufLen uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &bufLen)
	if bufLen == 0 {
		return nil
	}
	buf := make([]byte, bufLen)
	err = windows.GetTokenInformation(token, windows.TokenPrivileges,
		&buf[0], bufLen, &bufLen)
	if err != nil {
		return fmt.Errorf("GetTokenInformation, %w", err)
	}

	privs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	count := privs.PrivilegeCount
	if count == 0 {
		return nil
	}
	privSlice := unsafe.Slice(&privs.Privileges[0], count)

	luidAttrSize := unsafe.Sizeof(windows.LUIDAndAttributes{})
	newBufSize := unsafe.Sizeof(uint32(0)) + uintptr(count)*luidAttrSize
	newBuf := make([]byte, newBufSize)
	newPrivs := (*windows.Tokenprivileges)(unsafe.Pointer(&newBuf[0]))
	newPrivs.PrivilegeCount = count
	newPrivSlice := unsafe.Slice(&newPrivs.Privileges[0], count)

	for i := uint32(0); i < count; i++ {
		newPrivSlice[i].Luid = privSlice[i].Luid
		newPrivSlice[i].Attributes = windows.SE_PRIVILEGE_ENABLED
	}

	_ = windows.AdjustTokenPrivileges(token, false, newPrivs,
		uint32(newBufSize), nil, nil)
	return nil
}
