//go:build windows

package main

import (
	"syscall"

	execplus "github.com/tea4go/gh/execplus"
)

// Windows 进程创建标志
const (
	// DETACHED_PROCESS 与父进程分离，不继承控制台
	DETACHED_PROCESS = 0x00000008
	// CREATE_NO_WINDOW 完全不创建窗口
	CREATE_NO_WINDOW = 0x08000000
)

// setDaemonSysProcAttr 设置 Windows 守护进程的进程属性
// CREATE_NEW_PROCESS_GROUP: 创建新进程组
// DETACHED_PROCESS:         与父进程分离，不继承控制台
// CREATE_NO_WINDOW:         完全不创建窗口
func setDaemonSysProcAttr(cmd *execplus.CmdPlus) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW,
	}
}
