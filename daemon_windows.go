//go:build windows

package main

import (
	"syscall"

	execplus "github.com/tea4go/gh/execplus"
)

const (
	DETACHED_PROCESS = 0x00000008
	CREATE_NO_WINDOW = 0x08000000
)

func setDaemonSysProcAttr(cmd *execplus.CmdPlus) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW,
	}
}
