//go:build !windows

package main

import (
	execplus "github.com/tea4go/gh/execplus"
)

func setDaemonSysProcAttr(cmd *execplus.CmdPlus) {
}
