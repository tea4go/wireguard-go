/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "用法: %s <接口名称>\n", filepath.Base(os.Args[0]))
}

// exitWithError 打印错误信息后退出。
func exitWithError(logger *device.Logger, format string, args ...any) {
	logger.Errorf(format, args...)
	os.Exit(ExitSetupFailed)
}

func main() {
	if len(os.Args) != 2 {
		printUsage()
		fmt.Fprintln(os.Stderr, "错误: 缺少接口名称参数")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("正在启动 wireguard-go v%s", Version)

	tun, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		exitWithError(logger, "创建 TUN 设备失败: %v", err)
	}

	device := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		exitWithError(logger, "启动设备失败: %v", err)
	}
	logger.Verbosef("设备已启动")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		exitWithError(logger, "UAPI 监听失败: %v", err)
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()
	logger.Verbosef("UAPI 监听已启动")

	// 等待程序终止

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// 清理

	uapi.Close()
	device.Close()

	logger.Verbosef("正在关闭")
}
