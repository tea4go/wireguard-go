/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
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
	fmt.Fprintf(os.Stderr, "用法: %s [-c 配置文件.conf|配置包.zip] <接口名称>\n", filepath.Base(os.Args[0]))
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

type runningInterface struct {
	name   string
	device *device.Device
	uapi   net.Listener
}

func startConfiguredInterface(cfg *tunnelConfig) (*runningInterface, error) {
	logs.Notice("接口 %s: 开始创建 TUN", cfg.InterfaceName)
	logger := device.NewLogger(
		device.LogLevelVerbose,
		fmt.Sprintf("%s", cfg.InterfaceName),
	)

	mtu := cfg.MTU
	tunDevice, err := tun.CreateTUN(cfg.InterfaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备失败: %w", err)
	}
	logs.Notice("接口 %s: TUN 创建成功", cfg.InterfaceName)

	interfaceName := cfg.InterfaceName
	if realInterfaceName, err := tunDevice.Name(); err == nil {
		interfaceName = realInterfaceName
	}

	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	logger.Verbosef("配置摘要: %s", describeTunnelConfig(cfg))
	for _, peer := range cfg.Peers {
		logger.Verbosef("Peer 摘要: %s", describePeerConfig(peer))
	}
	if cfg.UAPI != "" {
		logs.Notice("接口 %s: 开始应用 WireGuard 配置", interfaceName)
		if err := dev.IpcSet(cfg.UAPI); err != nil {
			dev.Close()
			return nil, fmt.Errorf("应用配置失败: %w", err)
		}
		logs.Notice("接口 %s: WireGuard 配置应用成功", interfaceName)
		if cfg.MTU > 0 {
			logger.Verbosef("已从配置中应用 MTU=%s", strconv.Itoa(cfg.MTU))
		}
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("启动设备失败: %w", err)
	}
	logs.Notice("接口 %s: 设备启动成功", interfaceName)

	if len(cfg.Addresses) > 0 {
		logs.Notice("接口 %s: 开始应用接口地址", interfaceName)
		addressWarnings := applyInterfaceAddresses(interfaceName, cfg.Addresses)
		if len(addressWarnings) == 0 {
			logs.Notice("接口 %s: 接口地址应用完成", interfaceName)
		} else {
			for _, warning := range addressWarnings {
				logs.Error(warning)
			}
		}
	}

	logs.Notice("接口 %s: 开始关闭 IPv6 绑定", interfaceName)
	if err := disableInterfaceIPv6(interfaceName); err != nil {
		logs.Error("接口 %s: 关闭 IPv6 绑定失败: %v", interfaceName, err)
	} else {
		logs.Notice("接口 %s: IPv6 绑定已关闭", interfaceName)
	}

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("UAPI 监听失败: %w", err)
	}
	logs.Notice("接口 %s: UAPI 监听已启动", interfaceName)

	return &runningInterface{
		name:   interfaceName,
		device: dev,
		uapi:   uapi,
	}, nil
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
	//#endregion
	log_name := os.Getenv("log_name")
	if log_name == "" {
		log_name = appName
	}
	// 标准程序块
	network.SetAppVersion(appName, appVer, IsBeta, BuildTime) //设置应用版本号，便于自动更新
	logsFileName := filepathJoin(os.TempDir(), "ulog_"+log_name+".txt")
	logs.SetLogFuncCallDepth(5)
	logs.SetLogger("file", `{"filename":"`+logsFileName+`", "perm": "0666","level":5}`)
	logs.StartLogger()
	network.StartSelfUpdate("http://wc192.yj2025.icu:8118", "http://nj.yj2025.icu:23432", "http://wc8.yj2025.icu:8118", "http://wc47.yj2025.icu:23431")
	// 标准程序块

	var configs []*tunnelConfig
	if strings.TrimSpace(confile) != "" {
		if flag.NArg() != 0 {
			printUsage()
			fmt.Fprintln(os.Stderr, "错误: 使用配置文件模式时不应再传接口名称")
			os.Exit(ExitSetupFailed)
		}
		var warnings []string
		configs, warnings = loadTunnelConfigs(confile)
		logs.Notice("配置来源: %s", confile)
		logs.Notice("本次共识别到 %d 个接口配置", len(configs))
		for _, warning := range warnings {
			logs.Error("配置告警: %s", warning)
		}
		for _, cfg := range configs {
			logs.Notice("配置摘要: %s", describeTunnelConfig(cfg))
		}
	} else {
		if flag.NArg() != 1 {
			printUsage()
			fmt.Fprintln(os.Stderr, "错误: 缺少接口名称参数")
			os.Exit(ExitSetupFailed)
		}
		configs = []*tunnelConfig{{
			InterfaceName: strings.TrimSpace(flag.Arg(0)),
		}}
	}
	logs.Notice("正在启动 %s %s", appName, appVer)

	if err := tun.CheckWintunReady(); err != nil {
		logs.Error(err)
		return
	}

	running := make([]*runningInterface, 0, len(configs))
	var networkMonitor *windowsNetworkMonitor
	type interfaceError struct {
		name string
		err  error
	}
	errs := make(chan interfaceError)
	term := make(chan os.Signal, 1)
	deviceClosed := make(chan string, len(configs))

	for _, cfg := range configs {
		ri, err := startConfiguredInterface(cfg)
		if err != nil {
			logs.Error("启动接口 %s 失败: %v", cfg.InterfaceName, err)
			continue
		}
		running = append(running, ri)
		go func(name string, listener net.Listener, dev *device.Device) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					errs <- interfaceError{name: name, err: err}
					return
				}
				go dev.IpcHandle(conn)
			}
		}(ri.name, ri.uapi, ri.device)
		go func(name string, done <-chan struct{}) {
			<-done
			deviceClosed <- name
		}(ri.name, ri.device.Wait())
		logs.Notice("接口 %s 已启动", ri.name)
	}

	if len(running) == 0 {
		logs.Notice("当前没有成功启动的接口，进程将保持运行并等待终止信号")
	} else {
		var err error
		networkMonitor, err = startWindowsNetworkMonitor(func() {
			logs.Notice("检测到本地网络变化，开始刷新 WireGuard UDP 绑定")
			for _, ri := range running {
				if err := ri.device.HandleNetworkChange(); err != nil {
					logs.Error("接口 %s: 网络变化恢复失败: %v", ri.name, err)
					continue
				}
				logs.Notice("接口 %s: 网络变化恢复完成", ri.name)
			}
		})
		if err != nil {
			logs.Error("启动 Windows 网络变化监视失败: %v", err)
		} else {
			logs.Notice("Windows 网络变化监视已启动")
		}
	}

	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	shutdownReason := "未知原因"
	select {
	case <-term:
		shutdownReason = "收到终止信号"
	case ifaceErr := <-errs:
		shutdownReason = fmt.Sprintf("接口 %s 的 UAPI 监听退出: %v", ifaceErr.name, ifaceErr.err)
	case name := <-deviceClosed:
		shutdownReason = fmt.Sprintf("接口 %s 已退出", name)
	}

	logs.Notice("开始关闭，原因: %s", shutdownReason)
	if networkMonitor != nil {
		networkMonitor.Close()
		logs.Notice("Windows 网络变化监视已关闭")
	}
	for _, ri := range running {
		if ri.uapi != nil {
			ri.uapi.Close()
		}
		ri.device.Close()
		logs.Notice("接口 %s 已关闭", ri.name)
	}

	logs.Notice("正在关闭")
}
