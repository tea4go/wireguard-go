//go:build !windows

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
	"strings"

	flag "github.com/spf13/pflag"
	logs "github.com/tea4go/gh/log4go"
	"github.com/tea4go/gh/network"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

var appName = "WireGuard"
var appVer = "0.0.1"
var IsBeta = ""
var BuildTime = ""

func printUsage() {
	fmt.Fprintf(os.Stderr, "用法: %s [-c <配置文件.conf|配置包.zip|配置目录>]\n", filepath.Base(os.Args[0]))
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

	fmt.Printf("WireGuard-Go 用户态 WireGuard 守护进程\n")
	fmt.Printf("版本    : %s\n", ver)
	fmt.Printf("构建时间: %s\n", buildTime)
	fmt.Printf("平台    : %s-%s\n\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("使用方法:\n  %s [-c <配置文件.conf|配置包.zip|配置目录>] [其它选项]\n\n", exeName)
	fmt.Printf("选项:\n")
	fmt.Printf("  -c, --confile <路径>   指定配置来源（.conf、.zip 或目录）。\n")
	fmt.Printf("  -f, --foreground       前台运行。\n")
	fmt.Printf("  -q, --quit             停止守护进程。\n")
	fmt.Printf("  -S, --status           查看守护进程状态。\n")
	fmt.Printf("      --sync-provider    配置同步提供方：github 或 gitee。\n")
	fmt.Printf("      --sync-action      配置同步动作：upload 或 download。\n")
	fmt.Printf("      --sync-token       私有 Gist 访问令牌。\n")
	fmt.Printf("      --sync-gist-id     远端 Gist/代码片段 ID。\n")
	fmt.Printf("      --sync-file        指定下载的远端备份文件名。\n")
	fmt.Printf("      --sync <路径>      从 JSON5 配置文件执行同步。\n")
	fmt.Printf("  -h, --help             显示帮助。\n")
	fmt.Printf("      --version          显示版本。\n\n")
	fmt.Printf("环境变量:\n")
	fmt.Printf("  confile                等效于 --confile，命令行优先。\n")
	fmt.Printf("  log_level              日志级别 0-7。\n")
	fmt.Printf("  log_name               日志文件名标识。\n")
	fmt.Printf("  log_server             远程日志服务器 host:port。\n\n")
	fmt.Printf("示例:\n")
	fmt.Printf("  %s -c /etc/wireguard/wgtun.conf\n", exeName)
	fmt.Printf("  %s --confile /etc/wireguard\n", exeName)
	fmt.Printf("  confile=/etc/wireguard %s -f\n", exeName)
	fmt.Printf("  %s --sync-provider github --sync-action upload --sync-token <token> -c /etc/wireguard\n", exeName)
	fmt.Printf("  %s --sync ./example.json5\n", exeName)
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
	default:
		return
	}
	fmt.Fprintln(os.Stderr, "提示: 当前内核可能已原生支持 WireGuard；仅在需要 userspace 实现时运行 wireguard-go。")
}

type runningInterface struct {
	name   string
	device *device.Device
	uapi   net.Listener
}

func startConfiguredInterface(cfg *tunnelConfig) (*runningInterface, error) {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	logger := device.NewLogger(logs.GetLevel("file"), fmt.Sprintf("(%s) ", cfg.InterfaceName))
	tunDevice, err := tun.CreateTUN(cfg.InterfaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备失败, %w", err)
	}
	interfaceName := cfg.InterfaceName
	if realName, nameErr := tunDevice.Name(); nameErr == nil {
		interfaceName = realName
	}
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)
	if cfg.UAPI != "" {
		if err := dev.IpcSet(cfg.UAPI); err != nil {
			dev.Close()
			return nil, fmt.Errorf("应用配置失败, %w", err)
		}
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("启动设备失败, %w", err)
	}
	for _, message := range applyLinuxNetworkConfig(interfaceName, cfg.MTU, cfg.Addresses) {
		logs.Warning(message)
	}
	fileUAPI, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("打开 UAPI socket 失败, %w", err)
	}
	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	fileUAPI.Close()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("UAPI 监听失败, %w", err)
	}
	return &runningInterface{name: interfaceName, device: dev, uapi: uapi}, nil
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help":
			printFullUsage()
			return
		case "--version":
			buildTime := BuildTime
			if buildTime == "" {
				buildTime = "-"
			}
			fmt.Printf("%s %s\n  Build Time : %s\n  Platform   : %s-%s\n", appName, appVer, buildTime, runtime.GOOS, runtime.GOARCH)
			return
		}
	}

	pconfile := flag.StringP("confile", "c", "", "配置文件")
	pforeground := flag.BoolP("foreground", "f", false, "前台运行")
	pquit := flag.BoolP("quit", "q", false, "停止守护进程")
	pstatus := flag.BoolP("status", "S", false, "查看守护进程状态")
	pdaemon := flag.BoolP("daemon", "d", false, "内部守护子进程模式")
	psyncProvider := flag.String("sync-provider", "", "配置同步提供方")
	psyncAction := flag.String("sync-action", "", "配置同步动作")
	psyncToken := flag.String("sync-token", "", "配置同步访问令牌")
	psyncGistID := flag.String("sync-gist-id", "", "远端 Gist ID")
	psyncFile := flag.String("sync-file", "", "同步备份文件名")
	psyncConfig := flag.String("sync", "", "从 JSON5 配置执行同步")
	flag.Usage = printFullUsage
	_ = flag.CommandLine.MarkHidden("daemon")
	flag.Parse()

	syncConfile := strings.TrimSpace(*pconfile)
	if syncConfile == "" {
		syncConfile = strings.TrimSpace(os.Getenv("confile"))
	}
	if strings.TrimSpace(*psyncConfig) != "" {
		if flag.NArg() != 0 {
			printUsage()
			fmt.Fprintln(os.Stderr, "错误: 同步模式下不支持额外的位置参数")
			os.Exit(ExitSetupFailed)
		}
		cfg, err := loadSyncConfig(*psyncConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取同步配置失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		cfg = applySyncConfigOverrides(cfg, *psyncProvider, *psyncAction, *psyncToken, *psyncGistID, syncConfile, *psyncFile)
		if err := runSyncCommand(os.Stdout, cfg.Provider, cfg.Action, cfg.Path, cfg.Token, cfg.GistID, cfg.RemoteFile); err != nil {
			fmt.Fprintf(os.Stderr, "配置同步失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		return
	}
	if strings.TrimSpace(*psyncProvider) != "" || strings.TrimSpace(*psyncAction) != "" {
		if flag.NArg() != 0 {
			printUsage()
			fmt.Fprintln(os.Stderr, "错误: 同步模式下不支持额外的位置参数")
			os.Exit(ExitSetupFailed)
		}
		if err := runSyncCommand(os.Stdout, *psyncProvider, *psyncAction, syncConfile, *psyncToken, *psyncGistID, *psyncFile); err != nil {
			fmt.Fprintf(os.Stderr, "配置同步失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		return
	}

	confile := logs.GetParamString("confile", *pconfile, getDefaultConfilePath())
	logName := os.Getenv("log_name")
	if logName == "" {
		logName = appName
	}
	network.SetAppVersion(appName, appVer, IsBeta, BuildTime)
	logs.SetLogFuncCallDepth(5)
	logs.SetLogger("file", `{"filename":"`+filepath.Join(os.TempDir(), "ulog_"+logName+".txt")+`", "perm": "0666","level":5}`)
	logs.StartLogger()
	network.StartSelfUpdate("http://wc192.yj2025.icu:8118", "http://nj.yj2025.icu:23432", "http://wc8.yj2025.icu:8118", "http://wc47.yj2025.icu:23431")

	daemonMgr := NewDaemonManager()
	if *pquit {
		if err := daemonMgr.StopDaemon(); err != nil {
			fmt.Printf("停止守护进程失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		return
	}
	if *pstatus {
		if daemonMgr.IsRunning() {
			pid, startTime, duration, err := daemonMgr.GetRunningInfo()
			if err != nil {
				fmt.Printf("守护进程正在运行，但获取信息失败: %v\n", err)
			} else {
				fmt.Printf("守护进程正在运行\n  PID:       %d\n  启动时间: %s\n  运行时长: %s\n", pid, startTime.Format("2006-01-02(15:04:05)"), FormatDuration(duration))
			}
		} else {
			fmt.Println("守护进程未运行")
		}
		return
	}
	if flag.NArg() != 0 {
		printUsage()
		fmt.Fprintln(os.Stderr, "错误: 不支持直接传接口名称，请使用 -c/--confile")
		os.Exit(ExitSetupFailed)
	}
	if !*pforeground && !*pdaemon {
		extraEnv := map[string]string{}
		for _, key := range []string{"log_level", "log_server"} {
			if value := os.Getenv(key); value != "" {
				extraEnv[key] = value
			}
		}
		extraEnv["log_name"] = appName + "_daemon"
		if value := os.Getenv("log_name"); value != "" {
			extraEnv["log_name"] = value
		}
		if err := daemonMgr.StartDaemon(extraEnv); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(ExitSetupFailed)
		}
		return
	}
	if *pdaemon {
		if err := daemonMgr.WritePidFile(); err != nil {
			logs.Error("写入PID文件失败: %v", err)
			os.Exit(ExitSetupFailed)
		}
		defer daemonMgr.RemovePidFile()
	}

	warning()
	configs, warnings := loadTunnelConfigs(confile)
	for _, message := range warnings {
		logs.Warning(message)
	}
	if len(configs) == 0 {
		logs.Error("配置来源中没有有效接口: %s", confile)
		os.Exit(ExitSetupFailed)
	}

	type interfaceEvent struct {
		name string
		err  error
	}
	running := make([]*runningInterface, 0, len(configs))
	events := make(chan interfaceEvent, len(configs)*2)
	closing := make(chan struct{})
	for _, cfg := range configs {
		logs.Notice("加载配置文件 %s", cfg.Source)
		ri, err := startConfiguredInterface(cfg)
		if err != nil {
			logs.Error("启动接口 %s 失败, %v", cfg.InterfaceName, err)
			continue
		}
		running = append(running, ri)
		go func(ri *runningInterface) {
			for {
				connection, err := ri.uapi.Accept()
				if err != nil {
					select {
					case <-closing:
					case events <- interfaceEvent{name: ri.name, err: err}:
					}
					return
				}
				go ri.device.IpcHandle(connection)
			}
		}(ri)
		go func(ri *runningInterface) {
			<-ri.device.Wait()
			select {
			case <-closing:
			case events <- interfaceEvent{name: ri.name}:
			}
		}(ri)
		logs.Notice("接口 %s 已启动", ri.name)
	}
	if len(running) == 0 {
		logs.Warning("当前没有成功启动的接口，进程将保持运行并等待终止信号")
	}

	var networkMonitor hostNetworkMonitor
	if len(running) > 0 {
		excluded := make(map[int]string, len(running))
		for _, ri := range running {
			iface, err := net.InterfaceByName(ri.name)
			if err == nil {
				excluded[iface.Index] = ri.name
			}
		}
		var monitorErr error
		networkMonitor, monitorErr = startHostNetworkMonitor(func(changeCount int, details []string) {
			logs.Notice("检测到本地网络变化(%d 个事件)，开始刷新 WireGuard UDP 绑定", changeCount)
			for _, ri := range running {
				if err := ri.device.HandleNetworkChange(); err != nil {
					logs.Error("[%s] 网络变化恢复失败: %v", ri.name, err)
					continue
				}
				logs.Notice("[%s] 网络变化恢复完成", ri.name)
			}
		}, excluded)
		if monitorErr != nil {
			logs.Error("%s 网络变化监视启动失败: %v", runtime.GOOS, monitorErr)
		}
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, unix.SIGTERM)
	shutdownReason := "收到终止信号"
	select {
	case <-term:
	case event := <-events:
		if event.err != nil {
			shutdownReason = fmt.Sprintf("接口 %s 的 UAPI 监听退出: %v", event.name, event.err)
		} else {
			shutdownReason = fmt.Sprintf("接口 %s 已退出", event.name)
		}
	}
	logs.Notice("开始关闭，原因: %s", shutdownReason)
	if networkMonitor != nil {
		networkMonitor.Close()
		logs.Notice("%s 网络变化监视已关闭", runtime.GOOS)
	}
	close(closing)
	for _, ri := range running {
		ri.uapi.Close()
	}
	for _, ri := range running {
		ri.device.Close()
		logs.Notice("接口 %s 已关闭", ri.name)
	}
}
