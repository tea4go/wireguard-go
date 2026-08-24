//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"

	logs "github.com/tea4go/gh/log4go"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// appVer 由构建系统通过 -ldflags "-X main.appVer=..." 方式注入版本号。
// 未注入时回退到编译时默认值 "0.0.1"。
var appVer string = "0.0.1"

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func printUsage() {
	fmt.Printf("用法: %s [-f/--foreground] <接口名称>\n", os.Args[0])
}

func printFullUsage() {
	exeName := os.Args[0]
	ver := appVer
	if ver == "" {
		ver = "(未注入)"
	}

	fmt.Printf("WireGuard-Go  用户态 WireGuard 守护进程\n")
	fmt.Printf("版本    : %s\n", ver)
	fmt.Printf("平台    : %s-%s\n\n", runtime.GOOS, runtime.GOARCH)

	fmt.Printf("使用方法:\n")
	fmt.Printf("  %s [选项...] <接口名称>\n\n", exeName)

	fmt.Printf("选项:\n")
	fmt.Printf("  -f, --foreground       前台模式：在当前终端直接运行，不启动守护子进程。\n")
	fmt.Printf("  -d, --daemon           (内部) 守护子进程标识，用户调用时请勿显式传入。\n")
	fmt.Printf("                         默认无参启动（且未使用 -f）会自动 fork 带 -d 的子进程。\n")
	fmt.Printf("  -q, --quit             停止当前正在运行的守护进程（通过 PID 文件匹配）。\n")
	fmt.Printf("  -S, --status           查看守护进程运行状态：PID、启动时间、运行时长。\n")
	fmt.Printf("  -h, --help             显示本帮助信息并退出。\n")
	fmt.Printf("      --version          显示版本信息并退出。\n\n")

	fmt.Printf("运行模式:\n")
	fmt.Printf("  1) 无 -f 直接调用: 父进程启动带 --daemon 的子进程后退出，\n")
	fmt.Printf("                      子进程写入 %s PID 文件并真正执行 VPN。\n", pidFileLinux)
	fmt.Printf("  2) -f/--foreground : 不 fork，在当前终端直接运行，不写 PID 文件。\n")
	fmt.Printf("  3) -q/--quit       : 读取 PID 文件，发送 SIGTERM 终止进程后删除 PID 文件。\n")
	fmt.Printf("  4) -S/--status     : 读取 PID 文件，通过 Signal(0) 探测存活并打印运行时长。\n\n")

	fmt.Printf("位置参数:\n")
	fmt.Printf("  接口名称               TUN 接口名。若系统已存在同名接口则直接复用，\n")
	fmt.Printf("                         否则由内核/驱动创建。\n\n")

	fmt.Printf("环境变量 / 通用 log4go 参数:\n")
	fmt.Printf("  log_level (或 -l 数值)   日志级别 (0-7, 数字越大越详细, 默认 5=Notice)\n")
	fmt.Printf("                              0 emergency   => LogLevelEmergency\n")
	fmt.Printf("                              1 alert       => LogLevelAlert\n")
	fmt.Printf("                              2 critical    => LogLevelCritical\n")
	fmt.Printf("                              3 error       => LogLevelError\n")
	fmt.Printf("                              4 warning     => LogLevelWarning\n")
	fmt.Printf("                              5 notice      => LogLevelNotice (默认)\n")
	fmt.Printf("                              6 info        => LogLevelInfo\n")
	fmt.Printf("                              7 debug       => LogLevelVerbose\n")
	fmt.Printf("  WG_TUN_FD                 (内部) 父进程传递已打开的 TUN 文件描述符。\n")
	fmt.Printf("  WG_UAPI_FD                (内部) 父进程传递已打开的 UAPI socket 文件描述符。\n")
	fmt.Printf("  WG_PROCESS_FOREGROUND=1   等效于 -f，前台模式。\n")
	fmt.Printf("  log_server                远程日志服务器 host:port，透传给守护子进程。\n")
	fmt.Printf("  log_name (-N)             日志文件名标识，透传给守护子进程。\n\n")

	fmt.Printf("示例:\n")
	fmt.Printf("  %s wg0                                   # 自动守护模式启动接口 wg0\n", exeName)
	fmt.Printf("  %s -f wg0                                # 前台模式启动接口 wg0\n", exeName)
	fmt.Printf("  log_level=6 %s -f wg0                    # 日志级别=Info + 前台运行\n", exeName)
	fmt.Printf("  %s -l 7 -f wg0                           # 通过 -l flag 设置日志级别=Debug/Verbose\n", exeName)
	fmt.Printf("  %s -S                                    # 查看守护状态\n", exeName)
	fmt.Printf("  %s -q                                    # 停止守护进程\n\n", exeName)

	fmt.Printf("更多信息: https://www.wireguard.com/\n")
	fmt.Printf("版权所有 (C) Jason A. Donenfeld <jason@zx2c4.com>.\n")
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   Running wireguard-go is not required because this  │")
	fmt.Fprintln(os.Stderr, "│   kernel has first class support for WireGuard. For  │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,       │")
	fmt.Fprintln(os.Stderr, "│   please visit:                                      │")
	fmt.Fprintln(os.Stderr, "│         https://www.wireguard.com/install/           │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "-h", "--help":
			printFullUsage()
			return
		case "--version":
			ver := appVer
			fmt.Printf("wireguard-go %s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <jason@zx2c4.com>.\n", ver, runtime.GOOS, runtime.GOARCH)
			return
		}
	}
	warning()

	pforeground := flag.BoolP("foreground", "f", false, "前台运行（不启动守护进程）")
	pdaemon := flag.BoolP("daemon", "d", false, "(内部) 守护子进程模式，用户请省略本参数")
	pquit := flag.BoolP("quit", "q", false, "停止正在运行的守护进程")
	pstatus := flag.BoolP("status", "S", false, "查看守护进程运行状态")

	flag.Usage = func() {
		printFullUsage()
	}
	_ = flag.CommandLine.MarkHidden("daemon")
	flag.Parse()

	foreground := *pforeground
	isDaemon := *pdaemon

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

	var interfaceName string
	remainingArgs := flag.Args()
	if len(remainingArgs) != 1 {
		printUsage()
		return
	}
	interfaceName = remainingArgs[0]

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	levelStr := ""
	lvNum := logs.GetParamInt("log_level", 5)
	levelStr = fmt.Sprintf("log_level=%d", lvNum)
	fmt.Fprintf(os.Stderr, "启动参数: foreground=%v daemon=%v iface=%s %s\n", foreground, isDaemon, interfaceName, levelStr)

	if !foreground && !isDaemon {
		daemonMgr := NewDaemonManager()
		extraEnv := map[string]string{}
		if ls := os.Getenv("log_server"); ls != "" {
			extraEnv["log_server"] = ls
		}
		if ln := os.Getenv("log_name"); ln != "" {
			extraEnv["log_name"] = ln
		}
		if lv := os.Getenv("log_level"); lv != "" {
			extraEnv["log_level"] = lv
		}
		if err := daemonMgr.StartDaemon(extraEnv); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(ExitSetupFailed)
		}
		return
	}

	if isDaemon {
		daemonMgr := NewDaemonManager()
		if err := daemonMgr.WritePidFile(); err != nil {
			fmt.Fprintf(os.Stderr, "写入PID文件失败: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
		defer daemonMgr.RemovePidFile()
	}

	log4goLevel := logs.GetParamInt("log_level", 5)
	if log4goLevel < 0 {
		log4goLevel = 5
	}
	if log4goLevel > 7 {
		log4goLevel = 7
	}
	logLevel := log4goLevel + 1

	// open TUN device (or use supplied fd)
	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd
		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	ver := appVer
	logger.Verbosef("启动 wireguard-go 版本 %s", ver)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go dev.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-dev.Wait():
	}

	uapi.Close()
	dev.Close()

	logger.Verbosef("Shutting down")
}
