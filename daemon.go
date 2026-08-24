package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	execplus "github.com/tea4go/gh/execplus"
	logs "github.com/tea4go/gh/log4go"
)

const (
	pidFileLinux   = "/var/run/wireguard-go.pid"
	pidFileWindows = "wireguard-go.pid"

	defaultConfileName                  = "wgtun.conf"
	defaultConfileDirLinux              = "/etc/wireguard"
	defaultConfileDirDarwinIntel        = "/usr/local/etc/wireguard"
	defaultConfileDirDarwinAppleSilicon = "/opt/homebrew/etc/wireguard"
	defaultConfileSubdirWindows         = "conf"
)

type DaemonManager struct {
	pidFile string
}

func NewDaemonManager() *DaemonManager {
	return &DaemonManager{
		pidFile: getPidFilePath(),
	}
}

func getPidFilePath() string {
	if runtime.GOOS == "windows" {
		exePath, _ := os.Executable()
		exeDir := filepath.Dir(exePath)
		return filepath.Join(exeDir, pidFileWindows)
	}
	return pidFileLinux
}

func getDefaultConfilePath() string {
	if runtime.GOOS == "windows" {
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			return filepath.Join(exeDir, defaultConfileSubdirWindows)
		}
		return defaultConfileSubdirWindows
	}
	if runtime.GOOS == "darwin" {
		confileDir := defaultConfileDirDarwinAppleSilicon
		if runtime.GOARCH == "amd64" {
			confileDir = defaultConfileDirDarwinIntel
		}
		if _, err := os.Stat(filepath.Join(confileDir, defaultConfileName)); err == nil {
			return filepath.Join(confileDir, defaultConfileName)
		}
		altDir := defaultConfileDirDarwinIntel
		if runtime.GOARCH == "amd64" {
			altDir = defaultConfileDirDarwinAppleSilicon
		}
		if _, err := os.Stat(filepath.Join(altDir, defaultConfileName)); err == nil {
			return filepath.Join(altDir, defaultConfileName)
		}
		return filepath.Join(confileDir, defaultConfileName)
	}
	return filepath.Join(defaultConfileDirLinux, defaultConfileName)
}

func FormatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%d天%d小时%d分钟%d秒", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%d小时%d分钟%d秒", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d分钟%d秒", minutes, seconds)
	}
	return fmt.Sprintf("%d秒", seconds)
}

func (dm *DaemonManager) StartDaemon(extraEnv map[string]string) error {
	if dm.IsRunning() {
		return fmt.Errorf("守护进程已在运行")
	}

	var err error
	if runtime.GOOS == "windows" {
		err = startDaemonWindows(extraEnv)
	} else {
		err = startDaemonLinux(extraEnv)
	}

	return err
}

func startDaemonLinux(extraEnv map[string]string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败，%v", err)
	}

	newArgs := []string{"--daemon"}
	newArgs = append(newArgs, os.Args[1:]...)
	cmd := execplus.Command(exePath, newArgs...)
	for k, v := range extraEnv {
		cmd.SetEnv(k, v)
	}
	logs.Info("启动守护子进程 %v", cmd.String())
	for k, v := range extraEnv {
		logs.Info("= env %s : %v", k, v)
	}

	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动子进程失败，%v", err)
	}

	os.Exit(0)
	return nil
}

func startDaemonWindows(extraEnv map[string]string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败，%v", err)
	}

	newArgs := []string{"--daemon"}
	newArgs = append(newArgs, os.Args[1:]...)
	cmd := execplus.Command(exePath, newArgs...)
	for k, v := range extraEnv {
		cmd.SetEnv(k, v)
	}
	logs.Info("启动守护子进程 %v", cmd.String())
	for k, v := range extraEnv {
		logs.Info("= env %s : %v", k, v)
	}

	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	setDaemonSysProcAttr(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动子进程失败，%v", err)
	}

	fmt.Printf("WireGuard-Go 守护进程已启动 (PID: %d)\n", cmd.Process.Pid)

	os.Exit(0)
	return nil
}

func daemonInit() {
	if runtime.GOOS == "windows" {
		return
	}
}

func (dm *DaemonManager) IsRunning() bool {
	logs.Debug("检测守护进程是否已运行 ...... File = %s", dm.pidFile)
	data, err := os.ReadFile(dm.pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return false
	}

	logs.Debug("检测守护进程是否已运行 ...... PID = %d", pid)
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid))
		output, err := cmd.Output()
		if err != nil {
			logs.Warning("检查进程是否存在失败(%s)，%v", cmd.String(), err)
			return false
		}
		ok := strings.Contains(string(output), fmt.Sprintf("%d", pid))
		logs.Debug("检测守护进程是否已运行 ...... %v", ok)
		return ok
	}

	err = process.Signal(syscall.Signal(0))
	if err != nil {
		logs.Warning("检查进程是否存在失败，%v", err)
		return false
	}
	return true
}

func (dm *DaemonManager) WritePidFile() error {
	pid := os.Getpid()
	if err := os.WriteFile(dm.pidFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("写入PID文件失败，%v", err)
	}
	logs.Debug("守护进程PID: %d (文件: %s)", pid, dm.pidFile)
	return nil
}

func (dm *DaemonManager) RemovePidFile() error {
	return os.Remove(dm.pidFile)
}

func (dm *DaemonManager) GetPid() (int, error) {
	data, err := os.ReadFile(dm.pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("解析PID失败，%v", err)
	}
	return pid, nil
}

func (dm *DaemonManager) GetStartTime() (time.Time, error) {
	info, err := os.Stat(dm.pidFile)
	if err != nil {
		return time.Time{}, fmt.Errorf("获取PID文件信息失败，%v", err)
	}
	return info.ModTime(), nil
}

func (dm *DaemonManager) GetRunningDuration() (time.Duration, error) {
	startTime, err := dm.GetStartTime()
	if err != nil {
		return 0, err
	}
	return time.Since(startTime), nil
}

func (dm *DaemonManager) GetRunningInfo() (pid int, startTime time.Time, duration time.Duration, err error) {
	pid, err = dm.GetPid()
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	startTime, err = dm.GetStartTime()
	if err != nil {
		return 0, time.Time{}, 0, err
	}
	duration = time.Since(startTime)
	return pid, startTime, duration, nil
}

func (dm *DaemonManager) StopDaemon() error {
	if !dm.IsRunning() {
		return fmt.Errorf("守护进程未运行")
	}
	pid, err := dm.GetPid()
	if err != nil {
		return fmt.Errorf("获取PID失败，%v", err)
	}

	logs.Debug("正在停止守护进程  ...... (PID: %d)", pid)

	if runtime.GOOS == "windows" {
		err = stopDaemonWindows(pid)
	} else {
		err = stopDaemonLinux(pid)
	}

	if err != nil {
		return fmt.Errorf("停止守护进程失败，%v", err)
	}

	if err := dm.RemovePidFile(); err != nil {
		logs.Warning("删除PID文件失败，%v", err)
	}

	logs.Info("守护进程已停止")
	return nil
}

func stopDaemonLinux(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("找不到进程: %v", err)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送终止信号失败，%v", err)
	}
	return nil
}

func stopDaemonWindows(pid int) error {
	cmd := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("执行taskkill失败，%v", err)
	}
	return nil
}
