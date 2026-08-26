package main

import (
	"fmt"

	logs "github.com/tea4go/gh/log4go"
)

func collectStartupParameterLines(foreground, daemon bool, confile string, level int) []string {
	return []string{
		"当前启动参数",
		fmt.Sprintf("= Foreground ....... %v", foreground),
		fmt.Sprintf("= Daemon ........... %v", daemon),
		fmt.Sprintf("= Confile .......... %s", confile),
		fmt.Sprintf("= LogLevel ......... %d", level),
	}
}

func collectStartupBannerLines(foreground, daemon bool, app, version string) []string {
	mode := "默认"
	if daemon {
		mode = "守护进程子进程"
	} else if foreground {
		mode = "前台"
	}
	return []string{
		"========================================",
		fmt.Sprintf("%s %s 启动", app, version),
		"运行模式: " + mode,
		"========================================",
	}
}

func logStartupParameters(foreground, daemon bool, confile string) {
	lines := collectStartupParameterLines(foreground, daemon, confile, logs.GetLevel("file"))
	logs.Notice(lines[0])
	for _, line := range lines[1:] {
		logs.Info(line)
	}
}

func logStartupBanner(foreground, daemon bool) {
	for _, line := range collectStartupBannerLines(foreground, daemon, appName, appVer) {
		logs.Notice(line)
	}
}
