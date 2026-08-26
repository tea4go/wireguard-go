package main

import (
	"reflect"
	"testing"
)

func TestCollectStartupParameterLines(t *testing.T) {
	got := collectStartupParameterLines(true, false, `C:\MyWork\GitCode\wireguard-go\conf`, 6)
	want := []string{
		"当前启动参数",
		"= Foreground ....... true",
		"= Daemon ........... false",
		"= Confile .......... C:\\MyWork\\GitCode\\wireguard-go\\conf",
		"= LogLevel ......... 6",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestCollectStartupBannerLines(t *testing.T) {
	got := collectStartupBannerLines(false, true, "WireGuard", "v3.9.0")
	want := []string{
		"========================================",
		"WireGuard v3.9.0 启动",
		"运行模式: 守护进程子进程",
		"========================================",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
