package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetDefaultConfilePathOnWindowsUsesConfDirectory(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}

	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable: %v", err)
	}

	got := getDefaultConfilePath()
	want := filepath.Join(filepath.Dir(exePath), defaultConfileSubdirWindows)
	if got != want {
		t.Fatalf("expected default confile path %q, got %q", want, got)
	}
}
