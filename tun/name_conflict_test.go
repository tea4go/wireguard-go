package tun

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExplainLinuxTUNCreateErrorPreservesOtherErrors(t *testing.T) {
	createErr := errors.New("permission denied")
	err := explainLinuxTUNCreateError(t.TempDir(), "wgtun1", createErr)
	if err != createErr {
		t.Fatalf("expected original error, got %v", err)
	}
}

func TestExplainLinuxTUNCreateErrorPreservesEINVALForMissingInterface(t *testing.T) {
	err := explainLinuxTUNCreateError(t.TempDir(), "wgtun1", syscall.EINVAL)
	if err != syscall.EINVAL {
		t.Fatalf("expected original EINVAL, got %v", err)
	}
}

func TestExplainLinuxTUNCreateErrorPreservesEINVALForExistingTUN(t *testing.T) {
	sysClassNet := t.TempDir()
	interfaceDir := filepath.Join(sysClassNet, "wgtun1")
	if err := os.Mkdir(interfaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interfaceDir, "tun_flags"), []byte("0x1001\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := explainLinuxTUNCreateError(sysClassNet, "wgtun1", syscall.EINVAL)
	if err != syscall.EINVAL {
		t.Fatalf("expected original EINVAL, got %v", err)
	}
}

func TestExplainLinuxTUNCreateErrorPreservesEINVALForUnsafeName(t *testing.T) {
	sysClassNet := filepath.Join(t.TempDir(), "net")
	if err := os.Mkdir(sysClassNet, 0o755); err != nil {
		t.Fatal(err)
	}

	err := explainLinuxTUNCreateError(sysClassNet, "..", syscall.EINVAL)
	if err != syscall.EINVAL {
		t.Fatalf("expected original EINVAL, got %v", err)
	}
}

func TestExplainLinuxTUNCreateErrorPreservesEINVALForInvalidTUNFlags(t *testing.T) {
	for _, contents := range []string{"", "not-flags"} {
		t.Run(contents, func(t *testing.T) {
			sysClassNet := t.TempDir()
			interfaceDir := filepath.Join(sysClassNet, "wgtun1")
			if err := os.Mkdir(interfaceDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(interfaceDir, "tun_flags"), []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}

			err := explainLinuxTUNCreateError(sysClassNet, "wgtun1", syscall.EINVAL)
			if err != syscall.EINVAL {
				t.Fatalf("expected original EINVAL, got %v", err)
			}
		})
	}
}

func TestExplainLinuxTUNCreateErrorDescribesExistingTAP(t *testing.T) {
	sysClassNet := t.TempDir()
	interfaceDir := filepath.Join(sysClassNet, "wgtun1")
	if err := os.Mkdir(interfaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interfaceDir, "tun_flags"), []byte("0x1002\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := explainLinuxTUNCreateError(sysClassNet, "wgtun1", syscall.EINVAL)
	if !strings.Contains(err.Error(), "同名网络接口已存在且不是 TUN 设备") {
		t.Fatalf("expected TAP conflict diagnosis, got %v", err)
	}
}

func TestExplainLinuxTUNCreateErrorDescribesExistingNonTUN(t *testing.T) {
	sysClassNet := t.TempDir()
	if err := os.Mkdir(filepath.Join(sysClassNet, "wgtun1"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := explainLinuxTUNCreateError(sysClassNet, "wgtun1", syscall.EINVAL)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("expected wrapped EINVAL, got %v", err)
	}
	for _, want := range []string{
		`同名网络接口已存在且不是 TUN 设备`,
		`ip link delete dev <接口名>`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error %q to contain %q", err, want)
		}
	}
}

func TestExplainLinuxTUNCreateErrorDoesNotBuildShellCommandFromName(t *testing.T) {
	sysClassNet := t.TempDir()
	name := "wg$(touch pwn)"
	if err := os.Mkdir(filepath.Join(sysClassNet, name), 0o755); err != nil {
		t.Fatal(err)
	}

	err := explainLinuxTUNCreateError(sysClassNet, name, syscall.EINVAL)
	if strings.Contains(err.Error(), "ip link delete dev "+name) ||
		strings.Contains(err.Error(), `ip link delete dev "`+name) {
		t.Fatalf("error contains executable command built from interface name: %v", err)
	}
}
