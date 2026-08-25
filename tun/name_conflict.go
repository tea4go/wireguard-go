package tun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	linuxIFFTUN = 0x0001
	linuxIFFTAP = 0x0002
)

func explainLinuxTUNCreateError(sysClassNet, name string, createErr error) error {
	if !errors.Is(createErr, syscall.EINVAL) ||
		name == "." ||
		name == ".." ||
		strings.Contains(name, "/") {
		return createErr
	}

	interfacePath := filepath.Join(sysClassNet, name)
	tunFlags, err := os.ReadFile(filepath.Join(interfacePath, "tun_flags"))
	if err == nil {
		flags, parseErr := strconv.ParseUint(strings.TrimSpace(string(tunFlags)), 0, 16)
		if parseErr != nil {
			return createErr
		}
		if flags&(linuxIFFTUN|linuxIFFTAP) == linuxIFFTUN {
			return createErr
		}
	} else if !os.IsNotExist(err) {
		return createErr
	} else if _, statErr := os.Stat(interfacePath); statErr != nil {
		return createErr
	}

	return fmt.Errorf(
		"创建 TUN 设备 %q 失败：同名网络接口已存在且不是 TUN 设备；请先停止冲突服务，确认接口可删除后执行 ip link delete dev <接口名>，或重命名配置文件: %w",
		name,
		createErr,
	)
}
