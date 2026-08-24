package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

type systemCommand struct {
	exe  string
	args []string
}

func (c systemCommand) String() string {
	return c.exe + " " + strings.Join(c.args, " ")
}

type netshCommand struct {
	args []string
}

func (c netshCommand) String() string {
	return "netsh " + strings.Join(c.args, " ")
}

func buildNetshAddressCommands(interfaceName string, addresses []string) ([]netshCommand, []string) {
	commands := make([]netshCommand, 0, len(addresses))
	warnings := make([]string, 0)
	ipv4Configured := false
	ipv6Configured := false

	for _, raw := range addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("解析接口地址失败，已跳过 %q: %v", raw, err))
			continue
		}

		if prefix.Addr().Is4() {
			mask := prefixLengthToIPv4Mask(prefix.Bits())
			if mask == "" {
				warnings = append(warnings, fmt.Sprintf("不支持的 IPv4 前缀长度，已跳过 %q", raw))
				continue
			}

			command := netshCommand{
				args: []string{"interface", "ipv4", "add", "address", fmt.Sprintf(`name="%s"`, interfaceName), "address=" + prefix.Addr().String(), "mask=" + mask},
			}
			if !ipv4Configured {
				command.args = []string{"interface", "ipv4", "set", "address", fmt.Sprintf(`name="%s"`, interfaceName), "source=static", "address=" + prefix.Addr().String(), "mask=" + mask, "gateway=none"}
				ipv4Configured = true
			}
			commands = append(commands, command)
			continue
		}

		if prefix.Addr().Is6() {
			command := netshCommand{
				args: []string{"interface", "ipv6", "add", "address", fmt.Sprintf(`interface="%s"`, interfaceName), "address=" + prefix.String()},
			}
			if !ipv6Configured {
				command.args = []string{"interface", "ipv6", "set", "address", fmt.Sprintf(`interface="%s"`, interfaceName), "address=" + prefix.String()}
				ipv6Configured = true
			}
			commands = append(commands, command)
			continue
		}

		warnings = append(warnings, fmt.Sprintf("不支持的接口地址类型，已跳过 %q", raw))
	}

	return commands, warnings
}

func prefixLengthToIPv4Mask(bits int) string {
	if bits < 0 || bits > 32 {
		return ""
	}
	mask := net.CIDRMask(bits, 32)
	return net.IP(mask).String()
}

func applyInterfaceAddresses(interfaceName string, addresses []string) []string {
	commands, warnings := buildNetshAddressCommands(interfaceName, addresses)
	if len(commands) == 0 {
		if len(addresses) > 0 {
			warnings = append(warnings, fmt.Sprintf("[%s] 没有可应用的有效地址", interfaceName))
		}
		return warnings
	}

	for _, command := range commands {
		if err := runNetshCommand(command); err != nil {
			warnings = append(warnings, fmt.Sprintf("[%s] 地址命令执行失败: %s | %v", interfaceName, command.String(), err))
		}
	}
	return warnings
}

func buildDisableIPv6BindingCommand(interfaceName string) systemCommand {
	return systemCommand{
		exe: "powershell",
		args: []string{
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			fmt.Sprintf("Disable-NetAdapterBinding -Name '%s' -ComponentID 'ms_tcpip6' -Confirm:$false -ErrorAction Stop", escapePowerShellSingleQuotedString(interfaceName)),
		},
	}
}

func disableInterfaceIPv6(interfaceName string) error {
	return runSystemCommand(buildDisableIPv6BindingCommand(interfaceName))
}

func runNetshCommand(command netshCommand) error {
	return runSystemCommand(systemCommand{
		exe:  "netsh",
		args: append([]string(nil), command.args...),
	})
}

func runSystemCommand(command systemCommand) error {
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		output, err := exec.Command(command.exe, command.args...).CombinedOutput()
		if err == nil {
			return nil
		}

		message := strings.TrimSpace(string(output))
		if message != "" {
			lastErr = fmt.Errorf("%w; 输出: %s", err, message)
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}
	return lastErr
}

func escapePowerShellSingleQuotedString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
