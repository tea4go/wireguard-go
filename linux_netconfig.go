//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type systemCommand struct {
	exe  string
	args []string
}

func (c systemCommand) String() string {
	return c.exe + " " + strings.Join(c.args, " ")
}

func buildLinuxNetworkCommands(interfaceName string, mtu int, addresses []string) []systemCommand {
	commands := make([]systemCommand, 0, len(addresses)+2)
	if mtu > 0 {
		commands = append(commands, systemCommand{
			exe:  "ip",
			args: []string{"link", "set", "dev", interfaceName, "mtu", strconv.Itoa(mtu)},
		})
	}
	for _, address := range addresses {
		commands = append(commands, systemCommand{
			exe:  "ip",
			args: []string{"address", "replace", address, "dev", interfaceName},
		})
	}
	return append(commands, systemCommand{
		exe:  "ip",
		args: []string{"link", "set", "dev", interfaceName, "up"},
	})
}

func applyLinuxNetworkConfig(interfaceName string, mtu int, addresses []string) []string {
	return applyLinuxNetworkConfigWithRunner(interfaceName, mtu, addresses, runLinuxSystemCommand)
}

func applyLinuxNetworkConfigWithRunner(interfaceName string, mtu int, addresses []string, run func(systemCommand) error) []string {
	var warnings []string
	for _, command := range buildLinuxNetworkCommands(interfaceName, mtu, addresses) {
		if err := run(command); err != nil {
			warnings = append(warnings, fmt.Sprintf("[%s] 网络配置命令执行失败: %s | %v", interfaceName, command.String(), err))
		}
	}
	return warnings
}

func runLinuxSystemCommand(command systemCommand) error {
	output, err := exec.Command(command.exe, command.args...).CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message != "" {
		return fmt.Errorf("%w; 输出: %s", err, message)
	}
	return err
}
