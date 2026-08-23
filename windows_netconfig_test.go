package main

import (
	"reflect"
	"testing"
)

func TestBuildDisableIPv6BindingCommand(t *testing.T) {
	command := buildDisableIPv6BindingCommand("wgtun0")
	want := systemCommand{
		exe: "powershell",
		args: []string{
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			"Disable-NetAdapterBinding -Name 'wgtun0' -ComponentID 'ms_tcpip6' -Confirm:$false -ErrorAction Stop",
		},
	}
	if !reflect.DeepEqual(command, want) {
		t.Fatalf("unexpected command:\nwant=%#v\ngot=%#v", want, command)
	}
}

func TestBuildNetshAddressCommands(t *testing.T) {
	commands, warnings := buildNetshAddressCommands("wgtun0", []string{
		"192.168.189.160/24",
		"192.168.189.161/24",
		"fd00::10/64",
	})
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}

	want := []netshCommand{
		{
			args: []string{"interface", "ipv4", "set", "address", `name="wgtun0"`, "source=static", "address=192.168.189.160", "mask=255.255.255.0", "gateway=none"},
		},
		{
			args: []string{"interface", "ipv4", "add", "address", `name="wgtun0"`, "address=192.168.189.161", "mask=255.255.255.0"},
		},
		{
			args: []string{"interface", "ipv6", "set", "address", `interface="wgtun0"`, "address=fd00::10/64"},
		},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("unexpected commands:\nwant=%#v\ngot=%#v", want, commands)
	}
}

func TestBuildNetshAddressCommandsSkipsInvalidAddress(t *testing.T) {
	commands, warnings := buildNetshAddressCommands("wgtun0", []string{
		"not-a-prefix",
		"192.168.189.160/24",
	})
	if got, want := len(commands), 1; got != want {
		t.Fatalf("expected %d command, got %d", want, got)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warnings, got none")
	}
	if warnings[0] == "" {
		t.Fatal("expected non-empty warning")
	}
}
