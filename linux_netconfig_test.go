//go:build !windows

package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildLinuxNetworkCommands(t *testing.T) {
	got := buildLinuxNetworkCommands("wg-test", 1380, []string{"10.0.0.2/24", "fd00::2/64"})
	want := []systemCommand{
		{exe: "ip", args: []string{"link", "set", "dev", "wg-test", "mtu", "1380"}},
		{exe: "ip", args: []string{"address", "replace", "10.0.0.2/24", "dev", "wg-test"}},
		{exe: "ip", args: []string{"address", "replace", "fd00::2/64", "dev", "wg-test"}},
		{exe: "ip", args: []string{"link", "set", "dev", "wg-test", "up"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected commands:\nwant=%#v\ngot=%#v", want, got)
	}
}

func TestBuildLinuxNetworkCommandsWithoutOptionalSettings(t *testing.T) {
	got := buildLinuxNetworkCommands("wg-test", 0, nil)
	want := []systemCommand{{exe: "ip", args: []string{"link", "set", "dev", "wg-test", "up"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected commands:\nwant=%#v\ngot=%#v", want, got)
	}
}

func TestApplyLinuxNetworkConfigReportsCommandFailure(t *testing.T) {
	var commands []systemCommand
	warnings := applyLinuxNetworkConfigWithRunner("wg-test", 0, nil, func(command systemCommand) error {
		commands = append(commands, command)
		return errors.New("permission denied")
	})
	if len(commands) != 1 {
		t.Fatalf("expected one command, got %d", len(commands))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "permission denied") {
		t.Fatalf("expected permission warning, got %v", warnings)
	}
}
