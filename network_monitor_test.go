//go:build windows

package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRunDebouncedSignalLoopCoalescesBursts(t *testing.T) {
	changes := make(chan netChangeEvent, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	counts := make(chan int, 2)
	detailsCh := make(chan []string, 2)
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 40*time.Millisecond, func(changeCount int, details []string) {
			calls.Add(1)
			counts <- changeCount
			detailsCh <- details
		}, nil)
		close(done)
	}()

	changes <- netChangeEvent{kind: "IpInterface", notifyType: windows.MibAddInstance, ifIndex: 7, ifName: "IfIndex#7", family: windows.AF_INET}
	changes <- netChangeEvent{kind: "UnicastAddr", notifyType: windows.MibAddInstance, ifIndex: 7, ifName: "IfIndex#7", family: windows.AF_INET, address: "192.168.50.10/24"}
	changes <- netChangeEvent{kind: "UnicastAddr", notifyType: windows.MibDeleteInstance, ifIndex: 7, ifName: "IfIndex#7", family: windows.AF_INET6, address: "fe80::1/64"}
	time.Sleep(120 * time.Millisecond)

	close(stop)
	<-done

	if got, want := calls.Load(), int32(1); got != want {
		t.Fatalf("expected %d callback, got %d", want, got)
	}

	if got, want := <-counts, 3; got != want {
		t.Fatalf("expected change count %d, got %d", want, got)
	}
	details := <-detailsCh
	summary := formatNetChangeSummary(len(details), details)
	for _, want := range []string{
		"3 次系统通知",
		"IpInterface-Add@IfIndex#7(family=IPv4)",
		"UnicastAddr-Add@IfIndex#7(family=IPv4, addr=192.168.50.10/24)",
		"UnicastAddr-Del@IfIndex#7(family=IPv6, addr=fe80::1/64)",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected summary %q to contain %q", summary, want)
		}
	}
}

func TestRunDebouncedSignalLoopHandlesSeparatedEvents(t *testing.T) {
	changes := make(chan netChangeEvent, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 30*time.Millisecond, func(int, []string) {
			calls.Add(1)
		}, nil)
		close(done)
	}()

	changes <- netChangeEvent{kind: "IpInterface", notifyType: windows.MibAddInstance, ifIndex: 3, ifName: "IfIndex#3"}
	time.Sleep(80 * time.Millisecond)
	changes <- netChangeEvent{kind: "IpInterface", notifyType: windows.MibAddInstance, ifIndex: 3, ifName: "IfIndex#3"}
	time.Sleep(80 * time.Millisecond)

	close(stop)
	<-done

	if got, want := calls.Load(), int32(2); got != want {
		t.Fatalf("expected %d callbacks, got %d", want, got)
	}
}

func TestRunDebouncedSignalLoopIgnoresIpInterfaceParamOnly(t *testing.T) {
	changes := make(chan netChangeEvent, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 30*time.Millisecond, func(int, []string) {
			calls.Add(1)
		}, nil)
		close(done)
	}()

	changes <- netChangeEvent{kind: "IpInterface", notifyType: windows.MibParameterNotification, ifIndex: 9, ifName: "WLAN", family: windows.AF_INET}
	time.Sleep(80 * time.Millisecond)

	close(stop)
	<-done

	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no callback for IpInterface Param-only event, got %d", got)
	}
}

func TestRunDebouncedSignalLoopKeepsMeaningfulEventsWhenMixed(t *testing.T) {
	changes := make(chan netChangeEvent, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	counts := make(chan int, 2)
	detailsCh := make(chan []string, 2)
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 30*time.Millisecond, func(changeCount int, details []string) {
			calls.Add(1)
			counts <- changeCount
			detailsCh <- details
		}, nil)
		close(done)
	}()

	changes <- netChangeEvent{kind: "IpInterface", notifyType: windows.MibParameterNotification, ifIndex: 9, ifName: "WLAN", family: windows.AF_INET}
	changes <- netChangeEvent{kind: "UnicastAddr", notifyType: windows.MibAddInstance, ifIndex: 9, ifName: "WLAN", family: windows.AF_INET, address: "192.168.1.23/24"}
	time.Sleep(80 * time.Millisecond)

	close(stop)
	<-done

	if got, want := calls.Load(), int32(1); got != want {
		t.Fatalf("expected %d callback, got %d", want, got)
	}

	if got, want := <-counts, 1; got != want {
		t.Fatalf("expected change count %d, got %d", want, got)
	}
	details := <-detailsCh
	summary := formatNetChangeSummary(len(details), details)
	if strings.Contains(summary, "IpInterface-Param@WLAN") {
		t.Fatalf("expected summary to filter IpInterface Param noise, got %q", summary)
	}
	if !strings.Contains(summary, "UnicastAddr-Add@WLAN(family=IPv4, addr=192.168.1.23/24)") {
		t.Fatalf("expected summary to keep meaningful address change, got %q", summary)
	}
}

func TestFormatNetChangeSummary(t *testing.T) {
	summary := formatNetChangeSummary(4, []string{
		"IpInterface-Param@IfIndex#12(family=IPv4)",
		"UnicastAddr-Add@IfIndex#12(family=IPv4, addr=10.0.0.8/24)",
	})

	if !strings.Contains(summary, "4 次系统通知") {
		t.Fatalf("expected summary to include event count, got %q", summary)
	}
	if !strings.Contains(summary, "IpInterface-Param@IfIndex#12(family=IPv4)") {
		t.Fatalf("expected summary to include interface change detail, got %q", summary)
	}
	if !strings.Contains(summary, "UnicastAddr-Add@IfIndex#12(family=IPv4, addr=10.0.0.8/24)") {
		t.Fatalf("expected summary to include address detail, got %q", summary)
	}
}
