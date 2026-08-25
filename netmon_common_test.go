package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testHostNetworkMonitor struct{}

func (testHostNetworkMonitor) Close() {}

func TestStopHostNetworkMonitorReportsFirstStopOnly(t *testing.T) {
	stop := make(chan struct{})
	var stopOnce sync.Once
	if !stopHostNetworkMonitor(&stopOnce, stop) {
		t.Fatal("expected first stop request to report ownership")
	}
	select {
	case <-stop:
	default:
		t.Fatal("expected first stop request to close stop channel")
	}
	if stopHostNetworkMonitor(&stopOnce, stop) {
		t.Fatal("expected later stop request to report existing stop")
	}
}

func TestHostNetworkMonitorStartStatus(t *testing.T) {
	startErr := errors.New("socket failed")
	for _, test := range []struct {
		name        string
		goos        string
		monitor     hostNetworkMonitor
		err         error
		wantMessage string
		wantError   bool
	}{
		{
			name:        "started",
			goos:        "linux",
			monitor:     testHostNetworkMonitor{},
			wantMessage: "linux 网络变化监视已启动",
		},
		{
			name:        "unsupported",
			goos:        "freebsd",
			wantMessage: "freebsd 不支持网络变化监视，继续运行",
		},
		{
			name:        "failed",
			goos:        "darwin",
			err:         startErr,
			wantMessage: "darwin 网络变化监视启动失败: socket failed",
			wantError:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message, isError := hostNetworkMonitorStartStatus(test.goos, test.monitor, test.err)
			if message != test.wantMessage {
				t.Fatalf("expected message %q, got %q", test.wantMessage, message)
			}
			if isError != test.wantError {
				t.Fatalf("expected error status %t, got %t", test.wantError, isError)
			}
		})
	}
}

func TestRunHostNetworkChangeLoopCoalescesBurst(t *testing.T) {
	events := make(chan hostNetworkEvent, 4)
	stop := make(chan struct{})
	done := make(chan struct{})
	counts := make(chan int, 1)
	details := make(chan []string, 1)

	go func() {
		runHostNetworkChangeLoop(events, stop, 30*time.Millisecond, nil, func(count int, eventDetails []string) {
			counts <- count
			details <- eventDetails
		})
		close(done)
	}()

	events <- hostNetworkEvent{kind: hostNetworkEventLink, ifIndex: 7, detail: "Link@if#7"}
	events <- hostNetworkEvent{kind: hostNetworkEventAddress, ifIndex: 7, detail: "Address@if#7"}

	select {
	case got := <-counts:
		if got != 2 {
			t.Fatalf("expected 2 coalesced events, got %d", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for callback")
	}
	if got := <-details; len(got) != 2 {
		t.Fatalf("expected 2 event details, got %d", len(got))
	}

	close(stop)
	<-done
}

func TestRunHostNetworkChangeLoopSeparatesEvents(t *testing.T) {
	events := make(chan hostNetworkEvent, 2)
	stop := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32

	go func() {
		runHostNetworkChangeLoop(events, stop, 25*time.Millisecond, nil, func(int, []string) {
			calls.Add(1)
		})
		close(done)
	}()

	events <- hostNetworkEvent{kind: hostNetworkEventRoute, detail: "Route"}
	time.Sleep(75 * time.Millisecond)
	events <- hostNetworkEvent{kind: hostNetworkEventRoute, detail: "Route"}
	time.Sleep(75 * time.Millisecond)

	close(stop)
	<-done
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 callbacks, got %d", got)
	}
}

func TestRunHostNetworkChangeLoopStopsWithoutCallback(t *testing.T) {
	events := make(chan hostNetworkEvent, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32

	go func() {
		runHostNetworkChangeLoop(events, stop, 30*time.Millisecond, nil, func(int, []string) {
			calls.Add(1)
		})
		close(done)
	}()

	events <- hostNetworkEvent{kind: hostNetworkEventRoute, detail: "Route"}
	close(stop)
	<-done
	time.Sleep(50 * time.Millisecond)

	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no callback after stop, got %d", got)
	}
}

func TestHostNetworkEventFiltersExcludedInterface(t *testing.T) {
	excluded := map[int]string{9: "wgtun0"}

	for _, event := range []hostNetworkEvent{
		{kind: hostNetworkEventLink, ifIndex: 9},
		{kind: hostNetworkEventAddress, ifIndex: 9},
	} {
		if event.actionable(excluded) {
			t.Fatalf("expected event kind %d for excluded interface to be ignored", event.kind)
		}
	}

	if event := (hostNetworkEvent{kind: hostNetworkEventRoute, ifIndex: 9}); !event.actionable(excluded) {
		t.Fatal("expected route event to remain actionable")
	}
}

func TestEnqueueHostNetworkEventKeepsPendingRecoveryWhenFull(t *testing.T) {
	events := make(chan hostNetworkEvent, 1)
	first := hostNetworkEvent{kind: hostNetworkEventLink, ifIndex: 2, detail: "Link@if#2"}
	second := hostNetworkEvent{kind: hostNetworkEventRoute, detail: "Route"}

	enqueueHostNetworkEvent(events, first)
	enqueueHostNetworkEvent(events, second)

	if len(events) != 1 {
		t.Fatalf("expected one pending recovery event, got %d", len(events))
	}
	if got := <-events; got != first {
		t.Fatalf("expected existing pending event to remain, got %#v", got)
	}
}
