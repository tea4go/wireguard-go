package main

import (
	"sync/atomic"
	"testing"
	"time"
)

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
