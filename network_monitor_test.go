package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRunDebouncedSignalLoopCoalescesBursts(t *testing.T) {
	changes := make(chan struct{}, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 40*time.Millisecond, func() {
			calls.Add(1)
		})
		close(done)
	}()

	changes <- struct{}{}
	changes <- struct{}{}
	changes <- struct{}{}
	time.Sleep(120 * time.Millisecond)

	close(stop)
	<-done

	if got, want := calls.Load(), int32(1); got != want {
		t.Fatalf("expected %d callback, got %d", want, got)
	}
}

func TestRunDebouncedSignalLoopHandlesSeparatedEvents(t *testing.T) {
	changes := make(chan struct{}, 8)
	stop := make(chan struct{})
	var calls atomic.Int32
	done := make(chan struct{})

	go func() {
		runDebouncedSignalLoop(changes, stop, 30*time.Millisecond, func() {
			calls.Add(1)
		})
		close(done)
	}()

	changes <- struct{}{}
	time.Sleep(80 * time.Millisecond)
	changes <- struct{}{}
	time.Sleep(80 * time.Millisecond)

	close(stop)
	<-done

	if got, want := calls.Load(), int32(2); got != want {
		t.Fatalf("expected %d callbacks, got %d", want, got)
	}
}
