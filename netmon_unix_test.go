//go:build linux || darwin

package main

import (
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCloseUnixHostNetworkMonitorReturnsWithoutEvents(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer unix.Close(fds[1])

	stop := make(chan struct{})
	done := make(chan struct{})
	pollErr := make(chan error, 1)
	pollStarted := make(chan struct{})
	go func() {
		defer close(done)
		close(pollStarted)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := pollHostNetworkMonitor(fds[0]); err != nil {
				pollErr <- err
				return
			}
		}
	}()
	<-pollStarted
	time.Sleep(10 * time.Millisecond)

	var closeOnce sync.Once
	var stopOnce sync.Once
	returned := make(chan struct{})
	go func() {
		closeUnixHostNetworkMonitor(fds[0], &closeOnce, &stopOnce, stop, done)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Close did not return while the monitored fd was idle")
	}
	select {
	case err := <-pollErr:
		t.Fatalf("poll failed during Close: %v", err)
	default:
	}
}

func TestCloseUnixHostNetworkMonitorIsConcurrentSafe(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer unix.Close(fds[1])

	stop := make(chan struct{})
	done := make(chan struct{})
	pollStarted := make(chan struct{})
	go func() {
		defer close(done)
		close(pollStarted)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := pollHostNetworkMonitor(fds[0]); err != nil {
				return
			}
		}
	}()
	<-pollStarted
	time.Sleep(10 * time.Millisecond)

	var closeOnce sync.Once
	var stopOnce sync.Once
	var callers sync.WaitGroup
	callers.Add(8)
	for range 8 {
		go func() {
			defer callers.Done()
			closeUnixHostNetworkMonitor(fds[0], &closeOnce, &stopOnce, stop, done)
		}()
	}

	returned := make(chan struct{})
	go func() {
		callers.Wait()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("concurrent Close calls did not return")
	}
}
