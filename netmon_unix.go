//go:build linux || darwin

package main

import (
	"sync"

	"golang.org/x/sys/unix"
)

const hostNetworkMonitorPollTimeout = 100

func pollHostNetworkMonitor(fd int) (bool, error) {
	pollFDs := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}}
	count, err := unix.Poll(pollFDs, hostNetworkMonitorPollTimeout)
	return count > 0, err
}

func closeUnixHostNetworkMonitor(
	fd int,
	closeOnce *sync.Once,
	stopOnce *sync.Once,
	stop chan struct{},
	done <-chan struct{},
) {
	closeOnce.Do(func() {
		stopHostNetworkMonitor(stopOnce, stop)
		<-done
		_ = unix.Close(fd)
	})
}
