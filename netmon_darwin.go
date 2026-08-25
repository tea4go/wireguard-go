//go:build darwin

package main

import (
	"sync"

	logs "github.com/tea4go/gh/log4go"
	"golang.org/x/sys/unix"
)

type darwinHostNetworkMonitor struct {
	fd        int
	events    chan hostNetworkEvent
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	stopOnce  sync.Once
	waitGroup sync.WaitGroup
	onChange  func(int, []string)
	excluded  map[int]string
}

func startHostNetworkMonitor(onChange func(int, []string), excluded map[int]string) (hostNetworkMonitor, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	// x/sys/unix does not expose SOCK_CLOEXEC on Darwin.
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	monitor := &darwinHostNetworkMonitor{
		fd:       fd,
		events:   make(chan hostNetworkEvent, 16),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		onChange: onChange,
		excluded: excluded,
	}
	monitor.waitGroup.Add(2)
	go monitor.readEvents()
	go monitor.run()
	go func() {
		monitor.waitGroup.Wait()
		close(monitor.done)
	}()
	return monitor, nil
}

func (monitor *darwinHostNetworkMonitor) Close() {
	closeUnixHostNetworkMonitor(
		monitor.fd,
		&monitor.closeOnce,
		&monitor.stopOnce,
		monitor.stop,
		monitor.done,
	)
}

func (monitor *darwinHostNetworkMonitor) run() {
	defer monitor.waitGroup.Done()
	runHostNetworkChangeLoop(
		monitor.events,
		monitor.stop,
		hostNetworkChangeDebounce,
		monitor.excluded,
		monitor.onChange,
	)
}

func (monitor *darwinHostNetworkMonitor) readEvents() {
	defer monitor.waitGroup.Done()
	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-monitor.stop:
			return
		default:
		}
		ready, err := pollHostNetworkMonitor(monitor.fd)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if stopHostNetworkMonitor(&monitor.stopOnce, monitor.stop) {
				logs.Error("macOS 网络变化监视读取失败: %v", err)
			}
			return
		}
		if !ready {
			continue
		}

		count, err := unix.Read(monitor.fd, buffer)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			if stopHostNetworkMonitor(&monitor.stopOnce, monitor.stop) {
				logs.Error("macOS 网络变化监视读取失败: %v", err)
			}
			return
		}
		if count == 0 {
			stopHostNetworkMonitor(&monitor.stopOnce, monitor.stop)
			return
		}
		for _, event := range parseDarwinRouteEvents(buffer[:count]) {
			if event.actionable(monitor.excluded) {
				enqueueHostNetworkEvent(monitor.events, event)
			}
		}
	}
}
