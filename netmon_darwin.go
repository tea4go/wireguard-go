//go:build darwin

package main

import (
	"sync"

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
	unix.CloseOnExec(fd)

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
	monitor.closeOnce.Do(func() {
		monitor.stopOnce.Do(func() {
			close(monitor.stop)
		})
		_ = unix.Shutdown(monitor.fd, unix.SHUT_RDWR)
		_ = unix.Close(monitor.fd)
		<-monitor.done
	})
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
		count, err := unix.Read(monitor.fd, buffer)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			monitor.stopOnce.Do(func() {
				close(monitor.stop)
			})
			return
		}
		if count == 0 {
			monitor.stopOnce.Do(func() {
				close(monitor.stop)
			})
			return
		}
		for _, event := range parseDarwinRouteEvents(buffer[:count]) {
			if event.actionable(monitor.excluded) {
				enqueueHostNetworkEvent(monitor.events, event)
			}
		}
	}
}
