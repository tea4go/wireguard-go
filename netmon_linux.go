//go:build linux

package main

import (
	"sync"

	logs "github.com/tea4go/gh/log4go"
	"golang.org/x/sys/unix"
)

type linuxHostNetworkMonitor struct {
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
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	address := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK |
			unix.RTMGRP_IPV4_IFADDR |
			unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE |
			unix.RTMGRP_IPV6_ROUTE,
	}
	if err := unix.Bind(fd, address); err != nil {
		unix.Close(fd)
		return nil, err
	}

	monitor := &linuxHostNetworkMonitor{
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

func (monitor *linuxHostNetworkMonitor) Close() {
	closeUnixHostNetworkMonitor(
		monitor.fd,
		&monitor.closeOnce,
		&monitor.stopOnce,
		monitor.stop,
		monitor.done,
	)
}

func (monitor *linuxHostNetworkMonitor) run() {
	defer monitor.waitGroup.Done()
	runHostNetworkChangeLoop(
		monitor.events,
		monitor.stop,
		hostNetworkChangeDebounce,
		monitor.excluded,
		monitor.onChange,
	)
}

func (monitor *linuxHostNetworkMonitor) readEvents() {
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
				logs.Error("Linux 网络变化监视读取失败: %v", err)
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
				logs.Error("Linux 网络变化监视读取失败: %v", err)
			}
			return
		}
		if count == 0 {
			stopHostNetworkMonitor(&monitor.stopOnce, monitor.stop)
			return
		}
		for _, event := range parseLinuxNetlinkEvents(buffer[:count]) {
			if event.actionable(monitor.excluded) {
				enqueueHostNetworkEvent(monitor.events, event)
			}
		}
	}
}
