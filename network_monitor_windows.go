package main

import (
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsNetworkChangeDebounce = 1500 * time.Millisecond

type windowsNetworkMonitor struct {
	token               uintptr
	ipInterfaceHandle   windows.Handle
	unicastChangeHandle windows.Handle
	changes             chan struct{}
	stop                chan struct{}
	done                chan struct{}
	closeOnce           sync.Once
	onChange            func()
}

var (
	windowsNetworkMonitorSeq atomic.Uintptr
	windowsNetworkMonitors   sync.Map
)

var windowsInterfaceChangeCallback = syscall.NewCallback(func(callerContext, _ uintptr, _ uint32) uintptr {
	enqueueWindowsNetworkChange(callerContext)
	return 0
})

var windowsUnicastChangeCallback = syscall.NewCallback(func(callerContext, _ uintptr, _ uint32) uintptr {
	enqueueWindowsNetworkChange(callerContext)
	return 0
})

func startWindowsNetworkMonitor(onChange func()) (*windowsNetworkMonitor, error) {
	monitor := &windowsNetworkMonitor{
		token:   windowsNetworkMonitorSeq.Add(1),
		changes: make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		onChange: func() {
			if onChange != nil {
				onChange()
			}
		},
	}
	windowsNetworkMonitors.Store(monitor.token, monitor)

	if err := windows.NotifyIpInterfaceChange(0, windowsInterfaceChangeCallback, unsafe.Pointer(monitor.token), false, &monitor.ipInterfaceHandle); err != nil {
		windowsNetworkMonitors.Delete(monitor.token)
		return nil, err
	}
	if err := windows.NotifyUnicastIpAddressChange(0, windowsUnicastChangeCallback, unsafe.Pointer(monitor.token), false, &monitor.unicastChangeHandle); err != nil {
		if monitor.ipInterfaceHandle != 0 {
			_ = windows.CancelMibChangeNotify2(monitor.ipInterfaceHandle)
			monitor.ipInterfaceHandle = 0
		}
		windowsNetworkMonitors.Delete(monitor.token)
		return nil, err
	}

	go monitor.run()
	return monitor, nil
}

func (m *windowsNetworkMonitor) Close() {
	m.closeOnce.Do(func() {
		close(m.stop)
		if m.ipInterfaceHandle != 0 {
			_ = windows.CancelMibChangeNotify2(m.ipInterfaceHandle)
			m.ipInterfaceHandle = 0
		}
		if m.unicastChangeHandle != 0 {
			_ = windows.CancelMibChangeNotify2(m.unicastChangeHandle)
			m.unicastChangeHandle = 0
		}
		windowsNetworkMonitors.Delete(m.token)
		<-m.done
	})
}

func (m *windowsNetworkMonitor) run() {
	defer close(m.done)
	runDebouncedSignalLoop(m.changes, m.stop, windowsNetworkChangeDebounce, m.onChange)
}

func enqueueWindowsNetworkChange(token uintptr) {
	monitorAny, ok := windowsNetworkMonitors.Load(token)
	if !ok {
		return
	}
	monitor := monitorAny.(*windowsNetworkMonitor)
	select {
	case monitor.changes <- struct{}{}:
	default:
	}
}

func runDebouncedSignalLoop(changes <-chan struct{}, stop <-chan struct{}, debounce time.Duration, onChange func()) {
	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		select {
		case <-changes:
			if timer == nil {
				timer = time.NewTimer(debounce)
				timerC = timer.C
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(debounce)

		case <-timerC:
			timerC = nil
			if timer != nil {
				timer.Stop()
				timer = nil
			}
			if onChange != nil {
				onChange()
			}

		case <-stop:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			return
		}
	}
}
