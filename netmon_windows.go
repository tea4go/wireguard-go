package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsNetworkChangeDebounce = 1500 * time.Millisecond

type netChangeEvent struct {
	kind       string
	notifyType uint32
	ifLuid     uint64
	ifIndex    uint32
}

type windowsNetworkMonitor struct {
	token               uintptr
	ipInterfaceHandle   windows.Handle
	unicastChangeHandle windows.Handle
	changes             chan netChangeEvent
	stop                chan struct{}
	done                chan struct{}
	closeOnce           sync.Once
	onChange            func()
	excludedLuids       map[uint64]string
	lastDetailLogged    atomic.Bool
}

var (
	windowsNetworkMonitorSeq atomic.Uintptr
	windowsNetworkMonitors   sync.Map
)

func notificationTypeString(t uint32) string {
	switch t {
	case windows.MibParameterNotification:
		return "Param"
	case windows.MibAddInstance:
		return "Add"
	case windows.MibDeleteInstance:
		return "Del"
	case windows.MibInitialNotification:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func luidToIndex(luid uint64) uint32 {
	var idx uint32
	if luid == 0 {
		return 0
	}
	if err := windows.LuidToIndex((*windows.LUID)(unsafe.Pointer(&luid)), &idx); err != nil {
		return 0
	}
	return idx
}

func interfaceNameByLuid(luid uint64) string {
	if luid == 0 {
		return ""
	}
	var idx uint32
	if err := windows.LuidToIndex((*windows.LUID)(unsafe.Pointer(&luid)), &idx); err != nil {
		return fmt.Sprintf("Luid#%x", luid)
	}
	var size uint32 = 0
	_ = windows.GetIfEntry2(&windows.MibIfRow2{InterfaceIndex: idx})
	buf := make([]uint16, 256)
	size = uint32(len(buf))
	if err := windows.GetIfAliasByIndex(idx, &buf[0], &size); err == nil && size > 0 {
		return windows.UTF16ToString(buf[:size])
	}
	if err := windows.GetIfNameByIndex(idx, &buf[0], &size); err == nil && size > 0 {
		return windows.UTF16ToString(buf[:size])
	}
	return fmt.Sprintf("IfIndex#%d", idx)
}

var windowsInterfaceChangeCallback = syscall.NewCallback(func(callerContext, rowPtr uintptr, notificationType uint32) uintptr {
	var ifLuid uint64
	var ifIndex uint32
	if rowPtr != 0 {
		row := (*windows.MibIpInterfaceRow)(unsafe.Pointer(rowPtr))
		ifLuid = row.InterfaceLuid
		ifIndex = row.InterfaceIndex
	}
	enqueueWindowsNetworkChange(callerContext, netChangeEvent{
		kind:       "IpInterface",
		notifyType: notificationType,
		ifLuid:     ifLuid,
		ifIndex:    ifIndex,
	})
	return 0
})

var windowsUnicastChangeCallback = syscall.NewCallback(func(callerContext, rowPtr uintptr, notificationType uint32) uintptr {
	var ifLuid uint64
	var ifIndex uint32
	if rowPtr != 0 {
		row := (*windows.MibUnicastIpAddressRow)(unsafe.Pointer(rowPtr))
		ifLuid = row.InterfaceLuid
		ifIndex = row.InterfaceIndex
	}
	enqueueWindowsNetworkChange(callerContext, netChangeEvent{
		kind:       "UnicastAddr",
		notifyType: notificationType,
		ifLuid:     ifLuid,
		ifIndex:    ifIndex,
	})
	return 0
})

func startWindowsNetworkMonitor(onChange func(), excludedLuids map[uint64]string) (*windowsNetworkMonitor, error) {
	monitor := &windowsNetworkMonitor{
		token:   windowsNetworkMonitorSeq.Add(1),
		changes: make(chan netChangeEvent, 16),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		onChange: func() {
			if onChange != nil {
				onChange()
			}
		},
		excludedLuids: excludedLuids,
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
	runDebouncedSignalLoop(m.changes, m.stop, windowsNetworkChangeDebounce, m.onChange, m.excludedLuids)
}

func enqueueWindowsNetworkChange(token uintptr, evt netChangeEvent) {
	monitorAny, ok := windowsNetworkMonitors.Load(token)
	if !ok {
		return
	}
	monitor := monitorAny.(*windowsNetworkMonitor)
	if _, excluded := monitor.excludedLuids[evt.ifLuid]; excluded {
		return
	}
	select {
	case monitor.changes <- evt:
	default:
	}
}

func runDebouncedSignalLoop(changes <-chan netChangeEvent, stop <-chan struct{}, debounce time.Duration, onChange func(), excludedLuids map[uint64]string) {
	var timer *time.Timer
	var timerC <-chan time.Time
	var lastEvt netChangeEvent
	var eventsInWindow int
	var nonExcludedEvents []netChangeEvent

	for {
		select {
		case evt := <-changes:
			eventsInWindow++
			lastEvt = evt
			if len(nonExcludedEvents) < 8 {
				nonExcludedEvents = append(nonExcludedEvents, evt)
			}
			ifName := interfaceNameByLuid(evt.ifLuid)
			logs.Debug("[NetMon] %s %s ifLuid=%x ifIndex=%d name=%q",
				evt.kind, notificationTypeString(evt.notifyType), evt.ifLuid, evt.ifIndex, ifName)
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
			realCount := 0
			details := make([]string, 0, len(nonExcludedEvents))
			for _, e := range nonExcludedEvents {
				if _, ok := excludedLuids[e.ifLuid]; !ok {
					realCount++
					ifName := interfaceNameByLuid(e.ifLuid)
					details = append(details, fmt.Sprintf("%s-%s@%s",
						e.kind, notificationTypeString(e.notifyType), ifName))
				}
			}
			nonExcludedEvents = nonExcludedEvents[:0]
			eventsInWindow = 0
			if realCount == 0 {
				continue
			}
			logs.Verbosef("[NetMon] 防抖窗口内共 %d 次系统通知，有效 %d 次: %v",
				eventsInWindow, realCount, details)
			if onChange != nil {
				onChange()
			}
			lastEvt = netChangeEvent{}

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
