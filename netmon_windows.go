package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	logs "github.com/tea4go/gh/log4go"
	"golang.org/x/sys/windows"
)

const windowsNetworkChangeDebounce = 8000 * time.Millisecond

type netChangeEvent struct {
	kind       string
	notifyType uint32
	ifLuid     uint64
	ifIndex    uint32
	ifName     string
	family     uint16
	address    string
}

type windowsNetworkMonitor struct {
	token               uintptr
	ipInterfaceHandle   windows.Handle
	unicastChangeHandle windows.Handle
	changes             chan netChangeEvent
	stop                chan struct{}
	done                chan struct{}
	closeOnce           sync.Once
	onChange            func(changeCount int, details []string)
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

func addressFamilyString(family uint16) string {
	switch family {
	case windows.AF_INET:
		return "IPv4"
	case windows.AF_INET6:
		return "IPv6"
	case 0:
		return ""
	default:
		return fmt.Sprintf("Family(%d)", family)
	}
}

func interfaceNameByLuid(luid uint64, ifIndex uint32) string {
	if luid == 0 && ifIndex == 0 {
		return "N/A"
	}
	row := windows.MibIfRow2{
		InterfaceLuid:  luid,
		InterfaceIndex: ifIndex,
	}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err == nil {
		if name := windows.UTF16ToString(row.Alias[:]); name != "" {
			return name
		}
		if name := windows.UTF16ToString(row.Description[:]); name != "" {
			return name
		}
		if row.InterfaceIndex != 0 {
			return fmt.Sprintf("IfIndex#%d", row.InterfaceIndex)
		}
	}
	if ifIndex != 0 {
		return fmt.Sprintf("IfIndex#%d", ifIndex)
	}
	return fmt.Sprintf("Luid#%x", luid)
}

func sockaddrAddressString(raw windows.RawSockaddrInet6, prefixLen uint8) string {
	switch raw.Family {
	case windows.AF_INET:
		addr := netip.AddrFrom4([4]byte{raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3]})
		return fmt.Sprintf("%s/%d", addr.String(), prefixLen)
	case windows.AF_INET6:
		addr := netip.AddrFrom16(raw.Addr)
		if raw.Scope_id != 0 {
			addr = addr.WithZone(fmt.Sprintf("%d", raw.Scope_id))
		}
		return fmt.Sprintf("%s/%d", addr.String(), prefixLen)
	default:
		return ""
	}
}

func formatNetChangeDetail(evt netChangeEvent) string {
	ifName := evt.ifName
	if ifName == "" {
		ifName = interfaceNameByLuid(evt.ifLuid, evt.ifIndex)
	}
	detail := fmt.Sprintf("%s-%s@%s", evt.kind, notificationTypeString(evt.notifyType), ifName)
	parts := make([]string, 0, 2)
	if family := addressFamilyString(evt.family); family != "" {
		parts = append(parts, "family="+family)
	}
	if evt.address != "" {
		parts = append(parts, "addr="+evt.address)
	}
	if len(parts) == 0 {
		return detail
	}
	return fmt.Sprintf("%s(%s)", detail, strings.Join(parts, ", "))
}

func formatNetChangeSummary(eventCount int, details []string) string {
	if len(details) == 0 {
		return fmt.Sprintf("没有系统通知")
	}
	return fmt.Sprintf("%s", strings.Join(details, "; "))
}

func isActionableNetChangeEvent(evt netChangeEvent) bool {
	return !(evt.kind == "IpInterface" && evt.notifyType == windows.MibParameterNotification)
}

var windowsInterfaceChangeCallback = syscall.NewCallback(func(callerContext, rowPtr uintptr, notificationType uint32) uintptr {
	var ifLuid uint64
	var ifIndex uint32
	var ifName string
	var family uint16
	if rowPtr != 0 {
		row := (*windows.MibIpInterfaceRow)(unsafe.Pointer(rowPtr))
		ifLuid = row.InterfaceLuid
		ifIndex = row.InterfaceIndex
		family = row.Family
		ifName = interfaceNameByLuid(ifLuid, ifIndex)
	}
	enqueueWindowsNetworkChange(callerContext, netChangeEvent{
		kind:       "IpInterface",
		notifyType: notificationType,
		ifLuid:     ifLuid,
		ifIndex:    ifIndex,
		ifName:     ifName,
		family:     family,
	})
	return 0
})

var windowsUnicastChangeCallback = syscall.NewCallback(func(callerContext, rowPtr uintptr, notificationType uint32) uintptr {
	var ifLuid uint64
	var ifIndex uint32
	var ifName string
	var family uint16
	var address string
	if rowPtr != 0 {
		row := (*windows.MibUnicastIpAddressRow)(unsafe.Pointer(rowPtr))
		ifLuid = row.InterfaceLuid
		ifIndex = row.InterfaceIndex
		family = row.Address.Family
		ifName = interfaceNameByLuid(ifLuid, ifIndex)
		address = sockaddrAddressString(row.Address, row.OnLinkPrefixLength)
	}
	enqueueWindowsNetworkChange(callerContext, netChangeEvent{
		kind:       "UnicastAddr",
		notifyType: notificationType,
		ifLuid:     ifLuid,
		ifIndex:    ifIndex,
		ifName:     ifName,
		family:     family,
		address:    address,
	})
	return 0
})

func startWindowsNetworkMonitor(onChange func(changeCount int, details []string), excludedLuids map[uint64]string) (*windowsNetworkMonitor, error) {
	monitor := &windowsNetworkMonitor{
		token:         windowsNetworkMonitorSeq.Add(1),
		changes:       make(chan netChangeEvent, 16),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		excludedLuids: excludedLuids,
	}
	if onChange != nil {
		monitor.onChange = func(changeCount int, details []string) {
			onChange(changeCount, details)
		}
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

func runDebouncedSignalLoop(changes <-chan netChangeEvent, stop <-chan struct{}, debounce time.Duration, onChange func(changeCount int, details []string), excludedLuids map[uint64]string) {
	var timer *time.Timer
	var timerC <-chan time.Time
	var eventsInWindow int
	var nonExcludedEvents []netChangeEvent

	for {
		select {
		case evt := <-changes:
			if !isActionableNetChangeEvent(evt) {
				continue
			}
			eventsInWindow++
			if len(nonExcludedEvents) < 8 {
				nonExcludedEvents = append(nonExcludedEvents, evt)
			}
			logs.Debug("[NetMon] %s", formatNetChangeDetail(evt))
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
					details = append(details, formatNetChangeDetail(e))
				}
			}
			nonExcludedEvents = nonExcludedEvents[:0]
			eventsInWindow = 0
			if realCount == 0 {
				continue
			}
			summary := formatNetChangeSummary(realCount, details)
			logs.Debug("[NetMon] 防抖窗口内有效 %d 次: %s", realCount, summary)
			if onChange != nil {
				onChange(realCount, details)
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
