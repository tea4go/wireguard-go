package main

import "time"

const hostNetworkChangeDebounce = 8 * time.Second

type hostNetworkEventKind uint8

const (
	hostNetworkEventLink hostNetworkEventKind = iota + 1
	hostNetworkEventAddress
	hostNetworkEventRoute
)

type hostNetworkEvent struct {
	kind    hostNetworkEventKind
	ifIndex int
	detail  string
}

type hostNetworkMonitor interface {
	Close()
}

func (event hostNetworkEvent) actionable(excluded map[int]string) bool {
	if event.kind == hostNetworkEventRoute {
		return true
	}
	_, isExcluded := excluded[event.ifIndex]
	return !isExcluded
}

func enqueueHostNetworkEvent(events chan<- hostNetworkEvent, event hostNetworkEvent) {
	select {
	case events <- event:
	default:
	}
}

func runHostNetworkChangeLoop(
	events <-chan hostNetworkEvent,
	stop <-chan struct{},
	debounce time.Duration,
	excluded map[int]string,
	onChange func(int, []string),
) {
	var timer *time.Timer
	var timerC <-chan time.Time
	eventCount := 0
	details := make([]string, 0, 8)

	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerC = nil
	}

	for {
		select {
		case <-stop:
			stopTimer()
			return
		default:
		}

		select {
		case event := <-events:
			if !event.actionable(excluded) {
				continue
			}
			eventCount++
			if event.detail != "" && len(details) < 8 {
				details = append(details, event.detail)
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
				timerC = timer.C
			} else {
				stopTimer()
				timer = time.NewTimer(debounce)
				timerC = timer.C
			}

		case <-timerC:
			timer = nil
			timerC = nil
			select {
			case <-stop:
				return
			default:
			}
			if eventCount > 0 && onChange != nil {
				onChange(eventCount, details)
			}
			eventCount = 0
			details = make([]string, 0, 8)

		case <-stop:
			stopTimer()
			return
		}
	}
}
