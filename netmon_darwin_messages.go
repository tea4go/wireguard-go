package main

import (
	"encoding/binary"
	"fmt"
)

const (
	darwinRouteMessageVersion = 0x5
	darwinRTMAdd              = 0x1
	darwinRTMDelete           = 0x2
	darwinRTMChange           = 0x3
	darwinRTMNewAddr          = 0xc
	darwinRTMDelAddr          = 0xd
	darwinRTMIfInfo           = 0xe
)

func parseDarwinRouteEvents(data []byte) []hostNetworkEvent {
	var events []hostNetworkEvent
	for len(data) >= 4 {
		messageLength := int(binary.NativeEndian.Uint16(data[0:2]))
		if messageLength < 4 || messageLength > len(data) {
			break
		}

		message := data[:messageLength]
		if message[2] == darwinRouteMessageVersion {
			switch message[3] {
			case darwinRTMIfInfo:
				if len(message) >= 14 {
					ifIndex := int(binary.NativeEndian.Uint16(message[12:14]))
					events = append(events, hostNetworkEvent{
						kind:    hostNetworkEventLink,
						ifIndex: ifIndex,
						detail:  fmt.Sprintf("Link@if#%d", ifIndex),
					})
				}
			case darwinRTMNewAddr, darwinRTMDelAddr:
				if len(message) >= 14 {
					ifIndex := int(binary.NativeEndian.Uint16(message[12:14]))
					events = append(events, hostNetworkEvent{
						kind:    hostNetworkEventAddress,
						ifIndex: ifIndex,
						detail:  fmt.Sprintf("Address@if#%d", ifIndex),
					})
				}
			case darwinRTMAdd, darwinRTMDelete, darwinRTMChange:
				if len(message) >= 6 {
					ifIndex := int(binary.NativeEndian.Uint16(message[4:6]))
					events = append(events, hostNetworkEvent{
						kind:    hostNetworkEventRoute,
						ifIndex: ifIndex,
						detail:  "Route",
					})
				}
			}
		}
		data = data[messageLength:]
	}
	return events
}
