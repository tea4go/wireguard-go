package main

import (
	"encoding/binary"
	"fmt"
)

const (
	linuxNetlinkHeaderLength = 16
	linuxIfInfoMessageLength = 16
	linuxIfAddrMessageLength = 8

	linuxRTMNewLink  = 16
	linuxRTMDelLink  = 17
	linuxRTMNewAddr  = 20
	linuxRTMDelAddr  = 21
	linuxRTMNewRoute = 24
	linuxRTMDelRoute = 25
)

func parseLinuxNetlinkEvents(data []byte) []hostNetworkEvent {
	var events []hostNetworkEvent
	for len(data) >= linuxNetlinkHeaderLength {
		messageLength := int(binary.NativeEndian.Uint32(data[0:4]))
		if messageLength < linuxNetlinkHeaderLength || messageLength > len(data) {
			break
		}

		messageType := binary.NativeEndian.Uint16(data[4:6])
		payload := data[linuxNetlinkHeaderLength:messageLength]
		switch messageType {
		case linuxRTMNewLink, linuxRTMDelLink:
			if len(payload) >= linuxIfInfoMessageLength {
				ifIndex := int(int32(binary.NativeEndian.Uint32(payload[4:8])))
				events = append(events, hostNetworkEvent{
					kind:    hostNetworkEventLink,
					ifIndex: ifIndex,
					detail:  fmt.Sprintf("Link@if#%d", ifIndex),
				})
			}
		case linuxRTMNewAddr, linuxRTMDelAddr:
			if len(payload) >= linuxIfAddrMessageLength {
				ifIndex := int(binary.NativeEndian.Uint32(payload[4:8]))
				events = append(events, hostNetworkEvent{
					kind:    hostNetworkEventAddress,
					ifIndex: ifIndex,
					detail:  fmt.Sprintf("Address@if#%d", ifIndex),
				})
			}
		case linuxRTMNewRoute, linuxRTMDelRoute:
			events = append(events, hostNetworkEvent{
				kind:   hostNetworkEventRoute,
				detail: "Route",
			})
		}

		alignedLength := (messageLength + 3) &^ 3
		if alignedLength > len(data) {
			break
		}
		data = data[alignedLength:]
	}
	return events
}
