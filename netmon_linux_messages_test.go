package main

import (
	"encoding/binary"
	"testing"
)

func linuxNetlinkMessage(messageType uint16, payload []byte) []byte {
	message := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], messageType)
	copy(message[16:], payload)
	return message
}

func TestParseLinuxNetlinkLinkEvents(t *testing.T) {
	for _, messageType := range []uint16{linuxRTMNewLink, linuxRTMDelLink} {
		payload := make([]byte, 16)
		binary.NativeEndian.PutUint32(payload[4:8], 17)

		events := parseLinuxNetlinkEvents(linuxNetlinkMessage(messageType, payload))
		if len(events) != 1 {
			t.Fatalf("type %d: expected 1 event, got %d", messageType, len(events))
		}
		if got := events[0]; got.kind != hostNetworkEventLink || got.ifIndex != 17 {
			t.Fatalf("type %d: unexpected event %#v", messageType, got)
		}
	}
}

func TestParseLinuxNetlinkAddressEvents(t *testing.T) {
	for _, messageType := range []uint16{linuxRTMNewAddr, linuxRTMDelAddr} {
		payload := make([]byte, 8)
		binary.NativeEndian.PutUint32(payload[4:8], 23)

		events := parseLinuxNetlinkEvents(linuxNetlinkMessage(messageType, payload))
		if len(events) != 1 {
			t.Fatalf("type %d: expected 1 event, got %d", messageType, len(events))
		}
		if got := events[0]; got.kind != hostNetworkEventAddress || got.ifIndex != 23 {
			t.Fatalf("type %d: unexpected event %#v", messageType, got)
		}
	}
}

func TestParseLinuxNetlinkRouteEvents(t *testing.T) {
	for _, messageType := range []uint16{linuxRTMNewRoute, linuxRTMDelRoute} {
		events := parseLinuxNetlinkEvents(linuxNetlinkMessage(messageType, nil))
		if len(events) != 1 {
			t.Fatalf("type %d: expected 1 event, got %d", messageType, len(events))
		}
		if got := events[0]; got.kind != hostNetworkEventRoute {
			t.Fatalf("type %d: unexpected event %#v", messageType, got)
		}
	}
}

func TestParseLinuxNetlinkMultipleAlignedMessages(t *testing.T) {
	linkPayload := make([]byte, 16)
	binary.NativeEndian.PutUint32(linkPayload[4:8], 3)
	addressPayload := make([]byte, 8)
	binary.NativeEndian.PutUint32(addressPayload[4:8], 4)

	data := append(linuxNetlinkMessage(linuxRTMNewLink, linkPayload), linuxNetlinkMessage(linuxRTMNewAddr, addressPayload)...)
	events := parseLinuxNetlinkEvents(data)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestParseLinuxNetlinkRejectsInvalidMessages(t *testing.T) {
	invalidLength := make([]byte, 16)
	binary.NativeEndian.PutUint32(invalidLength[0:4], 15)
	truncatedPayload := linuxNetlinkMessage(linuxRTMNewLink, make([]byte, 15))

	for name, data := range map[string][]byte{
		"truncated header":  make([]byte, 15),
		"invalid length":    invalidLength,
		"truncated payload": truncatedPayload,
		"unrelated type":    linuxNetlinkMessage(0xffff, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if events := parseLinuxNetlinkEvents(data); len(events) != 0 {
				t.Fatalf("expected no events, got %#v", events)
			}
		})
	}
}
