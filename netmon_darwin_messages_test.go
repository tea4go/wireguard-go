package main

import (
	"encoding/binary"
	"testing"
)

func darwinRouteMessage(messageType uint8, ifIndex uint16, length int) []byte {
	message := make([]byte, length)
	binary.NativeEndian.PutUint16(message[0:2], uint16(length))
	message[2] = darwinRouteMessageVersion
	message[3] = messageType
	switch messageType {
	case darwinRTMIfInfo, darwinRTMNewAddr, darwinRTMDelAddr:
		if len(message) >= 14 {
			binary.NativeEndian.PutUint16(message[12:14], ifIndex)
		}
	default:
		if len(message) >= 6 {
			binary.NativeEndian.PutUint16(message[4:6], ifIndex)
		}
	}
	return message
}

func TestParseDarwinRouteInterfaceEvents(t *testing.T) {
	for _, messageType := range []uint8{darwinRTMIfInfo, darwinRTMNewAddr, darwinRTMDelAddr} {
		events := parseDarwinRouteEvents(darwinRouteMessage(messageType, 11, 14))
		if len(events) != 1 {
			t.Fatalf("type %d: expected 1 event, got %d", messageType, len(events))
		}
		wantKind := hostNetworkEventAddress
		if messageType == darwinRTMIfInfo {
			wantKind = hostNetworkEventLink
		}
		if got := events[0]; got.kind != wantKind || got.ifIndex != 11 {
			t.Fatalf("type %d: unexpected event %#v", messageType, got)
		}
	}
}

func TestParseDarwinRouteRouteEvents(t *testing.T) {
	for _, messageType := range []uint8{darwinRTMAdd, darwinRTMDelete, darwinRTMChange} {
		events := parseDarwinRouteEvents(darwinRouteMessage(messageType, 19, 6))
		if len(events) != 1 {
			t.Fatalf("type %d: expected 1 event, got %d", messageType, len(events))
		}
		if got := events[0]; got.kind != hostNetworkEventRoute || got.ifIndex != 19 {
			t.Fatalf("type %d: unexpected event %#v", messageType, got)
		}
	}
}

func TestParseDarwinRouteMultipleMessages(t *testing.T) {
	data := append(
		darwinRouteMessage(darwinRTMIfInfo, 2, 14),
		darwinRouteMessage(darwinRTMAdd, 3, 6)...,
	)
	events := parseDarwinRouteEvents(data)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestParseDarwinRouteRejectsInvalidMessages(t *testing.T) {
	wrongVersion := darwinRouteMessage(darwinRTMIfInfo, 1, 14)
	wrongVersion[2] = 0xff
	oversized := darwinRouteMessage(darwinRTMIfInfo, 1, 14)
	binary.NativeEndian.PutUint16(oversized[0:2], 15)

	for name, data := range map[string][]byte{
		"short header":      make([]byte, 3),
		"zero length":       make([]byte, 4),
		"wrong version":     wrongVersion,
		"oversized message": oversized,
		"short interface":   darwinRouteMessage(darwinRTMIfInfo, 0, 13),
		"short route":       darwinRouteMessage(darwinRTMAdd, 0, 5),
		"unrelated type":    darwinRouteMessage(0xff, 0, 14),
	} {
		t.Run(name, func(t *testing.T) {
			if events := parseDarwinRouteEvents(data); len(events) != 0 {
				t.Fatalf("expected no events, got %#v", events)
			}
		})
	}
}
