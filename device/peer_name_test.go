package device

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestPeerNameFlowsThroughUAPIAndLogs(t *testing.T) {
	var privateKey NoisePrivateKey
	for i := range privateKey {
		privateKey[i] = 0x11
	}
	var peerKey NoisePublicKey
	for i := range peerKey {
		peerKey[i] = 0x22
	}

	device := &Device{
		log:    NewLogger(LogLevelSilent, ""),
		closed: make(chan struct{}),
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()
	device.staticIdentity.privateKey = privateKey
	device.staticIdentity.publicKey = privateKey.publicKey()

	uapi := strings.Join([]string{
		"private_key=" + hex.EncodeToString(privateKey[:]),
		"replace_peers=true",
		"public_key=" + hex.EncodeToString(peerKey[:]),
		"name=190网段",
		"protocol_version=1",
		"replace_allowed_ips=true",
		"allowed_ip=192.168.190.0/24",
		"",
	}, "\n")
	if err := device.IpcSet(uapi); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	peer := device.LookupPeer(peerKey)
	if peer == nil {
		t.Fatal("expected peer to exist")
	}
	if got, want := peer.Name, "190网段"; got != want {
		t.Fatalf("expected peer name %q, got %q", want, got)
	}
	if got, want := peer.String(), "Peer(190网段)"; got != want {
		t.Fatalf("expected peer string %q, got %q", want, got)
	}

	got, err := device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "name=190网段") {
		t.Fatalf("expected IpcGet output to contain peer name, got %q", got)
	}
}
