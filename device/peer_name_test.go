package device

import (
	"encoding/hex"
	"fmt"
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

func TestPeerNameAppearsInCreationAndRenameLogs(t *testing.T) {
	var privateKey NoisePrivateKey
	for i := range privateKey {
		privateKey[i] = 0x11
	}
	var peerKey NoisePublicKey
	for i := range peerKey {
		peerKey[i] = 0x22
	}

	var notices []string
	var infos []string
	logger := NewLogger(LogLevelSilent, "")
	logger.Notice = func(format string, args ...any) {
		notices = append(notices, fmt.Sprintf(format, args...))
	}
	logger.Info = func(format string, args ...any) {
		infos = append(infos, fmt.Sprintf(format, args...))
	}

	device := &Device{
		log:    logger,
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

	var creationLog string
	for _, line := range notices {
		if strings.Contains(line, "UAPI：已创建") {
			creationLog = line
			break
		}
	}
	if creationLog == "" {
		t.Fatalf("expected creation log, got notices %v", notices)
	}
	if !strings.Contains(creationLog, "Peer(190网段)") {
		t.Fatalf("expected creation log to contain peer name, got %q", creationLog)
	}

	var renameLog string
	for _, line := range infos {
		if strings.Contains(line, "UAPI：正在更新名称") {
			renameLog = line
			break
		}
	}
	if renameLog == "" {
		t.Fatalf("expected rename log, got infos %v", infos)
	}
	if !strings.Contains(renameLog, "Peer(190网段)") {
		t.Fatalf("expected rename log to contain peer name, got %q", renameLog)
	}
}

func TestHandshakeCompleteLogUsesPeerName(t *testing.T) {
	var notices []string
	logger := NewLogger(LogLevelSilent, "")
	logger.Notice = func(format string, args ...any) {
		notices = append(notices, fmt.Sprintf(format, args...))
	}

	device := &Device{
		log: logger,
	}
	peer := &Peer{
		Name:   "190网段",
		device: device,
	}

	peer.timersHandshakeComplete()

	if got := peer.lastHandshakeNano.Load(); got == 0 {
		t.Fatal("expected lastHandshakeNano to be updated")
	}

	var successLog string
	for _, line := range notices {
		if strings.Contains(line, "握手已完成") {
			successLog = line
			break
		}
	}
	if successLog == "" {
		t.Fatalf("expected handshake completion log, got notices %v", notices)
	}
	if !strings.Contains(successLog, "Peer(190网段)") {
		t.Fatalf("expected handshake completion log to contain peer name, got %q", successLog)
	}
}
