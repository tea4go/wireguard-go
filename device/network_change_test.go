package device

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

type countingBind struct {
	openCalls  atomic.Int32
	closeCalls atomic.Int32
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.openCalls.Add(1)
	return nil, port, nil
}

func (b *countingBind) Close() error {
	b.closeCalls.Add(1)
	return nil
}

func (b *countingBind) SetMark(mark uint32) error {
	return nil
}

func (b *countingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	return nil
}

func (b *countingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return dummyEndpoint{addr: netip.MustParseAddr("127.0.0.1")}, nil
}

func (b *countingBind) BatchSize() int {
	return 1
}

type dummyEndpoint struct {
	addr netip.Addr
}

func (e dummyEndpoint) ClearSrc()           {}
func (e dummyEndpoint) SrcToString() string { return "" }
func (e dummyEndpoint) DstToString() string { return e.addr.String() }
func (e dummyEndpoint) DstToBytes() []byte  { return e.addr.AsSlice() }
func (e dummyEndpoint) DstIP() netip.Addr   { return e.addr }
func (e dummyEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func TestHandleNetworkChangeRebindsSockets(t *testing.T) {
	bind := &countingBind{}
	device := &Device{
		log: NewLogger(LogLevelSilent, ""),
	}
	device.state.state.Store(uint32(deviceStateUp))
	device.net.bind = bind
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.queue.handshake = newHandshakeQueue()
	device.queue.decryption = newInboundQueue()

	if err := device.HandleNetworkChange(); err != nil {
		t.Fatalf("HandleNetworkChange: %v", err)
	}

	if got, want := bind.closeCalls.Load(), int32(1); got != want {
		t.Fatalf("expected %d close call, got %d", want, got)
	}
	if got, want := bind.openCalls.Load(), int32(1); got != want {
		t.Fatalf("expected %d open call, got %d", want, got)
	}
}
