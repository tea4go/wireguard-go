package conn

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

type hostPortEndpoint struct {
	original string
	host     string
	port     uint16
}

func parseHostPortEndpoint(s string) (*hostPortEndpoint, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	return &hostPortEndpoint{
		original: s,
		host:     host,
		port:     uint16(portNum),
	}, nil
}

func resolveHostPort(host string, port uint16) (netip.AddrPort, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return netip.AddrPort{}, err
	}
	return udpAddr.AddrPort(), nil
}

func (e *hostPortEndpoint) resolveAddrPort() (netip.AddrPort, error) {
	return resolveHostPort(e.host, e.port)
}

func (*hostPortEndpoint) ClearSrc() {}

func (e *hostPortEndpoint) SrcToString() string { return "" }

func (e *hostPortEndpoint) DstToString() string { return e.original }

func (e *hostPortEndpoint) DstToBytes() []byte {
	addrPort, err := e.resolveAddrPort()
	if err != nil {
		return nil
	}
	addr := addrPort.Addr()
	port := addrPort.Port()
	if addr.Is4() {
		b := make([]byte, 0, 6)
		as4 := addr.As4()
		b = append(b, as4[:]...)
		return binary.BigEndian.AppendUint16(b, port)
	}
	b := make([]byte, 0, 18)
	as16 := addr.As16()
	b = append(b, as16[:]...)
	return binary.BigEndian.AppendUint16(b, port)
}

func (e *hostPortEndpoint) DstIP() netip.Addr {
	addrPort, err := e.resolveAddrPort()
	if err != nil {
		return netip.Addr{}
	}
	return addrPort.Addr()
}

func (*hostPortEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (e *hostPortEndpoint) String() string {
	return fmt.Sprintf("%s:%d", e.host, e.port)
}
