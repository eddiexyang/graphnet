package sockets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// A dial with a network context resolves the name with the Lookup hook and
// hands every address to the network, never to a host socket.
func TestDialThroughNetwork(t *testing.T) {
	var looked string
	hostSockets := 0
	ctx := With(context.Background(), Hooks{
		Control: func(string, string, syscall.RawConn) error {
			hostSockets++
			return errors.New("host socket")
		},
		Lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			looked = network + " " + host
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
		},
	})
	var tried []netip.AddrPort
	server, client := net.Pipe()
	defer server.Close()
	ctx = WithNetwork(ctx, func(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("network dial without the dialer's timeout")
		}
		tried = append(tried, address)
		if address.Addr() == netip.MustParseAddr("192.0.2.1") {
			return nil, errors.New("no route")
		}
		return client, nil
	})
	conn, err := Dial(ctx, &net.Dialer{Timeout: time.Second}, "tcp", "controller.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	if conn != client {
		t.Fatal("dial did not return the network's connection")
	}
	if looked != "ip controller.example" {
		t.Fatalf("lookup %q", looked)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:8443"), netip.MustParseAddrPort("192.0.2.2:8443")}
	if len(tried) != 2 || tried[0] != want[0] || tried[1] != want[1] {
		t.Fatalf("tried %v, want %v", tried, want)
	}
	if hostSockets != 0 {
		t.Fatalf("%d host sockets", hostSockets)
	}

	// A literal address is not looked up; every failure is reported.
	looked, tried = "", nil
	failing := WithNetwork(ctx, func(context.Context, netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("no route")
	})
	if _, err := Dial(failing, &net.Dialer{}, "tcp", "198.51.100.7:443"); err == nil || looked != "" {
		t.Fatalf("literal address: err %v, lookup %q", err, looked)
	}
	if _, err := Dial(failing, &net.Dialer{}, "udp", "198.51.100.7:443"); err == nil {
		t.Fatal("UDP dialed through the network")
	}
}
