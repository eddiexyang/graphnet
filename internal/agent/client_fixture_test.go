package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// clientFixture forces node 0 of graphAgents/streamAgents to run as an embedded
// client node (DataPlaneOptions.Embedded = true, Node.Client = true) and routes
// its TCP dials through OpenEmbeddedTCP + streamproxy.ClientConn, matching
// package client's data path. Enabled by default; disable via
// -client-fixture=false or GRAPHNET_CLIENT_FIXTURE=0.
var clientFixture = flag.Bool("client-fixture", true, "run node 0 in graphAgents as an embedded client node")

func clientFixtureEnabled() bool {
	if v := os.Getenv("GRAPHNET_CLIENT_FIXTURE"); v != "" {
		return v != "0" && v != "false"
	}
	return *clientFixture
}

type tcpTestConn interface {
	net.Conn
	CloseWrite() error
}

type embeddedClientFixture struct {
	ctx      context.Context
	runtime  *DataPlane
	portMu   sync.Mutex
	portNext uint16
	ports    map[uint16]struct{}
}

func (d *kernelTUN) attachEmbeddedClient(ctx context.Context, runtime *DataPlane) {
	d.embedded = &embeddedClientFixture{
		ctx:     ctx,
		runtime: runtime,
		ports:   make(map[uint16]struct{}),
	}
}

func (f *embeddedClientFixture) allocPort() (uint16, func(), error) {
	const base = 32768
	const span = 65535 - base + 1
	f.portMu.Lock()
	defer f.portMu.Unlock()
	for range span {
		port := uint16(base + int(f.portNext)%span)
		f.portNext = uint16((int(f.portNext) + 1) % span)
		if _, used := f.ports[port]; !used {
			f.ports[port] = struct{}{}
			var once sync.Once
			return port, func() {
				once.Do(func() {
					f.portMu.Lock()
					delete(f.ports, port)
					f.portMu.Unlock()
				})
			}, nil
		}
	}
	return 0, nil, errors.New("embedded client fixture: no ephemeral port available")
}

func (f *embeddedClientFixture) route(ctx context.Context, destination netip.Addr) (model.ID, netip.Addr, error) {
	delay := 10 * time.Millisecond
	for {
		network, local, err := f.runtime.NetworkFor(destination.Unmap())
		if err == nil {
			return network, local, nil
		}
		if !errors.Is(err, ErrNotConfigured) && !errors.Is(err, forwarding.ErrUnreachable) {
			return "", netip.Addr{}, fmt.Errorf("embedded client fixture: %s: %w", destination, err)
		}
		select {
		case <-ctx.Done():
			return "", netip.Addr{}, fmt.Errorf("embedded client fixture: waiting for route to %s: %w", destination, ctx.Err())
		case <-f.ctx.Done():
			return "", netip.Addr{}, net.ErrClosed
		case <-time.After(delay):
		}
		delay = min(2*delay, 250*time.Millisecond)
	}
}

func (d *kernelTUN) dialTCP(ctx context.Context, addr tcpip.Address, port uint16, proto tcpip.NetworkProtocolNumber) (tcpTestConn, error) {
	if d.embedded == nil {
		return gonet.DialContextTCP(ctx, d.stack, tcpip.FullAddress{NIC: 1, Addr: addr, Port: port}, proto)
	}
	dst, ok := netip.AddrFromSlice(addr.AsSlice())
	if !ok {
		return nil, fmt.Errorf("embedded client fixture: invalid address %s", addr)
	}
	dst = dst.Unmap()
	destination := netip.AddrPortFrom(dst, port)
	network, local, err := d.embedded.route(ctx, dst)
	if err != nil {
		return nil, err
	}
	ephemeral, releasePort, err := d.embedded.allocPort()
	if err != nil {
		return nil, err
	}
	source := netip.AddrPortFrom(local, ephemeral)
	stream, err := d.embedded.runtime.OpenEmbeddedTCP(ctx, network, source, destination)
	if err != nil {
		releasePort()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, &net.OpError{Op: "connect", Net: "tcp", Source: net.TCPAddrFromAddrPort(source), Addr: net.TCPAddrFromAddrPort(destination), Err: err}
	}
	if stream == nil {
		releasePort()
		return gonet.DialContextTCP(ctx, d.stack, tcpip.FullAddress{NIC: 1, Addr: addr, Port: port}, proto)
	}
	return streamproxy.ClientConn(d.embedded.ctx, stream, source, destination, releasePort).(tcpTestConn), nil
}

// applyClientFixture mutates node 0 into a client node when the client fixture
// is active.
func applyClientFixture(t *testing.T, state *model.State) {
	t.Helper()
	if !clientFixtureEnabled() || len(state.Networks) == 0 || len(state.Networks[0].Nodes) == 0 {
		return
	}
	state.Networks[0].Nodes[0].Client = true
	if len(state.Agents) > 0 {
		state.Agents[0].Endpoints = []model.Endpoint{}
	}
}
