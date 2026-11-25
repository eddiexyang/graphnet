package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// dialTTL connects from d's stack with SYNs carrying ttl.
func (d *kernelTUN) dialTTL(ctx context.Context, to netip.AddrPort, local uint16, ttl uint8) error {
	var queue waiter.Queue
	ep, tcpErr := d.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if tcpErr != nil {
		return errors.New(tcpErr.String())
	}
	defer ep.Close()
	if err := ep.SetSockOptInt(tcpip.IPv4TTLOption, int(ttl)); err != nil {
		return errors.New(err.String())
	}
	if err := ep.Bind(tcpip.FullAddress{NIC: 1, Port: local}); err != nil {
		return errors.New(err.String())
	}
	entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
	queue.EventRegister(&entry)
	defer queue.EventUnregister(&entry)
	err := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(to.Addr().As4()), Port: to.Port()})
	if _, pending := err.(*tcpip.ErrConnectStarted); pending {
		select {
		case <-notify:
			err = ep.LastError()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// A TCP connection carried as streams keeps L3 hop-limit semantics: its SYN
// spends a hop at each relay, and the relay where it runs out answers the
// source with ICMP Time Exceeded from its own address, quoting the SYN, and
// does not reset the connection.
func TestStreamedSYNKeepsHopLimitSemantics(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4)
	b, c := state.Networks[0].Nodes[1], state.Networks[0].Nodes[2]
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(c.Address.As4()), Port: 8092}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	waitFor(t, 10*time.Second, "a route from A to C through B", func() bool {
		next, _, err := agents[0].state.Load().router.NextHop(state.Networks[0].ID, c.Address)
		return err == nil && next == b.ID
	})
	icmp := make(chan []byte, 16)
	devices[0].channels.Lock()
	devices[0].icmp = icmp
	devices[0].channels.Unlock()
	to := netip.AddrPortFrom(c.Address, 8092)

	// One hop left: B answers with Time Exceeded, and the SYN is not reset.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- devices[0].dialTTL(ctx, to, 40001, 1) }()
	select {
	case raw := <-icmp:
		quote := raw[28:]
		if raw[20] != 11 || netip.AddrFrom4([4]byte(raw[12:16])) != b.Address || binary.BigEndian.Uint16(quote[20:22]) != 40001 || binary.BigEndian.Uint16(quote[22:24]) != 8092 {
			t.Fatalf("ICMP %d from %s quoting %x", raw[20], netip.AddrFrom4([4]byte(raw[12:16])), quote[:24])
		}
	case err := <-result:
		t.Fatalf("SYN with one hop left ended without Time Exceeded: %v", err)
	case <-ctx.Done():
		t.Fatal("no ICMP Time Exceeded from B for a SYN with one hop left")
	}
	select {
	case err := <-result:
		if err != nil && errors.Is(err, context.DeadlineExceeded) == false && err.Error() == (&tcpip.ErrConnectionRefused{}).String() {
			t.Fatal("the expired SYN was reset")
		}
	case <-time.After(500 * time.Millisecond):
	}

	// Two hops left: the connection reaches C.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if err := devices[0].dialTTL(ctx2, to, 40002, 2); err != nil {
		t.Fatalf("SYN with two hops left: %v", err)
	}
}
