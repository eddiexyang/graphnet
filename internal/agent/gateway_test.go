package agent

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
)

func icmpTo(src, dst netip.Addr) []byte {
	raw := make([]byte, 28)
	raw[0], raw[3], raw[8], raw[9], raw[20] = 0x45, 28, 64, 1, 8
	copy(raw[12:16], src.AsSlice())
	copy(raw[16:20], dst.AsSlice())
	return raw
}

func TestDeliverDropsPacketsForAnotherNetwork(t *testing.T) {
	a, b := model.ID("a"), model.ID("b")
	d := &packetTestTUN{out: make(chan []byte, 4), done: make(chan struct{})}
	defer d.Close()
	r := &DataPlane{}
	r.state.Store(&runtimeState{
		snapshot: model.Snapshot{Networks: []model.NetworkConfig{
			{ID: a, CIDR: netip.MustParsePrefix("6.6.6.0/24")},
			{ID: b, CIDR: netip.MustParsePrefix("7.7.7.0/24")},
		}},
		devices:     map[model.ID]*runtimeTunnel{a: newRuntimeTunnel(d)},
		selfAddress: map[model.ID]netip.Addr{a: netip.MustParseAddr("6.6.6.4"), b: netip.MustParseAddr("7.7.7.13")},
	})
	src := netip.MustParseAddr("6.6.6.11")
	for _, dst := range []string{"7.7.7.2", "7.7.7.13"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); !errors.Is(err, forwarding.ErrDestination) {
			t.Fatalf("deliver to %s: %v", dst, err)
		}
	}
	if err := r.deliverBatch(context.Background(), a, [][]byte{icmpTo(src, netip.MustParseAddr("7.7.7.2"))}); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{"6.6.6.4", "1.1.1.1"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); err != nil {
			t.Fatalf("deliver to %s: %v", dst, err)
		}
	}
	for _, want := range []string{"6.6.6.4", "1.1.1.1"} {
		got, _ := netip.AddrFromSlice((<-d.out)[16:20])
		if got.String() != want {
			t.Fatalf("TUN received %s, want %s", got, want)
		}
	}
	if len(d.out) != 0 {
		t.Fatal("a packet for another network reached the TUN")
	}
}

func TestDeliverAllowsExplicitCrossNetworkAdvertisement(t *testing.T) {
	a, b, c := model.ID("a"), model.ID("b"), model.ID("c")
	d := &packetTestTUN{out: make(chan []byte, 4), done: make(chan struct{})}
	defer d.Close()
	r := &DataPlane{}
	r.state.Store(&runtimeState{
		snapshot: model.Snapshot{Networks: []model.NetworkConfig{
			{
				ID:   a,
				CIDR: netip.MustParsePrefix("6.6.6.0/24"),
				Self: model.Node{
					AdvertisedSubnets: []model.AdvertisedSubnet{
						{Prefix: netip.MustParsePrefix("0.0.0.0/0"), GatewayMode: model.GatewaySNAT},
						{Prefix: netip.MustParsePrefix("7.7.7.0/24"), GatewayMode: model.GatewaySNAT},
					},
				},
			},
			{ID: b, CIDR: netip.MustParsePrefix("7.7.7.0/24")},
			{ID: c, CIDR: netip.MustParsePrefix("8.8.8.0/24")},
		}},
		devices: map[model.ID]*runtimeTunnel{a: newRuntimeTunnel(d)},
		selfAddress: map[model.ID]netip.Addr{
			a: netip.MustParseAddr("6.6.6.4"),
			b: netip.MustParseAddr("7.7.7.13"),
			c: netip.MustParseAddr("8.8.8.9"),
		},
	})
	src := netip.MustParseAddr("6.6.6.11")
	// Unadvertised Network C must stay blocked even with 0.0.0.0/0 advertised.
	for _, dst := range []string{"8.8.8.1", "8.8.8.9"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); !errors.Is(err, forwarding.ErrDestination) {
			t.Fatalf("deliver to unadvertised network %s: %v, want ErrDestination", dst, err)
		}
	}
	// Explicitly advertised Network B must be delivered to TUN so host NAT can forward it.
	for _, dst := range []string{"7.7.7.2", "7.7.7.13"} {
		if err := r.deliver(context.Background(), a, icmpTo(src, netip.MustParseAddr(dst))); err != nil {
			t.Fatalf("deliver to explicitly advertised network %s: %v", dst, err)
		}
		got, _ := netip.AddrFromSlice((<-d.out)[16:20])
		if got.String() != dst {
			t.Fatalf("TUN received %s, want %s", got, dst)
		}
	}
}

func TestDeliverPreservesUserUDP18263ToSelfOverlay(t *testing.T) {
	a := model.ID("00000000000000000000000000000001")
	d := &packetTestTUN{out: make(chan []byte, 4), done: make(chan struct{})}
	defer d.Close()
	r := &DataPlane{}
	selfAddr := netip.MustParseAddr("6.6.6.4")
	peerAddr := netip.MustParseAddr("6.6.6.11")
	r.state.Store(&runtimeState{
		snapshot:    model.Snapshot{Networks: []model.NetworkConfig{{ID: a, CIDR: netip.MustParsePrefix("6.6.6.0/24")}}},
		devices:     map[model.ID]*runtimeTunnel{a: newRuntimeTunnel(d)},
		selfAddress: map[model.ID]netip.Addr{a: selfAddr},
	})
	// 20-byte UDP datagram on 18263 -> 18263 (formerly intercepted as replayPort).
	userPayload := []byte("0123456789abcdefghij")
	raw := packet.UDP(netip.AddrPortFrom(peerAddr, 18263), netip.AddrPortFrom(selfAddr, 18263), userPayload)
	if err := r.deliver(context.Background(), a, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-d.out:
		if !bytes.Equal(got, raw) {
			t.Fatal("user UDP 18263 datagram altered")
		}
	default:
		t.Fatal("user UDP 18263 datagram swallowed instead of delivered to TUN")
	}
}
