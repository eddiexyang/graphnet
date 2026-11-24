package forwarding_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// A client neighbor never relays: every frame and stream it sends must carry
// its own node as source, or a leaf could pose as a relay or exit node.
func TestClientNeighborCannotClaimAnotherSource(t *testing.T) {
	for _, client := range []bool{false, true} {
		s := testutil.Topology()
		n := &s.Networks[0]
		n.Nodes[3].Client = client // D, neighbor of A and C
		snapshot, err := routing.Compile(s, n.Nodes[2].AgentID)
		if err != nil {
			t.Fatal(err)
		}
		delivered := 0
		c, err := forwarding.New(snapshot, func(context.Context, model.ID, model.ID, []byte) error { return nil }, func(context.Context, model.ID, []byte) error { delivered++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		b, cID, d := n.Nodes[1], n.Nodes[2], n.Nodes[3]
		frame := func(source model.Node, kind uint8, payload []byte) []byte {
			raw, err := packet.Packet{Header: packet.Header{Network: n.ID, Source: source.ID, Destination: cID.ID, HopLimit: packet.DefaultHopLimit, Epoch: s.Revision, Kind: kind}, Payload: payload}.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		spoofed := frame(b, 0, ipv4("10.42.0.2", "10.42.0.3"))
		err = c.FromPeer(context.Background(), d.ID, spoofed)
		if client && !errors.Is(err, forwarding.ErrSource) || !client && err != nil {
			t.Fatalf("client=%t: frame from D claiming B: %v", client, err)
		}
		if err := c.FromPeerBatch(context.Background(), d.ID, [][]byte{spoofed}); client && !errors.Is(err, forwarding.ErrSource) {
			t.Fatalf("batch frame from client D claiming B: %v", err)
		}
		replay := frame(b, packet.KindSessionReplay, make([]byte, 20))
		if err := c.FromPeer(context.Background(), d.ID, replay); client && !errors.Is(err, forwarding.ErrSource) {
			t.Fatalf("session replay from client D claiming B: %v", err)
		}
		if err := c.FromPeer(context.Background(), d.ID, frame(d, 0, ipv4("10.42.0.4", "10.42.0.3"))); err != nil {
			t.Fatalf("client=%t: D's own frame: %v", client, err)
		}
		request := forwardingRequest(n.ID, b.ID, cID.ID, "10.42.0.2:40000", "10.42.0.3:443")
		if _, _, err := c.TCPRoute(request, d.ID); client && !errors.Is(err, forwarding.ErrSource) || !client && err != nil {
			t.Fatalf("client=%t: stream from D claiming B: %v", client, err)
		}
		own := forwardingRequest(n.ID, d.ID, cID.ID, "10.42.0.4:40000", "10.42.0.3:443")
		if _, local, err := c.TCPRoute(own, d.ID); err != nil || !local {
			t.Fatalf("client=%t: D's own stream: %v %v", client, local, err)
		}
		if want := map[bool]int{false: 3, true: 1}[client]; delivered != want {
			t.Fatalf("client=%t: delivered %d frames, want %d", client, delivered, want)
		}
	}
}

func forwardingRequest(network, source, destination model.ID, from, to string) streamproxy.Request {
	return streamproxy.Request{Network: network, Source: source, Destination: destination, From: netip.MustParseAddrPort(from), To: netip.MustParseAddrPort(to), Hops: packet.DefaultHopLimit}
}
