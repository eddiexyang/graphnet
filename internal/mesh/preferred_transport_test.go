package mesh_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/mesh"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

func newPreferredFixture(t *testing.T, seedOffset byte, pref model.Transport) (*mesh.Mesh, *mesh.Mesh, func(rev uint64, peerEps []model.Endpoint) model.Snapshot, []model.Endpoint) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var seedA, seedB [ed25519.SeedSize]byte
	seedA[0], seedB[0] = seedOffset, seedOffset+1
	keyA, keyB := ed25519.NewKeyFromSeed(seedA[:]), ed25519.NewKeyFromSeed(seedB[:])
	nop := func(context.Context, model.ID, []byte) error { return nil }

	meshA, err := mesh.NewWithOptions(ctx, keyA, "127.0.0.1", 0, nop, mesh.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meshA.Close() })

	meshB, err := mesh.NewWithOptions(ctx, keyB, "127.0.0.1", 0, nop, mesh.Options{
		PreferredTransport: pref,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meshB.Close() })

	netID := testutil.ID(1)
	agentA, agentB := testutil.ID(11), testutil.ID(12)
	nodeA, nodeB := testutil.ID(10), testutil.ID(20)
	edgeID := testutil.ID(30)
	portA := meshA.Port()
	epsA := []model.Endpoint{
		{ID: testutil.ID(40), Transport: model.TCP, Source: model.Manual, URL: fmt.Sprintf("tcp://127.0.0.1:%d", portA)},
		{ID: testutil.ID(41), Transport: model.QUIC, Source: model.Manual, URL: fmt.Sprintf("quic://127.0.0.1:%d", portA)},
	}
	edge := model.Edge{
		ID:         edgeID,
		A:          nodeA,
		B:          nodeB,
		Weight:     10,
		Enabled:    true,
		Transports: []model.Transport{model.TCP, model.QUIC},
		Methods:    model.ConnectionMethods{IPv4Direct: true},
	}
	addrA, addrB := netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.2")
	dir := []model.Destination{
		{NodeID: nodeA, Address: addrA, Index: 1},
		{NodeID: nodeB, Address: addrB, Client: true, Index: 2},
	}
	snapA := model.Snapshot{
		Schema:     model.SchemaVersion,
		Revision:   1,
		AgentID:    agentA,
		ListenPort: meshA.Port(),
		Endpoints:  epsA,
		Networks: []model.NetworkConfig{{
			ID:        netID,
			Name:      "net",
			CIDR:      netip.MustParsePrefix("10.42.0.0/24"),
			MTU:       1280,
			Cipher:    model.AES128GCM,
			Directory: dir,
			Self:      model.Node{ID: nodeA, AgentID: agentA, Name: "A", Address: addrA, Index: 1},
			Peers: []model.Peer{{
				Edge:      edge,
				Node:      model.Node{ID: nodeB, AgentID: agentB, Name: "B", Address: addrB, Client: true, Index: 2},
				PublicKey: keyB.Public().(ed25519.PublicKey),
			}},
		}},
	}
	if err := meshA.Apply(snapA); err != nil {
		t.Fatal(err)
	}
	snapB := func(rev uint64, peerEps []model.Endpoint) model.Snapshot {
		return model.Snapshot{
			Schema:     model.SchemaVersion,
			Revision:   rev,
			AgentID:    agentB,
			ListenPort: meshB.Port(),
			Networks: []model.NetworkConfig{{
				ID:        netID,
				Name:      "net",
				CIDR:      netip.MustParsePrefix("10.42.0.0/24"),
				MTU:       1280,
				Cipher:    model.AES128GCM,
				Directory: dir,
				Self:      model.Node{ID: nodeB, AgentID: agentB, Name: "B", Address: addrB, Client: true, Index: 2},
				Peers: []model.Peer{{
					Edge:      edge,
					Node:      model.Node{ID: nodeA, AgentID: agentA, Name: "A", Address: addrA, Index: 1},
					PublicKey: keyA.Public().(ed25519.PublicKey),
					Endpoints: peerEps,
				}},
			}},
		}
	}
	return meshA, meshB, snapB, epsA
}

func TestPreferredTransportExclusiveWhenReachable(t *testing.T) {
	_, meshB, snapB, epsA := newPreferredFixture(t, 71, model.QUIC)
	if err := meshB.Apply(snapB(1, epsA)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		rep := meshB.Report()
		if len(rep) == 1 && rep[0].Active && rep[0].Healthy && rep[0].Transport == model.QUIC {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected sole active healthy QUIC link, got %+v", meshB.Report())
}

func TestPreferredTransportFallbackAndSwitchback(t *testing.T) {
	meshA, meshB, snapB, epsA := newPreferredFixture(t, 81, model.QUIC)
	deadQuic := []model.Endpoint{
		{ID: testutil.ID(40), Transport: model.TCP, Source: model.Manual, URL: fmt.Sprintf("tcp://127.0.0.1:%d", meshA.Port())},
		{ID: testutil.ID(42), Transport: model.QUIC, Source: model.Manual, URL: "quic://127.0.0.1:1"},
	}
	if err := meshB.Apply(snapB(1, deadQuic)); err != nil {
		t.Fatal(err)
	}
	// 1. QUIC is unreachable -> must fall back to TCP.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range meshB.Report() {
			if l.Active && l.Healthy && l.Transport == model.TCP {
				goto tcpReady
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected fallback to TCP when QUIC unreachable, got %+v", meshB.Report())
tcpReady:

	// 2. QUIC endpoint becomes reachable -> must switch back to QUIC and retire TCP.
	if err := meshB.Apply(snapB(2, epsA)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rep := meshB.Report()
		if len(rep) == 1 && rep[0].Active && rep[0].Healthy && rep[0].Transport == model.QUIC {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected switchback to sole QUIC link after recovery, got %+v", meshB.Report())
}
