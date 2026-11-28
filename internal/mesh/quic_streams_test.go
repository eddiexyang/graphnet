package mesh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/mesh"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
)

func newQUICStreamFixture(t *testing.T, seedOffset byte, quicOpts transport.QUICOptions, onPacket func([]byte), onStream mesh.StreamHandler) (*mesh.Mesh, *mesh.Mesh, model.ID, model.ID, model.ID) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var seedA, seedB [ed25519.SeedSize]byte
	seedA[0], seedB[0] = seedOffset, seedOffset+1
	keyA, keyB := ed25519.NewKeyFromSeed(seedA[:]), ed25519.NewKeyFromSeed(seedB[:])

	recvFn := func(_ context.Context, _ model.ID, owners []*packetbuf.Buffer) error {
		for _, b := range owners {
			if onPacket != nil && b != nil {
				cp := append([]byte(nil), b.Data...)
				onPacket(cp)
			}
		}
		packetbuf.ReleaseAll(owners)
		return nil
	}

	opts := mesh.Options{QUIC: quicOpts, PreferredTransport: model.QUIC}
	meshA, err := mesh.NewWithOptions(ctx, keyA, "127.0.0.1", 0, recvFn, noHeaders{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	meshA.EnableStreams(onStream)
	t.Cleanup(func() { _ = meshA.Close() })

	meshB, err := mesh.NewWithOptions(ctx, keyB, "127.0.0.1", 0, recvFn, noHeaders{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	meshB.EnableStreams(onStream)
	t.Cleanup(func() { _ = meshB.Close() })

	netID := testutil.ID(1)
	agentA, agentB := testutil.ID(11), testutil.ID(12)
	nodeA, nodeB := testutil.ID(10), testutil.ID(20)
	edgeID := testutil.ID(30)
	epsA := []model.Endpoint{
		{ID: testutil.ID(41), Transport: model.QUIC, Source: model.Manual, URL: fmt.Sprintf("quic://127.0.0.1:%d", meshA.Port())},
	}
	edge := model.Edge{
		ID:         edgeID,
		A:          nodeA,
		B:          nodeB,
		Weight:     10,
		Enabled:    true,
		Transports: []model.Transport{model.QUIC},
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
			ID:               netID,
			Name:             "net",
			CIDR:             netip.MustParsePrefix("10.42.0.0/24"),
			MTU:              1280,
			Cipher:           model.ChaCha20Poly1305,
			FailureDetection: 4000,
			Directory:        dir,
			Self:             model.Node{ID: nodeA, AgentID: agentA, Name: "A", Address: addrA, Index: 1},
			Peers: []model.Peer{{
				Edge:      edge,
				Node:      model.Node{ID: nodeB, AgentID: agentB, Name: "B", Address: addrB, Client: true, Index: 2},
				PublicKey: keyB.Public().(ed25519.PublicKey),
			}},
		}},
	}
	snapB := model.Snapshot{
		Schema:     model.SchemaVersion,
		Revision:   1,
		AgentID:    agentB,
		ListenPort: meshB.Port(),
		Networks: []model.NetworkConfig{{
			ID:               netID,
			Name:             "net",
			CIDR:             netip.MustParsePrefix("10.42.0.0/24"),
			MTU:              1280,
			Cipher:           model.ChaCha20Poly1305,
			FailureDetection: 4000,
			Directory:        dir,
			Self:             model.Node{ID: nodeB, AgentID: agentB, Name: "B", Address: addrB, Client: true, Index: 2},
			Peers: []model.Peer{{
				Edge:      edge,
				Node:      model.Node{ID: nodeA, AgentID: agentA, Name: "A", Address: addrA, Index: 1},
				PublicKey: keyA.Public().(ed25519.PublicKey),
				Endpoints: epsA,
			}},
		}},
	}
	if err := meshA.Apply(snapA); err != nil {
		t.Fatal(err)
	}
	if err := meshB.Apply(snapB); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if meshB.StreamsAvailable(netID, nodeA) && meshA.StreamsAvailable(netID, nodeB) {
			return meshA, meshB, netID, nodeA, nodeB
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("QUIC streams did not become available")
	return nil, nil, "", "", ""
}

func TestQUICStreamsBackpressureIsolationAndPackets(t *testing.T) {
	stalledGate := make(chan struct{})
	defer close(stalledGate)

	var rxPackets atomic.Int32
	handler := func(ctx context.Context, _ model.ID, _ model.ID, conn streamproxy.Conn) {
		var tag [1]byte
		if _, err := io.ReadFull(conn, tag[:]); err != nil {
			return
		}
		if tag[0] == 'S' {
			// Stop reading to stall this stream's QUIC flow-control window.
			<-stalledGate
			return
		}
		_, _ = io.Copy(conn, conn)
		_ = conn.CloseWrite()
	}

	quicOpts := transport.QUICOptions{
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         128 << 10,
		InitialConnectionReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow:     8 << 20,
	}
	_, meshB, netID, nodeA, _ := newQUICStreamFixture(t, 70, quicOpts, func([]byte) {
		rxPackets.Add(1)
	}, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Open a stalled stream and saturate its per-stream receive window.
	stalled, err := meshB.OpenStream(ctx, netID, nodeA)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	if _, err := stalled.Write([]byte{'S'}); err != nil {
		t.Fatal(err)
	}
	stalledDone := make(chan error, 1)
	go func() {
		_, werr := stalled.Write(make([]byte, 1<<20))
		stalledDone <- werr
	}()
	time.Sleep(80 * time.Millisecond)

	// Concurrently run 4 parallel 512 KiB echo streams and send L3 overlay frames.
	const workers = 4
	const payloadSize = 512 << 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			s, err := meshB.OpenStream(ctx, netID, nodeA)
			if err != nil {
				errCh <- err
				return
			}
			defer s.Close()
			src := bytes.Repeat([]byte{byte('A' + id)}, payloadSize)
			go func() {
				_, _ = s.Write(append([]byte{'E'}, src...))
				_ = s.CloseWrite()
			}()
			got, rerr := io.ReadAll(s)
			if rerr != nil {
				errCh <- rerr
				return
			}
			if !bytes.Equal(got, src) {
				errCh <- fmt.Errorf("worker %d payload mismatch: got %d bytes", id, len(got))
			}
		}(i)
	}

	// Send 32 non-IP overlay frames on the dedicated packet substream.
	frame := make([]byte, packet.HeaderSize+64)
	frame[6] = 2 // non-KindIP overlay frame
	for range 32 {
		if err := meshB.Send(ctx, netID, nodeA, frame); err != nil {
			t.Fatalf("Send overlay packet: %v", err)
		}
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for rxPackets.Load() < 32 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rxPackets.Load() != 32 {
		t.Fatalf("received %d overlay packets, want 32", rxPackets.Load())
	}

	// Stalled stream must still be blocked on its own flow control while Link stays healthy.
	select {
	case err := <-stalledDone:
		t.Fatalf("stalled stream exited prematurely: %v", err)
	default:
	}
	for _, st := range meshB.Report() {
		if !st.Healthy {
			t.Fatalf("QUIC Link became unhealthy while one stream stalled: %+v", st)
		}
	}
}

func TestQUICStreamHopSessionDeliveryAndAbort(t *testing.T) {
	serverHopCh := make(chan streamproxy.Hop, 4)
	handler := func(ctx context.Context, _ model.ID, _ model.ID, conn streamproxy.Conn) {
		hop, ok := conn.(streamproxy.Hop)
		if !ok {
			return
		}
		var mode [1]byte
		if _, err := io.ReadFull(hop, mode[:]); err != nil {
			return
		}
		switch mode[0] {
		case 1:
			hop.DeliverLocal()
			hop.Begin(500)
			_, _ = io.Copy(io.Discard, hop)
			_ = hop.CloseWrite()
			serverHopCh <- hop
			<-hop.Done()
		case 2:
			hop.AbortSession()
		case 3:
			hop.Abort()
		}
	}

	_, meshB, netID, nodeA, _ := newQUICStreamFixture(t, 90, transport.QUICOptions{}, nil, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Session delivery offset + PeerEnded + Ended.
	c1, err := meshB.OpenStream(ctx, netID, nodeA)
	if err != nil {
		t.Fatal(err)
	}
	hop1 := c1.(streamproxy.Hop)
	if _, err := hop1.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	const startOffset = 10000
	hop1.DeliverLocal()
	hop1.Begin(startOffset)
	data := bytes.Repeat([]byte{0x5a}, 160*1024)
	if _, err := hop1.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := hop1.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(hop1); err != nil {
		t.Fatal(err)
	}
	if !hop1.Ended() {
		t.Fatal("expected hop1.Ended() == true after session CloseWrite")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !hop1.PeerEnded() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !hop1.PeerEnded() {
		t.Fatalf("PeerEnded did not turn true; PeerDelivered=%d", hop1.PeerDelivered())
	}
	_ = hop1.Close()

	select {
	case shop := <-serverHopCh:
		if !shop.Ended() {
			t.Fatal("expected server hop Ended() == true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server hop")
	}

	// 2. AbortSession sets Aborted() == true on peer.
	c2, err := meshB.OpenStream(ctx, netID, nodeA)
	if err != nil {
		t.Fatal(err)
	}
	hop2 := c2.(streamproxy.Hop)
	if _, err := hop2.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_, rerr := hop2.Read(buf)
	if rerr == nil || errors.Is(rerr, io.EOF) {
		t.Fatalf("expected reset error on AbortSession, got %v", rerr)
	}
	if !hop2.Aborted() {
		t.Fatal("expected Aborted() == true on AbortSession")
	}
	_ = hop2.Close()

	// 3. Abort (hop reset) leaves Aborted() == false on peer.
	c3, err := meshB.OpenStream(ctx, netID, nodeA)
	if err != nil {
		t.Fatal(err)
	}
	hop3 := c3.(streamproxy.Hop)
	if _, err := hop3.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	_, rerr = hop3.Read(buf)
	if rerr == nil || errors.Is(rerr, io.EOF) {
		t.Fatalf("expected reset error on Abort, got %v", rerr)
	}
	if hop3.Aborted() {
		t.Fatal("expected Aborted() == false on hop-level Abort")
	}
	_ = hop3.Close()
}
