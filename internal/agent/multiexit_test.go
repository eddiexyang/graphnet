package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/routing"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// B (cost 10 + metric 0) and D (1 + 20) both advertise 192.168.0.0/24.
// Live connections stay pinned to their original exit across topology edits,
// temporary total-uplink outages and exit-metric changes, while new
// connections pick the cheaper exit D. Withdrawing the exit's prefix resets
// connections using that exit without continuing them on D.
func TestTCPConnectionResetsOnExitChange(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.0.0/24")
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].Nodes[1].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff}}
		s.Networks[0].Nodes[3].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff, Metric: 20}}
	})
	waitConverged(t, agents[0], state, 0)
	server := tcpip.AddrFrom4(netip.MustParseAddr("192.168.0.7").As4())
	accepted := make(chan int, 8)
	for _, exit := range []int{1, 3} {
		exit := exit
		if err := devices[exit].stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: server, PrefixLen: 32}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		listener, err := gonet.ListenTCP(devices[exit].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
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
				accepted <- exit
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
	}
	dial := func() (net.Conn, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := devices[0].dialTCP(ctx, server, 9000, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case exit := <-accepted:
			return conn, exit
		case <-time.After(10 * time.Second):
			t.Fatal("no exit accepted the connection")
		}
		return nil, 0
	}
	echo := func(conn net.Conn) {
		t.Helper()
		payload := make([]byte, 1<<20)
		rand.Read(payload)
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		go conn.Write(payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("echo: %v", err)
		}
	}

	// Phase 1: Establish live stream through B and keep it uninterrupted across:
	// (a) adding and removing an unrelated node + cipher change,
	// (b) temporary isolation of A where all exits are unreachable, and
	// (c) raising B's metric so D becomes the preferred exit for new flows.
	conn, exit := dial()
	defer conn.Close()
	if exit != 1 {
		t.Fatalf("first connection exits at node %d, want B", exit)
	}
	sent := make([]byte, 6<<20)
	rand.Read(sent)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	writeErr := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(sent); offset += 16 << 10 {
			if _, err := conn.Write(sent[offset : offset+16<<10]); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	received := make([]byte, 0, len(sent))
	buf := make([]byte, 64<<10)
	step := 0
	for len(received) < len(sent) {
		n, err := conn.Read(buf[:min(len(buf), len(sent)-len(received))])
		if err != nil {
			t.Fatalf("live connection interrupted at step %d (%d/%d bytes): %v", step, len(received), len(sent), err)
		}
		received = append(received, buf[:n]...)
		if !bytes.Equal(received, sent[:len(received)]) {
			t.Fatalf("echo differs from sent stream within %d bytes", len(received))
		}
		switch {
		case step == 0 && len(received) >= 1<<20:
			step = 1
			// (a) Add and remove an unrelated remote node and a local subnet on A
			// (both previously invalidated tcpFingerprint and tore down Engine).
			base := state.Networks[0].CIDR.Addr().As4()
			base[3] = 99
			extraPub, _, _ := ed25519.GenerateKey(rand.Reader)
			extraAgent := model.Agent{ID: model.NewID(), Name: "extra", PublicKey: extraPub, ListenPort: 24752}
			extraNode := model.Node{ID: model.NewID(), Name: "extra", Index: 99, AgentID: extraAgent.ID, Address: netip.AddrFrom4(base)}
			state.Revision++
			state.Agents = append(state.Agents, extraAgent)
			state.Networks[0].Nodes = append(state.Networks[0].Nodes, extraNode)
			state.Networks[0].LastIndex = 99
			state.Networks[0].Nodes[2].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: netip.MustParsePrefix("172.30.0.0/24"), GatewayMode: model.GatewayOff}}
			applyAll(t, agents, state)

			state.Revision++
			state.Networks[0].Nodes = state.Networks[0].Nodes[:4]
			state.Agents = state.Agents[:4]
			state.Networks[0].Nodes[2].AdvertisedSubnets = nil
			applyAll(t, agents, state)
		case step == 1 && len(received) >= 2<<20:
			step = 2
			// (b) Drop all routes on A so every exit is temporarily unreachable, then restore.
			compiledA, err := routing.Compile(state, state.Agents[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := agents[0].ApplyRoutes(model.RouteUpdate{
				Revision: state.Revision,
				Networks: []model.NetworkRoutes{{ID: state.Networks[0].ID, Routes: nil}},
			}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
			if err := agents[0].ApplyRoutes(model.RouteUpdate{
				Revision: state.Revision,
				Networks: []model.NetworkRoutes{{ID: state.Networks[0].ID, Routes: compiledA.Networks[0].Routes}},
			}); err != nil {
				t.Fatal(err)
			}
		case step == 2 && len(received) >= 3<<20:
			step = 3
			// (c) Make D cheaper than B: live session stays on B without resetting.
			state.Revision++
			state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 50 // B: 60, D: 21
			applyAll(t, agents, state)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writer failed on live connection: %v", err)
	}
	if agents[0].Counters()["session_exit_resets"] != 0 {
		t.Fatalf("unexpected exit resets during topology/uplink/metric changes: %d", agents[0].Counters()["session_exit_resets"])
	}

	// New connections now pick the cheaper exit D while B still advertises the prefix.
	second, exit := dial()
	defer second.Close()
	if exit != 3 {
		t.Fatalf("new connection exits at node %d, want D", exit)
	}
	echo(second)

	// Phase 2: Withdraw D's prefix while streaming on a live connection through D;
	// that connection must reset cleanly and never continue at B.
	third, exit := dial()
	defer third.Close()
	if exit != 3 {
		t.Fatalf("third connection exits at node %d, want D", exit)
	}
	third.SetDeadline(time.Now().Add(20 * time.Second))
	withdrawSent := make([]byte, 32<<20)
	rand.Read(withdrawSent)
	withdrawWriteErr := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(withdrawSent); offset += 16 << 10 {
			if _, err := third.Write(withdrawSent[offset : offset+16<<10]); err != nil {
				withdrawWriteErr <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
		withdrawWriteErr <- nil
	}()
	withdrawReceived := make([]byte, 0, len(withdrawSent))
	withdrawn := false
	var readErr error
	for readErr == nil {
		var n int
		n, readErr = third.Read(buf)
		withdrawReceived = append(withdrawReceived, buf[:n]...)
		if !bytes.Equal(withdrawReceived, withdrawSent[:len(withdrawReceived)]) {
			t.Fatalf("echo differs before withdrawal within %d bytes", len(withdrawReceived))
		}
		if !withdrawn && len(withdrawReceived) >= 512<<10 {
			withdrawn = true
			state.Revision++
			state.Networks[0].Nodes[3].AdvertisedSubnets = nil
			applyAll(t, agents, state)
		}
	}
	if !withdrawn {
		t.Fatalf("connection ended before prefix withdrawal: %v", readErr)
	}
	var written error
	select {
	case written = <-withdrawWriteErr:
	case <-time.After(5 * time.Second):
	}
	reset := func(err error) bool { return err != nil && strings.Contains(err.Error(), "connection reset by peer") }
	if !reset(readErr) && !reset(written) {
		t.Fatalf("connection through withdrawn exit was not reset: read %v, write %v", readErr, written)
	}
	select {
	case other := <-accepted:
		t.Fatalf("the connection continued at node %d", other)
	default:
	}
	if agents[0].Counters()["session_exit_resets"] == 0 {
		t.Fatal("no exit reset counted on prefix withdrawal")
	}
	assertNoTCPOverTCP(t, agents)
}

// exitServer is the address B and D's prefix holds in the exit tests.
var exitServer = netip.MustParseAddr("192.168.0.7")

// exitAgents has B (cost 10 + metric 0) and D (1 + dMetric) advertise
// 192.168.0.0/24 and capture the UDP datagrams written to their devices.
func exitAgents(t *testing.T, carrier model.Transport, dMetric uint32, paths model.EqualCostPaths) ([]*DataPlane, []*kernelTUN, model.State) {
	t.Helper()
	prefix := netip.MustParsePrefix("192.168.0.0/24")
	agents, devices, state := graphAgents(t, carrier, streamOptions{}, 4, 4, func(s *model.State) {
		s.Networks[0].EqualCostPaths = paths
		s.Networks[0].Nodes[1].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff}}
		s.Networks[0].Nodes[3].AdvertisedSubnets = []model.AdvertisedSubnet{{Prefix: prefix, GatewayMode: model.GatewayOff, Metric: dMetric}}
	})
	for _, exit := range []int{1, 3} {
		devices[exit].setUDP(make(chan []byte, 4096))
	}
	waitConverged(t, agents[0], state, 0)
	return agents, devices, state
}

// datagramExit sends one datagram from port from at A to the exit server and
// reports which exit's device received it, unchanged.
func datagramExit(t *testing.T, devices []*kernelTUN, state model.State, from uint16) int {
	t.Helper()
	source := netip.AddrPortFrom(state.Networks[0].Nodes[0].Address, from)
	destination := netip.AddrPortFrom(exitServer, 5001)
	message := []byte(fmt.Sprintf("datagram from %d", from))
	raw := packet.UDP(source, destination, message)
	for attempt := 0; attempt < 50; attempt++ {
		devices[0].packets <- kernelPacket{raw: bytes.Clone(raw)}
		select {
		case got := <-devices[1].udp:
			return checkDatagram(t, got, source, destination, message, 1)
		case got := <-devices[3].udp:
			return checkDatagram(t, got, source, destination, message, 3)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("no exit received the datagram")
	return 0
}

func checkDatagram(t *testing.T, got []byte, source, destination netip.AddrPort, message []byte, exit int) int {
	t.Helper()
	if s, d, payload, ok := packet.UDPDatagram(got); !ok || s != source || d != destination || !bytes.Equal(payload, message) {
		t.Fatalf("exit %d received a changed datagram", exit)
	}
	return exit
}

// Datagrams move to the cheaper exit with the next packet.
func TestPacketsFollowExitChange(t *testing.T) {
	agents, devices, state := exitAgents(t, model.UDP, 20, model.EqualCostLowestID)
	if exit := datagramExit(t, devices, state, 6000); exit != 1 {
		t.Fatalf("datagram exits at node %d, want B", exit)
	}
	state.Revision++
	state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 50 // B: 60, D: 21
	applyAll(t, agents, state)
	for port := uint16(6001); port < 6021; port++ {
		if exit := datagramExit(t, devices, state, port); exit != 3 {
			t.Fatalf("datagram %d after the change exits at node %d, want D", port, exit)
		}
	}
}

// With ECMP between two exits of equal cost, each flow keeps one exit and
// both exits carry flows; when one exit becomes dearer every flow moves to
// the other at once.
func TestSealedECMPKeepsEachFlowOnOneExit(t *testing.T) {
	agents, devices, state := exitAgents(t, model.UDP, 9, model.EqualCostECMP) // B: 10, D: 10
	exits := map[uint16]int{}
	used := map[int]int{}
	for port := uint16(7000); port < 7064; port++ {
		exit := datagramExit(t, devices, state, port)
		exits[port] = exit
		used[exit]++
	}
	if used[1] == 0 || used[3] == 0 {
		t.Fatalf("flows per exit %v, want both", used)
	}
	for port, exit := range exits {
		for range 3 {
			if again := datagramExit(t, devices, state, port); again != exit {
				t.Fatalf("flow %d moved from node %d to %d", port, exit, again)
			}
		}
	}
	state.Revision++
	state.Networks[0].Nodes[1].AdvertisedSubnets[0].Metric = 10 // B: 20, D: 10
	applyAll(t, agents, state)
	for port := range exits {
		if exit := datagramExit(t, devices, state, port); exit != 3 {
			t.Fatalf("flow %d exits at node %d after B became dearer", port, exit)
		}
	}
}

// With ECMP between two exits of equal cost, TCP connections spread over both
// exits.
func TestECMPSpreadsConnections(t *testing.T) {
	agents, devices, _ := exitAgents(t, model.TCP, 9, model.EqualCostECMP) // B: 10, D: 10
	server := tcpip.AddrFrom4(exitServer.As4())
	accepted := make(chan int, 64)
	for _, exit := range []int{1, 3} {
		if err := devices[exit].stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: server, PrefixLen: 32}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		listener, err := gonet.ListenTCP(devices[exit].stack, tcpip.FullAddress{NIC: 1, Addr: server, Port: 9000}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				accepted <- exit
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
	}
	used := map[int]int{}
	for i := range 64 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := devices[0].dialTCP(ctx, server, 9000, ipv4.ProtocolNumber)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		message := []byte(fmt.Sprintf("connection %d", i))
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		got := make([]byte, len(message))
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, message) {
			t.Fatalf("connection %d: %v", i, err)
		}
		conn.Close()
		select {
		case exit := <-accepted:
			used[exit]++
		case <-time.After(5 * time.Second):
			t.Fatalf("no exit accepted connection %d", i)
		}
	}
	if used[1] == 0 || used[3] == 0 || used[1]+used[3] != 64 {
		t.Fatalf("connections per exit %v, want both", used)
	}
	assertNoTCPOverTCP(t, agents)
}

// waitConverged waits until the routes the agent of Node index forwards on
// equal the routes compiled from state: each destination's next hop and cost
// are final, so traffic chooses between the exits on settled costs.
func waitConverged(t *testing.T, agent *DataPlane, state model.State, index int) {
	t.Helper()
	compiled, err := routing.Compile(state, state.Agents[index].ID)
	if err != nil {
		t.Fatal(err)
	}
	type hop struct {
		next model.ID
		cost uint64
	}
	want := map[model.ID]hop{}
	for _, r := range compiled.Networks[0].Routes {
		want[r.Destination] = hop{r.NextHop, r.Cost}
	}
	network := state.Networks[0].ID
	waitFor(t, 15*time.Second, "converged routes", func() bool {
		agent.applyMu.Lock()
		installed := agent.lastRoutes
		agent.applyMu.Unlock()
		if installed == nil {
			return false
		}
		for _, n := range installed.Networks {
			if n.ID != network {
				continue
			}
			got := map[model.ID]hop{}
			for _, r := range n.Routes {
				got[r.Destination] = hop{r.NextHop, r.Cost}
			}
			if len(got) != len(want) {
				return false
			}
			for d, h := range want {
				if got[d] != h {
					return false
				}
			}
			return true
		}
		return false
	})
}
