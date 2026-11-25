package linkstate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// clientLab starts every node with D as a client leaf, except those in skip.
func clientLab(t *testing.T, skip ...model.ID) *lab {
	l := newLab(t, nodeA, nodeB, nodeC, nodeD)
	l.state.Networks[0].Nodes[3].Client = true
	skipped := map[model.ID]bool{}
	for _, id := range skip {
		skipped[id] = true
	}
	for _, node := range l.state.Networks[0].Nodes {
		if !skipped[node.ID] {
			l.start(node)
		}
	}
	return l
}

// An offline client leaf does not hold its component on the legacy cadence.
func TestOfflineClientKeepsComponentOnSync(t *testing.T) {
	l := clientLab(t, nodeD)
	l.run(2 * time.Second)
	netID := l.state.Networks[0].ID
	for _, id := range []model.ID{nodeA, nodeB, nodeC} {
		if !l.engines[id].networks[netID].supportsSync() {
			t.Fatalf("%s fell back to the legacy cadence for an offline client", id)
		}
	}
}

// A client repairs an advertisement it lost through sync, not only through
// the origin's next full refresh.
func TestClientRepairsLostAdvertisementThroughSync(t *testing.T) {
	l := clientLab(t)
	l.run(time.Second)
	netID := l.state.Networks[0].ID
	// Lose every advertisement the routers send D while the A-B edge fails.
	for _, id := range []model.ID{nodeA, nodeC} {
		e := l.engines[id]
		send := e.cb.Send
		e.cb.Send = func(network, peer model.ID, raw []byte) bool {
			var msg syncMessage
			json.Unmarshal(raw, &msg)
			if peer == nodeD && msg.Kind == "" {
				return true // queued, then lost in transit
			}
			return send(network, peer, raw)
		}
		t.Cleanup(func() { e.cb.Send = send })
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	if l.engines[nodeD].networks[netID].db[nodeA].up[edgeAB] == false {
		t.Fatal("D received A's advertisement although it was lost")
	}
	for _, id := range []model.ID{nodeA, nodeC} {
		l.engines[id].cb.Send = func(network, peer model.ID, raw []byte) bool {
			l.queue = append(l.queue, message{network, id, peer, append([]byte(nil), raw...)})
			return true
		}
	}
	l.run(SyncInterval + time.Second)
	if l.engines[nodeD].networks[netID].db[nodeA].up[edgeAB] {
		t.Fatal("D still holds A's lost advertisement after a sync round")
	}
}

// An edge named by an advertisement that arrived before the revision adding
// it is usable as soon as that revision is configured.
func TestConfigureRefiltersRetainedAdvertisements(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	netID := l.state.Networks[0].ID
	next := l.state
	next.Revision++
	next.Networks = []model.Network{l.state.Networks[0]}
	newEdge := model.Edge{ID: testutil.ID(44), A: nodeB, B: nodeD, Weight: 5, Enabled: true, Transports: []model.Transport{model.UDP}, Methods: model.ConnectionMethods{IPv4Direct: true}}
	next.Networks[0].Edges = append(append([]model.Edge{}, l.state.Networks[0].Edges...), newEdge)
	// B advertises the new edge before A knows it.
	b := LSA{Network: netID, Origin: nodeB, Revision: next.Revision, Sequence: uint64(l.now.UnixNano()), Up: []model.ID{edgeAB, newEdge.ID}, Sync: true}
	b.Sign(agentKeyFor(l.state, l.state.Agents[1].ID))
	raw, _ := json.Marshal(b)
	engA := l.engines[nodeA]
	if err := engA.Receive(netID, nodeB, raw); err != nil {
		t.Fatal(err)
	}
	if engA.networks[netID].db[nodeB].up[newEdge.ID] {
		t.Fatal("an edge outside the configured topology was accepted")
	}
	snapshot, err := routing.Compile(next, l.state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	l.configure(nodeA, engA, snapshot)
	if !engA.networks[netID].db[nodeB].up[newEdge.ID] {
		t.Fatal("the new edge stayed stripped from B's advertisement after Configure")
	}
}
