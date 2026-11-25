package linkstate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

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
