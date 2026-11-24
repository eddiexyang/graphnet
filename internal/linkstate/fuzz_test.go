package linkstate

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// Any Node of a Network can advertise, so an advertisement's bytes are a
// peer's choice; the engine refuses what it cannot use without panicking.
func FuzzReceive(f *testing.F) {
	state := testutil.Topology()
	n := state.Networks[0]
	snapshot, err := routing.Compile(state, n.Nodes[1].AgentID)
	if err != nil {
		f.Fatal(err)
	}
	seed0, seed1 := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seed0[0], seed1[0] = 1, 2
	key0, key1 := ed25519.NewKeyFromSeed(seed0), ed25519.NewKeyFromSeed(seed1)
	e := New(Callbacks{
		Identity: key1,
		Now:      time.Now,
		Send:     func(model.ID, model.ID, []byte) {},
		Local:    func() (map[model.ID]map[model.ID]bool, map[model.ID]map[model.ID]bool) { return nil, nil },
		Apply:    func(model.RouteUpdate) error { return nil },
	})
	e.Configure(snapshot)
	valid := LSA{Network: n.ID, Origin: n.Nodes[0].ID, Revision: snapshot.Revision, Sequence: uint64(time.Now().UnixNano()), Sync: true}
	valid.Sign(key0)
	signedRaw, _ := json.Marshal(valid)
	f.Add(signedRaw)
	f.Add([]byte(`{"kind":"lsa"}`))
	f.Add([]byte(`{"kind":"hello","network":"` + string(n.ID) + `"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		e.Receive(n.ID, n.Nodes[0].ID, raw)
	})
}
