package linkstate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

type message struct {
	network, from, to model.ID
	raw               []byte
}

// lab runs one engine per Agent of the test topology over an in-memory,
// lossless network with a shared fake clock.
type lab struct {
	t        *testing.T
	state    model.State
	now      time.Time
	engines  map[model.ID]*Engine // node ID -> engine
	routes   map[model.ID]model.RouteUpdate
	down     map[model.ID]bool // edge ID -> failed
	fallback map[model.ID]bool // failed edge still carrying traffic
	queue    []message
	legacyD  bool
	// apply, when set, can fail route installs before they reach the table.
	apply     func(node model.ID, u model.RouteUpdate) error
	snapshots map[model.ID]model.Snapshot
	keys      map[model.ID]ed25519.PrivateKey
}

func agentKeyFor(state model.State, agentID model.ID) ed25519.PrivateKey {
	for i, a := range state.Agents {
		if a.ID == agentID {
			seed := make([]byte, ed25519.SeedSize)
			seed[0] = byte(i + 1)
			priv := ed25519.NewKeyFromSeed(seed)
			if bytes.Equal(priv.Public().(ed25519.PublicKey), a.PublicKey) {
				return priv
			}
		}
	}
	return nil
}

// configure installs a configuration and its routes as the Agent does.
func (l *lab) configure(node model.ID, e *Engine, s model.Snapshot) {
	if u := e.Configure(s); u != nil {
		err := e.cb.Apply(*u)
		e.Applied(*u, err, 0)
	}
}

func newLab(t *testing.T, without ...model.ID) *lab {
	l := &lab{t: t, state: testutil.Topology(), now: time.Unix(1_800_000_000, 0), engines: map[model.ID]*Engine{}, routes: map[model.ID]model.RouteUpdate{}, down: map[model.ID]bool{}, fallback: map[model.ID]bool{}, snapshots: map[model.ID]model.Snapshot{}}
	skip := map[model.ID]bool{}
	for _, id := range without {
		skip[id] = true
	}
	for _, node := range l.state.Networks[0].Nodes {
		if !skip[node.ID] {
			l.start(node)
		}
	}
	return l
}

func (l *lab) start(node model.Node) {
	snapshot, err := routing.Compile(l.state, node.AgentID)
	if err != nil {
		l.t.Fatal(err)
	}
	self := node.ID
	var identity ed25519.PrivateKey
	if l.keys != nil {
		identity = l.keys[self]
	}
	if identity == nil {
		identity = agentKeyFor(l.state, node.AgentID)
	}
	var e *Engine
	e = New(Callbacks{
		Identity: identity,
		Now:      func() time.Time { return l.now },
		Send: func(network, peer model.ID, raw []byte) {
			l.queue = append(l.queue, message{network, self, peer, append([]byte(nil), raw...)})
		},
		Local: func() (map[model.ID]map[model.ID]bool, map[model.ID]map[model.ID]bool) {
			up := map[model.ID]bool{}
			fallback := map[model.ID]bool{}
			for _, p := range snapshot.Networks[0].Peers {
				// A link is healthy only if both Agents run and the edge works.
				if _, running := l.engines[p.Node.ID]; running || l.legacy(p.Node.ID) {
					if !l.down[p.Edge.ID] {
						up[p.Edge.ID] = true
					} else if l.fallback[p.Edge.ID] {
						fallback[p.Edge.ID] = true
					}
				}
			}
			id := snapshot.Networks[0].ID
			return map[model.ID]map[model.ID]bool{id: up}, map[model.ID]map[model.ID]bool{id: fallback}
		},
		Apply: func(u model.RouteUpdate) error {
			if l.apply != nil {
				if err := l.apply(self, u); err != nil {
					return err
				}
			}
			if _, err := u.Apply(*e.snapshot); err != nil {
				return err
			}
			l.routes[self] = u
			return nil
		},
	})
	l.snapshots[self] = snapshot
	l.configure(self, e, snapshot)
	l.engines[self] = e
	for _, p := range snapshot.Networks[0].Peers {
		e.PeerReady(snapshot.Networks[0].ID, p.Node.ID)
		if other := l.engines[p.Node.ID]; other != nil {
			other.PeerReady(snapshot.Networks[0].ID, self)
		}
	}
}

// legacy marks nodes deliberately run without the engine but still forwarding.
func (l *lab) legacy(node model.ID) bool { return node == testutil.ID(23) && l.legacyD }

// run advances the clock in engine ticks, delivering messages, until quiet.
func (l *lab) run(d time.Duration) {
	for end := l.now.Add(d); l.now.Before(end); l.now = l.now.Add(tick) {
		for _, e := range l.engines {
			e.Step()
		}
		for len(l.queue) > 0 {
			m := l.queue[0]
			l.queue = l.queue[1:]
			edge := l.edge(m.from, m.to)
			if dst := l.engines[m.to]; dst != nil && (!l.down[edge] || l.fallback[edge]) {
				dst.Receive(m.network, m.from, m.raw)
			}
		}
	}
}

func (l *lab) edge(a, b model.ID) model.ID {
	for _, e := range l.state.Networks[0].Edges {
		if e.A == a && e.B == b || e.A == b && e.B == a {
			return e.ID
		}
	}
	return ""
}

func (l *lab) route(from, to model.ID) model.Route {
	for _, r := range l.routes[from].Networks[0].Routes {
		if r.Destination == to {
			return r
		}
	}
	return model.Route{}
}

var (
	nodeA, nodeB, nodeC, nodeD = testutil.ID(20), testutil.ID(21), testutil.ID(22), testutil.ID(23)
	edgeAB                     = testutil.ID(40)
)

func TestConvergesToCompiledRoutes(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	for node, e := range l.engines {
		snapshot := e.snapshot
		if !reflect.DeepEqual(l.routes[node].Networks[0].Routes, snapshot.Networks[0].Routes) {
			t.Fatalf("%s: %v, compiled %v", node, l.routes[node].Networks[0].Routes, snapshot.Networks[0].Routes)
		}
	}
}

func TestLinkFailureReroutesWithoutController(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("initial A->C %+v", r)
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD || r.Cost != 31 {
		t.Fatalf("A->C after A-B failure %+v", r)
	}
	// B learns it as well, through C.
	if r := l.route(nodeB, nodeA); r.NextHop != nodeC {
		t.Fatalf("B->A after A-B failure %+v", r)
	}
	delete(l.down, edgeAB)
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("A->C after recovery %+v", r)
	}
}

func TestFallbackEdgeKeepsOnlyRoute(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	l.down[edgeAB], l.fallback[edgeAB] = true, true
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD || r.Cost != 31 {
		t.Fatalf("A->C with healthy alternative: %+v", r)
	}

	l.down[l.edge(nodeD, nodeC)] = true
	l.run(time.Second)
	if r := l.route(nodeD, nodeC); r.NextHop != nodeA || r.Cost != 21 {
		t.Fatalf("D->C with only an unhealthy path: %+v", r)
	}
	if r := l.route(nodeB, nodeD); r.NextHop != nodeA || r.Cost != 11 {
		t.Fatalf("B->D without another link-state adjacency: %+v", r)
	}

	delete(l.fallback, edgeAB)
	l.run(time.Second)
	if r := l.route(nodeD, nodeC); r.NextHop != "" {
		t.Fatalf("D->C after the fallback closes: %+v", r)
	}
}

// A failure of this Agent's own Link moves its routes in the step that sees
// it, without waiting for an SPF delay or the next tick.
func TestOwnLinkFailureReroutesInTheSameStep(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("initial A->C %+v", r)
	}
	l.down[edgeAB] = true
	l.engines[nodeA].Step()
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD {
		t.Fatalf("A->C in the step that saw A-B fail %+v", r)
	}
}

func TestEndpointWithoutLinkStateDefersToNeighbour(t *testing.T) {
	l := newLab(t, nodeD)
	l.legacyD = true
	l.run(time.Second)
	if r := l.route(nodeA, nodeD); r.NextHop != nodeD {
		t.Fatalf("A->D through a legacy D %+v", r)
	}
	l.down[testutil.ID(42)] = true // A-D
	l.run(time.Second)
	if r := l.route(nodeA, nodeD); r.NextHop != nodeB {
		t.Fatalf("A->D after A-D failure reported by A alone %+v", r)
	}
}

func TestSilentOriginExpires(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	delete(l.engines, nodeC) // C stops: no refresh, links to it fail
	l.run(time.Second)
	if _, ok := l.route(nodeA, nodeC), true; !ok {
		t.Fatal()
	}
	view := l.engines[nodeA].View()
	if !hasOrigin(view, nodeC) {
		t.Fatal("C's LSA vanished before MaxAge")
	}
	l.run(MaxAge + time.Second)
	if hasOrigin(l.engines[nodeA].View(), nodeC) {
		t.Fatal("C's LSA did not expire")
	}
	if r := l.route(nodeA, nodeC); r.NextHop != "" {
		t.Fatalf("route to a failed node %+v", r)
	}
}

func TestRestartContinuesAboveOwnSequence(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	before := l.engines[nodeA].View().Networks[0].Sequence
	l.now = l.now.Add(-10 * time.Minute) // a restarted Agent with a clock behind
	delete(l.engines, nodeA)
	l.start(l.state.Networks[0].Nodes[0])
	l.run(time.Second)
	after := l.engines[nodeB].View()
	for _, o := range after.Networks[0].Database {
		if o.Origin == nodeA && o.Sequence <= before {
			t.Fatalf("B still holds A's pre-restart sequence %d <= %d", o.Sequence, before)
		}
	}
}

// An origin's current advertisement can return through the flood when a
// neighbour receives it first along a longer path; the echo must not trigger
// another origination, or every origin re-advertises on each tick.
func TestOwnAdvertisementEchoIsIgnored(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	network := l.state.Networks[0].ID
	echo, _ := json.Marshal(l.engines[nodeB].networks[network].db[nodeA].lsa)
	before := a.View().Networks[0].Sequence
	if err := a.Receive(network, nodeB, echo); err != nil {
		t.Fatal(err)
	}
	l.run(time.Second)
	if after := a.View().Networks[0].Sequence; after != before {
		t.Fatalf("echo of the current advertisement re-originated it: %d -> %d", before, after)
	}
}

// A new revision that leaves the topology alone gets routes for that revision
// at once but is not advertised again.
func TestRevisionWithoutTopologyChangeIsNotAdvertised(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	before := a.View().Networks[0].Sequence
	next := l.snapshots[nodeA]
	next.Revision++
	l.configure(nodeA, a, next)
	if got := l.routes[nodeA].Revision; got != next.Revision {
		t.Fatalf("routes for revision %d after configuring %d", got, next.Revision)
	}
	l.run(time.Second)
	if after := a.View().Networks[0].Sequence; after != before {
		t.Fatalf("unchanged topology re-advertised: %d -> %d", before, after)
	}
}

// Routes computed for a configuration that was replaced before they were
// installed are superseded, not failures; a real failure is retried.
func TestSupersededAndFailedRouteInstalls(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	a := l.engines[nodeA]
	// While A's routes for the failed edge wait to be installed, the Agent
	// applies a newer configuration with its own routes, then rejects them.
	next := l.snapshots[nodeA]
	next.Revision++
	l.apply = func(node model.ID, u model.RouteUpdate) error {
		if node == nodeA && u.Revision < next.Revision {
			l.apply = nil
			l.snapshots[nodeA] = next
			l.configure(nodeA, a, next)
			return ErrSuperseded
		}
		return nil
	}
	l.down[edgeAB] = true
	l.run(time.Second)
	c := a.View().Counters
	if c["routes_superseded"] != 1 || c["route_apply_errors"] != 0 {
		t.Fatalf("counters %v", c)
	}
	if r := l.route(nodeA, nodeC); r.NextHop != nodeD || l.routes[nodeA].Revision != next.Revision {
		t.Fatalf("A->C %+v at revision %d", r, l.routes[nodeA].Revision)
	}
	failures := 1
	l.apply = func(node model.ID, u model.RouteUpdate) error {
		if node == nodeA && failures > 0 {
			failures--
			return errors.New("router busy")
		}
		return nil
	}
	delete(l.down, edgeAB)
	l.run(time.Second)
	if c := a.View().Counters; c["route_apply_errors"] != 1 {
		t.Fatalf("counters %v", c)
	}
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB {
		t.Fatalf("failed install was not retried: A->C %+v", r)
	}
	var kinds []string
	for _, ev := range a.View().Events {
		if ev.Edge == edgeAB {
			kinds = append(kinds, ev.Kind)
		}
	}
	// The first edge-up is the Link coming up at start.
	if !slices.Equal(kinds, []string{"edge-up", "edge-down", "edge-up"}) {
		t.Fatalf("A-B edge events %v", kinds)
	}
}

// Until local Links have been polled, a configuration keeps its compiled
// routes: link-state would otherwise report every local edge down.
func TestFirstConfigurationKeepsCompiledRoutesUntilObserved(t *testing.T) {
	state := testutil.Topology()
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	e := New(Callbacks{
		Identity: agentKeyFor(state, state.Agents[0].ID),
		Send:     func(model.ID, model.ID, []byte) {},
		Local:    func() (map[model.ID]map[model.ID]bool, map[model.ID]map[model.ID]bool) { return nil, nil },
		Apply:    func(model.RouteUpdate) error { return nil },
	})
	if u := e.Configure(snapshot); u != nil {
		t.Fatalf("routes before observing local Links: %+v", u)
	}
	e.Step()
	snapshot.Revision++
	if u := e.Configure(snapshot); u == nil || u.Revision != snapshot.Revision {
		t.Fatalf("routes for an observed configuration: %+v", u)
	}
}

func TestSignatureSequenceBoundsAndClientLeafRole(t *testing.T) {
	l := newLab(t)
	// Mark node D (cheaper path A-D-C if D were transit when A-B fails!) as a Client leaf.
	l.state.Networks[0].Nodes[3].Client = true
	// Make A-D=1, D-C=1 (sum 2 < A-B-C 20) so D would be chosen as transit if allowed!
	l.state.Networks[0].Edges[3].Weight = 1
	l.engines = map[model.ID]*Engine{}
	l.routes = map[model.ID]model.RouteUpdate{}
	for _, node := range l.state.Networks[0].Nodes {
		l.start(node)
	}
	l.run(time.Second)

	// Even though A-D-C costs 2 vs A-B-C 20, client D must never be used as transit!
	if r := l.route(nodeA, nodeC); r.NextHop != nodeB || r.Cost != 20 {
		t.Fatalf("client D used as transit on A->C: %+v", r)
	}
	// Yet D itself remains reachable directly from A and C.
	if r := l.route(nodeA, nodeD); r.NextHop != nodeD || r.Cost != 1 {
		t.Fatalf("client D unreachable from A: %+v", r)
	}

	netID := l.state.Networks[0].ID
	engA := l.engines[nodeA]
	keyB := agentKeyFor(l.state, l.state.Agents[1].ID)
	keyD := agentKeyFor(l.state, l.state.Agents[3].ID)
	validSeq := uint64(l.now.UnixNano()) + 100

	// 1. Forged origin: B signs an LSA claiming Origin = nodeC.
	forgedOrigin := LSA{Network: netID, Origin: nodeC, Revision: 7, Sequence: validSeq, Sync: true}
	forgedOrigin.Sign(keyB)
	raw, _ := json.Marshal(forgedOrigin)
	if err := engA.Receive(netID, nodeB, raw); err == nil {
		t.Fatal("forged origin LSA was accepted")
	}

	// 2. Client neighbor D attempting to flood/relay C's valid LSA is rejected.
	validC := l.engines[nodeB].networks[netID].db[nodeC].lsa
	rawC, _ := json.Marshal(validC)
	if err := engA.Receive(netID, nodeD, rawC); err == nil {
		t.Fatal("third-party LSA from client neighbor was accepted")
	}

	// 3. Tampered / bad signature on B's LSA is rejected.
	badSig := LSA{Network: netID, Origin: nodeB, Revision: 7, Sequence: validSeq, Up: []model.ID{edgeAB}, Sync: true}
	badSig.Sign(keyB)
	badSig.Up = nil // mutate signed field after signing
	raw, _ = json.Marshal(badSig)
	if err := engA.Receive(netID, nodeB, raw); err == nil {
		t.Fatal("tampered LSA signature was accepted")
	}

	// 4. MaxUint64 and future (> now + MaxAge) sequences are rejected, including for own origin.
	keyA := agentKeyFor(l.state, l.state.Agents[0].ID)
	for _, seq := range []uint64{math.MaxUint64, uint64(l.now.Add(MaxAge + time.Second).UnixNano())} {
		overB := LSA{Network: netID, Origin: nodeB, Revision: 7, Sequence: seq, Sync: true}
		overB.Sign(keyB)
		raw, _ = json.Marshal(overB)
		if err := engA.Receive(netID, nodeB, raw); err == nil {
			t.Fatalf("peer sequence %d was accepted", seq)
		}
		overSelf := LSA{Network: netID, Origin: nodeA, Revision: 7, Sequence: seq, Sync: true}
		overSelf.Sign(keyA)
		raw, _ = json.Marshal(overSelf)
		if err := engA.Receive(netID, nodeB, raw); err == nil {
			t.Fatalf("self sequence %d was accepted", seq)
		}
	}

	// 5. Sequence saturation: originate saturates at MaxUint64-1 instead of wrapping to 0.
	nA := engA.networks[netID]
	nA.sequence = math.MaxUint64 - 2
	lsa1 := nA.originate(7, l.now, keyA)
	lsa2 := nA.originate(7, l.now, keyA)
	if lsa1.Sequence != math.MaxUint64-1 || lsa2.Sequence != math.MaxUint64-1 {
		t.Fatalf("sequence wrapped instead of saturating: %d, %d", lsa1.Sequence, lsa2.Sequence)
	}
	_ = keyD
}

func hasOrigin(v View, origin model.ID) bool {
	for _, o := range v.Networks[0].Database {
		if o.Origin == origin {
			return true
		}
	}
	return false
}

// A relay that resets AgeMS on a dead origin's last advertisement cannot keep
// it alive: its signed sequence, the origin's clock when it was made, bounds
// the age it may claim to one MaxAge of clock skew.
func TestResetAgeCannotResurrectStaleAdvertisement(t *testing.T) {
	l := newLab(t)
	l.run(time.Second)
	netID := l.state.Networks[0].ID
	engA := l.engines[nodeA]
	keyB := agentKeyFor(l.state, l.state.Agents[1].ID)
	advert := func(born time.Time) []byte {
		lsa := LSA{Network: netID, Origin: nodeB, Revision: 7, Sequence: uint64(born.UnixNano()), Up: []model.ID{edgeAB}, Sync: true}
		lsa.Sign(keyB)
		lsa.AgeMS = 0 // what a replaying relay claims
		raw, _ := json.Marshal(lsa)
		return raw
	}
	if err := engA.Receive(netID, nodeB, advert(l.now.Add(-2*MaxAge))); err == nil {
		t.Fatal("advertisement originated two MaxAge ago accepted with AgeMS=0")
	}
	// Within the skew allowance it is accepted, but expires on the origin's clock.
	born := l.now.Add(-MaxAge - time.Minute)
	delete(engA.networks[netID].db, nodeB)
	if err := engA.Receive(netID, nodeB, advert(born)); err != nil {
		t.Fatal(err)
	}
	arrived := engA.networks[netID].db[nodeB].arrived
	if want := born.Add(MaxAge); !arrived.Equal(want) {
		t.Fatalf("stale advertisement counted from %s, want at most %s", arrived, want)
	}
}
