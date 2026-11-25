// Package linkstate lets Agents converge routes from link-state advertisements
// flooded over their peer Links, so forwarding never depends on the controller.
package linkstate

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
)

const (
	// Changes flood immediately; capable neighbours repair missing records
	// through periodic database reconciliation. Legacy networks retain their
	// original refresh/expiry cadence throughout a rolling upgrade.
	RefreshInterval       = 5 * time.Minute
	MaxAge                = 15 * time.Minute
	LegacyRefreshInterval = 10 * time.Second
	LegacyMaxAge          = 40 * time.Second
	SyncInterval          = 10 * time.Second
	// SPFDelay batches the LSAs of one event; MinOriginateInterval bounds
	// the origination rate of a flapping link.
	SPFDelay             = 50 * time.Millisecond
	MinOriginateInterval = 100 * time.Millisecond
	tick                 = 100 * time.Millisecond
	maxLSA               = 64 * 1024
)

// ErrSuperseded is returned by Callbacks.Apply for routes computed for an
// older configuration; routes for the current one are already scheduled.
var ErrSuperseded = errors.New("routes superseded by a newer configuration")

// LSA is one origin's report of the edges it can use in one network.
type LSA struct {
	Network  model.ID   `json:"network"`
	Origin   model.ID   `json:"origin"`
	Revision uint64     `json:"revision"`
	Sequence uint64     `json:"sequence"`
	Up       []model.ID `json:"up"`
	// Fallback lists unhealthy edges: usable only to reach destinations that
	// no Up edge reaches. Agents without it read them as down.
	Fallback  []model.ID `json:"fallback,omitempty"`
	Signature []byte     `json:"sig,omitempty"`
	Sync      bool       `json:"sync,omitempty"`
	AgeMS     int64      `json:"age_ms,omitempty"`
}

func (l LSA) SignBytes() []byte {
	var buf []byte
	buf = append(buf, "graphnet lsa v1\n"...)
	buf = append(buf, l.Network...)
	buf = append(buf, '\n')
	buf = append(buf, l.Origin...)
	buf = append(buf, '\n')
	buf = binary.BigEndian.AppendUint64(buf, l.Revision)
	buf = binary.BigEndian.AppendUint64(buf, l.Sequence)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(l.Up)))
	for _, id := range l.Up {
		buf = append(buf, id...)
		buf = append(buf, '\n')
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(l.Fallback)))
	for _, id := range l.Fallback {
		buf = append(buf, id...)
		buf = append(buf, '\n')
	}
	return buf
}

func (l *LSA) Sign(key ed25519.PrivateKey) {
	if len(key) == ed25519.PrivateKeySize {
		l.Signature = ed25519.Sign(key, l.SignBytes())
	}
}

func (l LSA) Verify(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && len(l.Signature) == ed25519.SignatureSize && ed25519.Verify(pub, l.SignBytes(), l.Signature)
}

// Callbacks connect the engine to an Agent. Send is best effort and reports
// whether the message was queued: a database owed to a new neighbour is resent
// until it is, and periodic refresh repairs other lost advertisements.
type Callbacks struct {
	Identity ed25519.PrivateKey
	Send     func(network, peer model.ID, raw []byte) bool
	// Local returns up and fallback edges from the same observation.
	Local func() (up, fallback map[model.ID]map[model.ID]bool) // network -> edge
	Apply func(model.RouteUpdate) error
	Now   func() time.Time
}

type entry struct {
	lsa      LSA
	up       map[model.ID]bool
	fallback map[model.ID]bool
	arrived  time.Time
}

type network struct {
	config      model.NetworkConfig
	neighbors   map[model.ID]bool // peer node IDs
	local       map[model.ID]bool
	fallback    map[model.ID]bool
	db          map[model.ID]entry
	sequence    uint64
	sent        time.Time
	dirty       bool // local state changed since the last origination
	lastUp      []model.ID
	lastFall    []model.ID
	self        *LSA
	syncReady   bool
	syncSent    time.Time
	syncMembers []model.ID
	// owed holds neighbours whose database dump could not be queued yet,
	// with the time it was first owed.
	owed map[model.ID]time.Time
}

type Engine struct {
	cb       Callbacks
	mu       sync.Mutex
	snapshot *model.Snapshot
	networks map[model.ID]*network
	spfAt    time.Time
	applied  string
	observed bool // local link state has been polled at least once
	stats    Stats
	events   []Event
	kick     chan struct{}
}

func New(cb Callbacks) *Engine {
	if cb.Now == nil {
		cb.Now = time.Now
	}
	return &Engine{cb: cb, networks: map[model.ID]*network{}, kick: make(chan struct{}, 1)}
}

// Kick runs a step now: a local Link failed. It never blocks.
func (e *Engine) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Active reports whether the configuration carries topology, in which case
// the Agent routes locally and ignores controller route updates.
func Active(s model.Snapshot) bool {
	if len(s.Networks) == 0 {
		return false
	}
	for _, n := range s.Networks {
		if len(n.Topology) == 0 && len(n.Peers) > 0 {
			return false
		}
	}
	return true
}

// Configure installs a new configuration and returns the routes for it, which
// the caller installs together with the configuration and reports to Applied.
// Before the first poll of local Links it returns nil: the compiled routes stay
// until Step computes routes from observed state.
// Databases of networks that remain are kept; their entries are evaluated
// against the new topology. A new revision is advertised only when it changes
// this node's neighbours or the topology.
func (e *Engine) Configure(s model.Snapshot) *model.RouteUpdate {
	e.mu.Lock()
	defer e.mu.Unlock()
	clone := s.Clone()
	e.snapshot = &clone
	next := map[model.ID]*network{}
	for _, c := range clone.Networks {
		n := e.networks[c.ID]
		if n == nil {
			n = &network{db: map[model.ID]entry{}, local: map[model.ID]bool{}, fallback: map[model.ID]bool{}, owed: map[model.ID]time.Time{}, dirty: true}
		}
		neighbors := map[model.ID]bool{}
		for _, p := range c.Peers {
			neighbors[p.Node.ID] = true
		}
		if !maps(n.neighbors, neighbors) || !slices.Equal(n.config.Topology, c.Topology) || n.config.Self.ID != c.Self.ID {
			n.dirty = true
		}
		n.config, n.neighbors = c, neighbors
		for peer := range n.owed {
			if !neighbors[peer] {
				delete(n.owed, peer)
			}
		}
		n.syncMembers = componentMembers(c)
		for origin, en := range n.db {
			if !n.known(origin) {
				delete(n.db, origin)
				continue
			}
			// An advertisement received before this revision was filtered by
			// the previous topology: an edge it names may exist only now.
			en.up, en.fallback = n.usableEdges(en.lsa)
			n.db[origin] = en
		}
		next[c.ID] = n
	}
	e.networks = next
	if !e.observed {
		e.scheduleSPFLocked()
		return nil
	}
	return e.spfLocked()
}

// Applied records the outcome of installing routes from Configure or Step.
func (e *Engine) Applied(update model.RouteUpdate, err error, took time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case err == nil:
		e.stats.SPFRuns.Add(1)
		e.applied = update.Hash()
		e.eventLocked("routes", "", "", "", uint64(took.Microseconds()))
	case errors.Is(err, ErrSuperseded):
		e.stats.Superseded.Add(1)
	default:
		e.stats.ApplyErrors.Add(1)
		e.eventLocked("route-error", "", "", "", update.Revision)
		e.scheduleSPFLocked()
	}
}

// PeerReady sends the whole database to a neighbour that can now exchange
// advertisements. A neighbour is often reported ready before any of its Links
// can carry them; what cannot be queued is owed and resent on every Step until
// it is, or until periodic synchronization takes over.
func (e *Engine) PeerReady(networkID, peer model.ID) {
	e.mu.Lock()
	if n := e.networks[networkID]; n != nil && n.neighbors[peer] {
		if _, ok := n.owed[peer]; !ok {
			n.owed[peer] = e.cb.Now()
		}
	}
	e.mu.Unlock()
	e.sendDatabase(networkID, peer)
}

// sendDatabase sends the database owed to peer and clears the debt once every
// advertisement is queued.
func (e *Engine) sendDatabase(networkID, peer model.ID) {
	e.mu.Lock()
	n := e.networks[networkID]
	if n == nil || !n.neighbors[peer] {
		e.mu.Unlock()
		return
	}
	if _, ok := n.owed[peer]; !ok {
		e.mu.Unlock()
		return
	}
	var out [][]byte
	for id, record := range n.records(e.cb.Now()) {
		if n.config.Self.Client && id != n.config.Self.ID {
			continue
		}
		if raw, err := json.Marshal(record); err == nil {
			out = append(out, raw)
		}
	}
	e.mu.Unlock()
	queued := true
	for _, raw := range out {
		e.stats.Sent.Add(1)
		if !e.cb.Send(networkID, peer, raw) {
			queued = false
			break
		}
	}
	if !queued {
		return
	}
	e.mu.Lock()
	if n := e.networks[networkID]; n != nil {
		delete(n.owed, peer)
	}
	e.mu.Unlock()
}

// Receive handles an advertisement from an authenticated neighbour.
func (e *Engine) Receive(networkID, peer model.ID, raw []byte) error {
	if len(raw) > maxLSA {
		return errors.New("link-state advertisement too large")
	}
	var envelope struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Kind != "" {
		return e.receiveSync(networkID, peer, raw)
	}
	var lsa LSA
	if err := json.Unmarshal(raw, &lsa); err != nil {
		return err
	}
	e.stats.Received.Add(1)
	e.mu.Lock()
	n := e.networks[networkID]
	if n == nil || lsa.Network != networkID || !n.neighbors[peer] {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("link-state advertisement for an unknown network or node")
	}
	dest, ok := n.directoryEntry(lsa.Origin)
	if !ok || n.isClient(peer) && lsa.Origin != peer {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("link-state advertisement for an unknown or unauthorized origin")
	}
	if lsa.AgeMS < 0 || lsa.AgeMS >= lsa.maxAge().Milliseconds() {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("expired link-state advertisement")
	}
	now := e.cb.Now()
	maxSeq := uint64(max(int64(0), now.Add(lsa.maxAge()).UnixNano()))
	if lsa.Sequence == 0 || lsa.Sequence == math.MaxUint64 || lsa.Sequence > maxSeq {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("invalid link-state sequence")
	}
	// The signed sequence is the origin's clock when it originated the
	// advertisement. AgeMS is not signed, so a relay could reset it on a dead
	// origin's last advertisement forever; the sequence bounds the age it may
	// claim, allowing one maxAge of clock skew as the upper bound above does.
	born := time.Unix(0, int64(min(lsa.Sequence, math.MaxInt64)))
	if now.Sub(born) >= 2*lsa.maxAge() {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("expired link-state advertisement")
	}
	if !lsa.Verify(dest.PublicKey) {
		e.mu.Unlock()
		e.stats.Rejected.Add(1)
		return errors.New("invalid link-state signature")
	}
	if lsa.Origin == n.config.Self.ID {
		// Our own signed advertisement from before a restart: continue above it.
		if lsa.Sequence > n.sequence {
			n.sequence = lsa.Sequence
			n.dirty = true
		}
		e.mu.Unlock()
		return nil
	}
	if old, ok := n.db[lsa.Origin]; ok && old.lsa.Sequence >= lsa.Sequence {
		e.mu.Unlock()
		e.stats.Duplicate.Add(1)
		return nil
	}
	up, fallback := n.usableEdges(lsa)
	if old, ok := n.db[lsa.Origin]; !ok || !slices.Equal(old.lsa.Up, lsa.Up) || !slices.Equal(old.lsa.Fallback, lsa.Fallback) {
		e.eventLocked("received", networkID, lsa.Origin, "", lsa.Sequence)
	}
	arrived := now.Add(-time.Duration(lsa.AgeMS) * time.Millisecond)
	if latest := born.Add(lsa.maxAge()); arrived.After(latest) {
		arrived = latest
	}
	n.db[lsa.Origin] = entry{lsa: lsa, up: up, fallback: fallback, arrived: arrived}
	e.scheduleSPFLocked()
	var targets []model.ID
	if !n.config.Self.Client {
		targets = n.floodTargets(peer)
	}
	e.mu.Unlock()
	for _, t := range targets {
		e.stats.Sent.Add(1)
		e.cb.Send(networkID, t, raw)
	}
	return nil
}

func (n *network) directoryEntry(node model.ID) (model.Destination, bool) {
	for _, d := range n.config.Directory {
		if d.NodeID == node {
			return d, true
		}
	}
	return model.Destination{}, false
}

func (n *network) isClient(node model.ID) bool {
	if node == n.config.Self.ID {
		return n.config.Self.Client
	}
	d, ok := n.directoryEntry(node)
	return ok && d.Client
}

// usableEdges keeps the edges of lsa that the configured topology gives its
// origin: up first, then fallback edges that are not also up.
func (n *network) usableEdges(lsa LSA) (up, fallback map[model.ID]bool) {
	incident := n.incidentEdges(lsa.Origin)
	up = map[model.ID]bool{}
	for _, id := range lsa.Up {
		if incident[id] {
			up[id] = true
		}
	}
	fallback = map[model.ID]bool{}
	for _, id := range lsa.Fallback {
		if incident[id] && !up[id] {
			fallback[id] = true
		}
	}
	return up, fallback
}

func (n *network) incidentEdges(origin model.ID) map[model.ID]bool {
	allowed := map[model.ID]bool{}
	originClient := n.isClient(origin)
	for _, edge := range n.config.Topology {
		if edge.A != origin && edge.B != origin {
			continue
		}
		other := edge.B
		if edge.B == origin {
			other = edge.A
		}
		if originClient && n.isClient(other) {
			continue
		}
		allowed[edge.ID] = true
	}
	return allowed
}

func (n *network) known(node model.ID) bool {
	if node == n.config.Self.ID {
		return true
	}
	_, ok := n.directoryEntry(node)
	return ok
}

func (n *network) floodTargets(except model.ID) []model.ID {
	var out []model.ID
	for p := range n.neighbors {
		if p != except {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// Run polls local link state, originates, ages out and recomputes routes
// until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	spf := time.NewTimer(tick)
	defer spf.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		case <-spf.C:
		}
		e.Step()
		// A scheduled computation runs when due, not at the next tick.
		e.mu.Lock()
		wait := tick
		if !e.spfAt.IsZero() {
			wait = max(e.spfAt.Sub(e.cb.Now()), 0)
		}
		e.mu.Unlock()
		spf.Reset(wait)
	}
}

// Step performs one round of the engine's periodic work.
func (e *Engine) Step() {
	local, fallback := e.cb.Local()
	now := e.cb.Now()
	type send struct {
		network model.ID
		peers   []model.ID
		raw     []byte
		sync    bool
	}
	var sends []send
	var update *model.RouteUpdate
	e.mu.Lock()
	e.observed = true
	for id, n := range e.networks {
		if !maps(n.local, local[id]) || !maps(n.fallback, fallback[id]) {
			lost := false
			level := func(up, fall map[model.ID]bool, edge model.ID) int {
				switch {
				case up[edge]:
					return 2
				case fall[edge]:
					return 1
				}
				return 0
			}
			for _, edge := range n.config.Topology {
				was, is := level(n.local, n.fallback, edge.ID), level(local[id], fallback[id], edge.ID)
				if was != is {
					kind := [...]string{"edge-down", "edge-fallback", "edge-up"}[is]
					lost = lost || is < was
					e.eventLocked(kind, id, "", edge.ID, 0)
				}
			}
			n.local = copyMap(local[id])
			n.fallback = copyMap(fallback[id])
			n.dirty = true
			// A failed edge of this Agent moves its routes in this step. A new
			// one waits SPFDelay for the neighbour's database, so routes are
			// not computed from part of it.
			if lost {
				e.spfAt = now
			}
		}
		for origin, en := range n.db {
			if now.Sub(en.arrived) > en.lsa.maxAge() {
				delete(n.db, origin)
				e.stats.Expired.Add(1)
				e.eventLocked("expired", id, origin, "", en.lsa.Sequence)
				e.scheduleSPFLocked()
			}
		}
		ready := n.supportsSync()
		if n.syncReady && !ready {
			n.dirty = true // A legacy/restarted origin needs the short cadence now.
		}
		n.syncReady = ready
		interval := LegacyRefreshInterval
		if ready {
			interval = RefreshInterval
		}
		if (n.dirty && now.Sub(n.sent) >= MinOriginateInterval) || now.Sub(n.sent) >= interval {
			lsa := n.originate(e.snapshot.Revision, now, e.cb.Identity)
			if raw, err := json.Marshal(lsa); err == nil {
				sends = append(sends, send{id, n.floodTargets(""), raw, false})
			}
			if !slices.Equal(n.lastUp, lsa.Up) || !slices.Equal(n.lastFall, lsa.Fallback) {
				e.eventLocked("originated", id, lsa.Origin, "", lsa.Sequence)
				n.lastUp, n.lastFall = lsa.Up, lsa.Fallback
			}
			e.scheduleSPFLocked()
		}
		if now.Sub(n.syncSent) >= SyncInterval {
			n.syncSent = now
			message := syncMessage{Kind: "digest", Network: id, Digest: n.digest(now)}
			raw, _ := json.Marshal(message)
			var peers []model.ID
			for peer := range n.neighbors {
				if en, ok := n.db[peer]; ok && en.lsa.Sync {
					peers = append(peers, peer)
				}
			}
			sends = append(sends, send{id, peers, raw, true})
		}
	}
	type debt struct{ network, peer model.ID }
	var owed []debt
	for id, n := range e.networks {
		for peer, since := range n.owed {
			// After a full sync interval the digest exchange repairs it.
			if now.Sub(since) >= SyncInterval {
				delete(n.owed, peer)
				continue
			}
			owed = append(owed, debt{id, peer})
		}
	}
	if !e.spfAt.IsZero() && !now.Before(e.spfAt) {
		e.spfAt = time.Time{}
		update = e.spfLocked()
	}
	e.mu.Unlock()
	for _, d := range owed {
		e.sendDatabase(d.network, d.peer)
	}
	for _, s := range sends {
		for _, p := range s.peers {
			if !s.sync {
				e.stats.Sent.Add(1)
			}
			e.cb.Send(s.network, p, s.raw)
		}
	}
	if update != nil {
		start := e.cb.Now()
		err := e.cb.Apply(*update)
		e.Applied(*update, err, e.cb.Now().Sub(start))
	}
}

func (n *network) originate(revision uint64, now time.Time, identity ed25519.PrivateKey) LSA {
	next := uint64(max(int64(1), now.UnixNano()))
	if n.sequence >= next {
		if n.sequence < math.MaxUint64-1 {
			next = n.sequence + 1
		} else {
			next = math.MaxUint64 - 1
		}
	}
	n.sequence = next
	n.sent, n.dirty = now, false
	incident := n.incidentEdges(n.config.Self.ID)
	up := []model.ID{}
	for id, ok := range n.local {
		if ok && incident[id] {
			up = append(up, id)
		}
	}
	slices.Sort(up)
	var fallback []model.ID
	for id, ok := range n.fallback {
		if ok && !n.local[id] && incident[id] {
			fallback = append(fallback, id)
		}
	}
	slices.Sort(fallback)
	lsa := LSA{Network: n.config.ID, Origin: n.config.Self.ID, Revision: revision, Sequence: n.sequence, Up: up, Fallback: fallback, Sync: true}
	lsa.Sign(identity)
	n.self = &lsa
	return lsa
}

func (e *Engine) scheduleSPFLocked() {
	if e.spfAt.IsZero() {
		e.spfAt = e.cb.Now().Add(SPFDelay)
	}
}

// spfLocked returns the new forwarding tables, or nil when unchanged.
func (e *Engine) spfLocked() *model.RouteUpdate {
	if e.snapshot == nil {
		return nil
	}
	update := model.RouteUpdate{Revision: e.snapshot.Revision, Networks: []model.NetworkRoutes{}}
	for _, c := range e.snapshot.Networks {
		n := e.networks[c.ID]
		update.Networks = append(update.Networks, model.NetworkRoutes{ID: c.ID, Routes: routing.LocalRoutesFallback(c, n.usable, n.fallbackUsable)})
	}
	if update.Hash() == e.applied {
		return nil
	}
	return &update
}

func (n *network) usable(edge model.TopologyEdge) bool {
	return n.edgeUsable(edge, false)
}

func (n *network) fallbackUsable(edge model.TopologyEdge) bool {
	return n.edgeUsable(edge, true)
}

// An endpoint that has not advertised defers to the other end. With no
// report from either end, the edge keeps its configured state.
func (n *network) edgeUsable(edge model.TopologyEdge, allowFallback bool) bool {
	if n.isClient(edge.A) && n.isClient(edge.B) {
		return false
	}
	permits := func(node model.ID) bool {
		if node == n.config.Self.ID {
			return n.local[edge.ID] || allowFallback && n.fallback[edge.ID]
		}
		en, ok := n.db[node]
		return !ok || en.up[edge.ID] || allowFallback && en.fallback[edge.ID]
	}
	return permits(edge.A) && permits(edge.B)
}

func maps(a, b map[model.ID]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func copyMap(m map[model.ID]bool) map[model.ID]bool {
	out := map[model.ID]bool{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
