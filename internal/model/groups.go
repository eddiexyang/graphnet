package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
)

// FullMeshGroup is a topology group, not an IP subnet. Internal edges are
// derived rather than persisted, so membership and shared policy cannot drift.
type FullMeshGroup struct {
	ID         ID                `json:"id"`
	Name       string            `json:"name"`
	Weight     *uint32           `json:"weight,omitempty"`
	Members    []ID              `json:"members"`
	Transports []Transport       `json:"transports"`
	Methods    ConnectionMethods `json:"methods"`
	Overrides  []EdgeOverride    `json:"overrides,omitempty"`
}

// EdgeOverride replaces shared settings on one expanded pair. Unset fields
// inherit from the owner so later shared changes still reach the pair.
type EdgeOverride struct {
	A                  ID                 `json:"a"`
	B                  ID                 `json:"b"`
	Weight             *uint32            `json:"weight,omitempty"`
	Enabled            *bool              `json:"enabled,omitempty"`
	Transports         []Transport        `json:"transports,omitempty"`
	Methods            *ConnectionMethods `json:"methods,omitempty"`
	PreferredCandidate string             `json:"preferred_candidate,omitempty"`
}

func (o EdgeOverride) apply(e Edge) Edge {
	if o.Weight != nil {
		e.Weight = *o.Weight
	}
	if o.Enabled != nil {
		e.Enabled = *o.Enabled
	}
	if o.Transports != nil {
		e.Transports = slices.Clone(o.Transports)
	}
	if o.Methods != nil {
		e.Methods = *o.Methods
	}
	e.PreferredCandidate = o.PreferredCandidate
	return e
}

func (o EdgeOverride) Clone() EdgeOverride {
	if o.Weight != nil {
		weight := *o.Weight
		o.Weight = &weight
	}
	if o.Enabled != nil {
		enabled := *o.Enabled
		o.Enabled = &enabled
	}
	if o.Methods != nil {
		methods := *o.Methods
		o.Methods = &methods
	}
	o.Transports = slices.Clone(o.Transports)
	return o
}

func cloneOverrides(overrides []EdgeOverride) []EdgeOverride {
	if overrides == nil {
		return nil
	}
	out := make([]EdgeOverride, len(overrides))
	for i, o := range overrides {
		out[i] = o.Clone()
	}
	return out
}

func pairKey(a, b ID) [2]ID {
	if a > b {
		a, b = b, a
	}
	return [2]ID{a, b}
}

type overrideSet map[[2]ID]EdgeOverride

func newOverrideSet(overrides []EdgeOverride) overrideSet {
	set := make(overrideSet, len(overrides))
	for _, o := range overrides {
		set[pairKey(o.A, o.B)] = o
	}
	return set
}

func (s overrideSet) apply(e Edge) Edge {
	if o, ok := s[pairKey(e.A, e.B)]; ok {
		return o.apply(e)
	}
	return e
}

// RoutingWeight preserves weight 1 for groups saved before weight was configurable.
func (g FullMeshGroup) RoutingWeight() uint32 {
	if g.Weight == nil {
		return 1
	}
	return *g.Weight
}

// GroupLink expands one node-to-group or group-to-group connection into
// independently routed edges. Exactly one of Node and SourceGroup is set.
type GroupLink struct {
	ID          ID                `json:"id"`
	Node        ID                `json:"node,omitempty"`
	SourceGroup ID                `json:"source_group,omitempty"`
	Group       ID                `json:"group"`
	Weight      uint32            `json:"weight"`
	Enabled     bool              `json:"enabled"`
	Transports  []Transport       `json:"transports"`
	Methods     ConnectionMethods `json:"methods"`
	Overrides   []EdgeOverride    `json:"overrides,omitempty"`
}

func (n Network) group(id ID) (FullMeshGroup, bool) {
	for _, g := range n.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return FullMeshGroup{}, false
}

// sources returns the near end of a link: its node, or every source group member.
func (n Network) sources(link GroupLink) []ID {
	if link.SourceGroup == "" {
		return []ID{link.Node}
	}
	g, _ := n.group(link.SourceGroup)
	return g.Members
}

func (n Network) clientNodes() map[ID]bool {
	clients := make(map[ID]bool)
	for _, node := range n.Nodes {
		if node.Client {
			clients[node.ID] = true
		}
	}
	return clients
}

func (n Network) groupEdges(g FullMeshGroup) []Edge {
	clients := n.clientNodes()
	members := slices.Clone(g.Members)
	slices.Sort(members)
	overrides := newOverrideSet(g.Overrides)
	edges := []Edge{}
	for i, a := range members {
		for _, b := range members[i+1:] {
			if clients[a] && clients[b] {
				continue
			}
			edges = append(edges, overrides.apply(Edge{ID: GroupEdgeID(g.ID, a, b), A: a, B: b, Weight: g.RoutingWeight(), Enabled: true, Transports: slices.Clone(g.Transports), Methods: g.Methods}))
		}
	}
	return edges
}

func (n Network) linkEdges(link GroupLink) []Edge {
	g, ok := n.group(link.Group)
	if !ok {
		return nil
	}
	clients := n.clientNodes()
	overrides := newOverrideSet(link.Overrides)
	edges := []Edge{}
	for _, a := range n.sources(link) {
		for _, b := range g.Members {
			if clients[a] && clients[b] {
				continue
			}
			edges = append(edges, overrides.apply(Edge{ID: GroupEdgeID(link.ID, a, b), A: a, B: b, Weight: link.Weight, Enabled: link.Enabled, Transports: slices.Clone(link.Transports), Methods: link.Methods}))
		}
	}
	return edges
}

func GroupEdgeID(group, a, b ID) ID {
	if a > b {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte("graphnet/full-mesh/" + string(group) + "/" + string(a) + "/" + string(b)))
	return ID(hex.EncodeToString(sum[:16]))
}

// EffectiveEdges must only be called on validated/bounded groups.
func (n Network) EffectiveEdges() []Edge {
	if len(n.Groups) == 0 && len(n.GroupLinks) == 0 {
		return n.Edges
	}
	edges := slices.Clone(n.Edges)
	for _, g := range n.Groups {
		edges = append(edges, n.groupEdges(g)...)
	}
	for _, link := range n.GroupLinks {
		edges = append(edges, n.linkEdges(link)...)
	}
	return edges
}

func (n Network) validateGroups(addID func(ID) error) error {
	nodes := make(map[ID]Node, len(n.Nodes))
	for _, node := range n.Nodes {
		nodes[node.ID] = node
	}
	used := map[ID]bool{}
	count := int64(len(n.Edges))
	for _, g := range n.Groups {
		if err := addID(g.ID); err != nil {
			return err
		}
		if err := validateName(g.Name); err != nil {
			return err
		}
		if len(g.Members) > MaxNodes {
			return fmt.Errorf("full mesh group allows at most %d members", MaxNodes)
		}
		var clientMembers int64
		for _, id := range g.Members {
			node, ok := nodes[id]
			if !ok {
				return fmt.Errorf("group members must be nodes in this network")
			}
			if used[id] {
				return fmt.Errorf("node belongs to a full mesh group more than once")
			}
			used[id] = true
			if node.Client {
				clientMembers++
			}
		}
		size := int64(len(g.Members))
		count += size*(size-1)/2 - clientMembers*(clientMembers-1)/2
		if count > MaxEdges {
			return fmt.Errorf("full mesh topology exceeds %d edges", MaxEdges)
		}
	}
	groups := map[ID]FullMeshGroup{}
	for _, g := range n.Groups {
		groups[g.ID] = g
	}
	for _, g := range n.Groups {
		if err := validateOverrides(g.Overrides, func(a, b ID) bool {
			return a != b && !(nodes[a].Client && nodes[b].Client) && slices.Contains(g.Members, a) && slices.Contains(g.Members, b)
		}); err != nil {
			return err
		}
	}
	pairs := map[[2]ID]bool{}
	for _, link := range n.GroupLinks {
		if err := addID(link.ID); err != nil {
			return err
		}
		g, exists := groups[link.Group]
		if !exists {
			return fmt.Errorf("group link requires an existing target group")
		}
		var key [2]ID
		if link.SourceGroup != "" {
			if _, ok := groups[link.SourceGroup]; link.Node != "" || !ok || link.SourceGroup == link.Group {
				return fmt.Errorf("group-to-group link requires two distinct groups and no node")
			}
			key = pairKey(link.SourceGroup, link.Group)
		} else {
			if _, ok := nodes[link.Node]; !ok || slices.Contains(g.Members, link.Node) {
				return fmt.Errorf("group link requires a node outside its target group")
			}
			key = [2]ID{link.Node, link.Group}
		}
		if pairs[key] {
			return fmt.Errorf("duplicate group link")
		}
		pairs[key] = true
		near := n.sources(link)
		var nearClients, targetClients int64
		for _, id := range near {
			if nodes[id].Client {
				nearClients++
			}
		}
		for _, id := range g.Members {
			if nodes[id].Client {
				targetClients++
			}
		}
		count += int64(len(near))*int64(len(g.Members)) - nearClients*targetClients
		if count > MaxEdges {
			return fmt.Errorf("expanded topology exceeds %d edges", MaxEdges)
		}
		if err := validateOverrides(link.Overrides, func(a, b ID) bool {
			if nodes[a].Client && nodes[b].Client {
				return false
			}
			return slices.Contains(near, a) && slices.Contains(g.Members, b) || slices.Contains(near, b) && slices.Contains(g.Members, a)
		}); err != nil {
			return err
		}
	}
	return nil
}

// validateOverrides only checks ownership; overridden values are validated on
// the expanded edge like any explicit edge.
func validateOverrides(overrides []EdgeOverride, expanded func(a, b ID) bool) error {
	seen := map[[2]ID]bool{}
	for _, o := range overrides {
		key := pairKey(o.A, o.B)
		if !expanded(o.A, o.B) {
			return fmt.Errorf("edge override %s–%s is not an expanded pair of its owner", o.A, o.B)
		}
		if seen[key] {
			return fmt.Errorf("duplicate edge override %s–%s", o.A, o.B)
		}
		seen[key] = true
	}
	return nil
}

// PruneGroups removes deleted nodes and overrides whose pairs no longer expand,
// while preserving 0- and 1-member groups and their group links.
func (n *Network) PruneGroups() {
	nodes := map[ID]Node{}
	for _, node := range n.Nodes {
		nodes[node.ID] = node
	}
	hasNode := func(id ID) bool { _, ok := nodes[id]; return ok }
	groups := make([]FullMeshGroup, 0, len(n.Groups))
	groupMap := make(map[ID]FullMeshGroup, len(n.Groups))
	for _, g := range n.Groups {
		g.Members = slices.DeleteFunc(slices.Clone(g.Members), func(id ID) bool { return !hasNode(id) })
		g.Overrides = slices.DeleteFunc(slices.Clone(g.Overrides), func(o EdgeOverride) bool {
			return o.A == o.B || !hasNode(o.A) || !hasNode(o.B) || (nodes[o.A].Client && nodes[o.B].Client) || !slices.Contains(g.Members, o.A) || !slices.Contains(g.Members, o.B)
		})
		groups = append(groups, g)
		groupMap[g.ID] = g
	}
	n.Groups = groups
	n.GroupLinks = slices.DeleteFunc(slices.Clone(n.GroupLinks), func(l GroupLink) bool {
		if l.SourceGroup != "" {
			_, okSrc := groupMap[l.SourceGroup]
			_, okDst := groupMap[l.Group]
			return !okSrc || !okDst || l.SourceGroup == l.Group
		}
		g, okDst := groupMap[l.Group]
		return !hasNode(l.Node) || !okDst || slices.Contains(g.Members, l.Node)
	})
	for i := range n.GroupLinks {
		l := &n.GroupLinks[i]
		near := n.sources(*l)
		target := groupMap[l.Group].Members
		l.Overrides = slices.DeleteFunc(slices.Clone(l.Overrides), func(o EdgeOverride) bool {
			if o.A == o.B || !hasNode(o.A) || !hasNode(o.B) || (nodes[o.A].Client && nodes[o.B].Client) {
				return true
			}
			return !(slices.Contains(near, o.A) && slices.Contains(target, o.B) || slices.Contains(near, o.B) && slices.Contains(target, o.A))
		})
	}
}
