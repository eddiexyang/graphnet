package model_test

import (
	"net/netip"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

func TestEmptyAndSingleMemberGroupsAllowed(t *testing.T) {
	s := testutil.Topology()
	n := &s.Networks[0]
	n.Edges = nil
	n.Groups = []model.FullMeshGroup{
		{
			ID:         testutil.ID(90),
			Name:       "Clients",
			Members:    nil,
			Transports: []model.Transport{model.QUIC, model.TCP},
			Methods:    model.ConnectionMethods{IPv4Direct: true},
		},
		{
			ID:         testutil.ID(91),
			Name:       "Single",
			Members:    []model.ID{n.Nodes[0].ID},
			Transports: []model.Transport{model.QUIC},
			Methods:    model.ConnectionMethods{IPv4Direct: true},
		},
	}
	n.GroupLinks = []model.GroupLink{
		{
			ID:          testutil.ID(92),
			SourceGroup: testutil.ID(90),
			Group:       testutil.ID(91),
			Weight:      10,
			Enabled:     true,
			Transports:  []model.Transport{model.QUIC},
			Methods:     model.ConnectionMethods{IPv4Direct: true},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("empty/single groups should validate: %v", err)
	}
	if got := len(n.EffectiveEdges()); got != 0 {
		t.Fatalf("effective edges = %d, want 0", got)
	}
}

func TestClientGroupSkipsClientToClientEdges(t *testing.T) {
	s := testutil.Topology()
	n := &s.Networks[0]
	n.Edges = nil
	// Make nodes 2 and 3 client nodes, keep nodes 0 and 1 regular Agent nodes.
	n.Nodes[2].Client = true
	n.Nodes[3].Client = true
	s.Agents[2].Endpoints = nil
	s.Agents[3].Endpoints = nil
	// Add a third client node.
	client3Agent := s.Agents[3]
	client3Agent.ID = testutil.ID(50)
	client3Agent.Name = "client-3"
	client3Agent.PublicKey = append([]byte(nil), s.Agents[3].PublicKey...)
	client3Agent.PublicKey[0] ^= 0xff
	s.Agents = append(s.Agents, client3Agent)
	n.Nodes = append(n.Nodes, model.Node{
		ID:      testutil.ID(51),
		AgentID: client3Agent.ID,
		Name:    "client-3",
		Address: netip.MustParseAddr("10.42.0.51"),
		Index:   51,
		Client:  true,
	})

	n.Groups = []model.FullMeshGroup{
		{
			ID:         testutil.ID(93),
			Name:       "Clients",
			Members:    []model.ID{n.Nodes[2].ID, n.Nodes[3].ID, testutil.ID(51)},
			Transports: []model.Transport{model.QUIC, model.TCP},
			Methods:    model.ConnectionMethods{IPv4Direct: true},
		},
		{
			ID:         testutil.ID(94),
			Name:       "Ingress",
			Members:    []model.ID{n.Nodes[0].ID, n.Nodes[1].ID},
			Transports: []model.Transport{model.QUIC, model.TCP},
			Methods:    model.ConnectionMethods{IPv4Direct: true},
		},
	}
	n.GroupLinks = []model.GroupLink{
		{
			ID:          testutil.ID(95),
			SourceGroup: testutil.ID(93),
			Group:       testutil.ID(94),
			Weight:      10,
			Enabled:     true,
			Transports:  []model.Transport{model.QUIC},
			Methods:     model.ConnectionMethods{IPv4Direct: true},
		},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("client group topology should validate: %v", err)
	}
	// Expected: 1 internal edge in Ingress + 3*2 = 6 client->ingress edges = 7 edges (0 client<->client edges).
	if got := len(n.EffectiveEdges()); got != 7 {
		t.Fatalf("effective edges = %d, want 7", got)
	}
}
