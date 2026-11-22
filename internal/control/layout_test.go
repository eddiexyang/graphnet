package control_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

func TestPutNetworkAutoPlacesNewGroupNode(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := testutil.Topology()
	n := &state.Networks[0]
	n.Edges = nil
	n.Nodes = n.Nodes[:2]
	n.Nodes[0].Position = model.Position{X: 100, Y: 100}
	n.Nodes[1].Position = model.Position{X: 100, Y: 210}
	n.Nodes[0].Client = true
	n.Nodes[1].Client = true
	state.Agents[0].Endpoints = nil
	state.Agents[1].Endpoints = nil
	state.Agents[2].Endpoints = nil
	n.Groups = []model.FullMeshGroup{{
		ID:         testutil.ID(90),
		Name:       "Clients",
		Members:    []model.ID{n.Nodes[0].ID, n.Nodes[1].ID},
		Transports: []model.Transport{model.QUIC, model.TCP},
		Methods:    model.ConnectionMethods{IPv4Direct: true},
	}}
	cur, _ := db.Read()
	if _, err := db.Update(cur.Revision, func(s *model.State) error { *s = state; return nil }); err != nil {
		t.Fatal(err)
	}
	srv, err := control.New(db, control.Options{Password: "admin-password-1234", APIToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Add a 3rd client node into Clients group with zero Position.
	cur, _ = db.Read()
	upd := cur.Networks[0]
	newID := testutil.ID(99)
	upd.Nodes = append(upd.Nodes, model.Node{
		ID:      newID,
		AgentID: state.Agents[2].ID,
		Name:    "client-3",
		Address: netip.MustParseAddr("10.42.0.99"),
		Index:   99,
		Client:  true,
	})
	upd.Groups[0].Members = append(upd.Groups[0].Members, newID)
	body, _ := json.Marshal(upd)
	req := httptest.NewRequest("PUT", "/api/v1/networks/"+string(upd.ID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"`+strconv.FormatUint(cur.Revision, 10)+`"`)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	var after model.State
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	got := after.Networks[0].Nodes[2].Position
	if got.X != 100 || got.Y != 320 {
		t.Fatalf("auto-placed position = %+v, want {100 320}", got)
	}
}
