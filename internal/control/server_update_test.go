package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/cluster"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
)

func TestServerUpdateSerialization(t *testing.T) {
	now := time.Now()
	id := model.NewID()
	server := model.Server{Update: &model.UpdateRequest{ID: id, CreatedAt: now, Asset: model.ReleaseAsset{Version: "v1.2.3"}}}
	for _, test := range []struct {
		name    string
		status  cluster.Status
		pending bool
	}{
		{"awaiting delivery", cluster.Status{}, true},
		{"downloading", cluster.Status{Update: &model.UpdateStatus{RequestID: id, Phase: "downloading"}}, true},
		{"startup check", cluster.Status{Version: "v1.2.3", Update: &model.UpdateStatus{RequestID: id, Phase: "installing"}}, true},
		{"failed", cluster.Status{Update: &model.UpdateStatus{RequestID: id, Phase: "failed"}}, false},
		{"succeeded", cluster.Status{Update: &model.UpdateStatus{RequestID: id, Phase: "succeeded"}}, false},
		{"old completion", cluster.Status{Update: &model.UpdateStatus{RequestID: model.NewID(), Phase: "succeeded"}}, true},
		{"older release without updater", cluster.Status{Version: "v1.2.3"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := serverUpdatePending(server, test.status, now); got != test.pending {
				t.Fatalf("pending=%v, want %v", got, test.pending)
			}
		})
	}
	if serverUpdatePending(server, cluster.Status{}, now.Add(31*time.Minute)) {
		t.Fatal("expired request blocks new updates")
	}
	clone := model.CloneServers([]model.Server{server})
	clone[0].Update.ID = model.NewID()
	if clone[0].Update.ID == server.Update.ID {
		t.Fatal("update request was not deeply cloned")
	}
}

func TestPatchServerPreservesAutomaticEndpoints(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	apiToken := "0123456789abcdef0123456789abcdef"
	srv, err := New(db, Options{Password: "strong-admin-password-123", APIToken: apiToken})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	serverID := model.NewID()
	ifaceEp := model.ServerEndpoint{ID: model.NewID(), Transport: "tcp", URL: "tcp://192.0.2.10:8443", Source: model.Interface}
	obsEp := model.ServerEndpoint{ID: model.NewID(), Transport: "tcp", URL: "tcp://198.51.100.20:8443", Source: model.Observed, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	oldManual := model.ServerEndpoint{ID: model.NewID(), Transport: "tcp", URL: "tcp://203.0.113.1:8443", Source: model.Manual}

	cur, _ := db.Read()
	updated, err := db.Update(cur.Revision, func(s *model.State) error {
		s.ClusterID = model.NewID()
		s.ClusterCA = ca.PEM
		s.Servers = []model.Server{{
			ID:        serverID,
			Name:      "ctrl-1",
			PublicKey: pub,
			Endpoints: []model.ServerEndpoint{ifaceEp, obsEp, oldManual},
		}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]any{
		"name": "ctrl-renamed",
		"manual_endpoints": []map[string]any{{
			"transport": "wss",
			"url":       "wss://ctrl.example.com:443",
		}},
	})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/"+string(serverID), bytes.NewReader(payload))
	req.SetPathValue("id", string(serverID))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("If-Match", `"`+jsonRevision(updated.Revision)+`"`)
	rec := httptest.NewRecorder()
	srv.auth.require(srv.patchServer)(rec, req)
	if rec.Code != 200 {
		t.Fatalf("PATCH server = %d: %s", rec.Code, rec.Body.String())
	}

	after, _ := db.Read()
	got := after.Servers[0].Endpoints
	if len(got) != 3 {
		t.Fatalf("expected 2 automatic + 1 manual endpoints, got %+v", got)
	}
	sources := map[model.EndpointSource]int{}
	for _, ep := range got {
		sources[ep.Source]++
	}
	if sources[model.Interface] != 1 || sources[model.Observed] != 1 || sources[model.Manual] != 1 {
		t.Fatalf("automatic endpoints lost on PATCH: %+v", got)
	}
}

func jsonRevision(rev uint64) string {
	raw, _ := json.Marshal(rev)
	return string(raw)
}

// A dead or compromised controller can be revoked, which removes it from the
// cluster; the last server cannot be.
func TestPatchServerRevokes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	apiToken := "0123456789abcdef0123456789abcdef"
	srv, err := New(db, Options{Password: "strong-admin-password-123", APIToken: apiToken})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	ids := []model.ID{model.NewID(), model.NewID()}
	cur, _ := db.Read()
	if _, err := db.Update(cur.Revision, func(s *model.State) error {
		s.ClusterID = model.NewID()
		s.ClusterCA = ca.PEM
		for i, id := range ids {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			s.Servers = append(s.Servers, model.Server{ID: id, Name: "ctrl-" + string(rune('a'+i)), PublicKey: pub})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	patch := func(id model.ID, revoked bool) *httptest.ResponseRecorder {
		state, _ := db.Read()
		payload, _ := json.Marshal(map[string]any{"revoked": revoked})
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/"+string(id), bytes.NewReader(payload))
		req.SetPathValue("id", string(id))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("If-Match", `"`+jsonRevision(state.Revision)+`"`)
		rec := httptest.NewRecorder()
		srv.auth.require(srv.patchServer)(rec, req)
		return rec
	}
	if rec := patch(ids[1], true); rec.Code != 200 {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body.String())
	}
	state, _ := db.Read()
	if !state.Servers[1].Revoked || state.Servers[0].Revoked {
		t.Fatalf("servers after revoke: %+v", state.Servers)
	}
	if rec := patch(ids[0], true); rec.Code == 200 {
		t.Fatal("revoked the last server of the cluster")
	}
	if rec := patch(ids[1], false); rec.Code != 200 {
		t.Fatalf("restore = %d: %s", rec.Code, rec.Body.String())
	}
}
