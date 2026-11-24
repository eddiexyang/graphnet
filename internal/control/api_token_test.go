package control_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/store"
)

func TestAPITokenBearerAuth(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := control.New(db, control.Options{
		Password: "admin-password-1234",
		APIToken: "short-token",
	}); err == nil {
		t.Fatal("accepted API token shorter than 32 bytes")
	}
	const validToken = "secret-api-token-at-least-32-bytes-long"
	srv, err := control.New(db, control.Options{
		Password: "admin-password-1234",
		APIToken: validToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Missing token -> 401
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/state", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth status = %d, want 401", rec.Code)
	}

	// Wrong token -> 401
	req := httptest.NewRequest("GET", "/api/v1/state", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status = %d, want 401", rec.Code)
	}

	// Valid token -> 200 on GET and POST without cookie or CSRF
	req = httptest.NewRequest("GET", "/api/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid bearer GET status = %d, want 200", rec.Code)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(map[string]any{
		"name":       "automation-test",
		"public_key": base64.StdEncoding.EncodeToString(pub),
	})
	var st struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/api/v1/agents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"`+string(rune('0'+st.Revision))+`"`)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("valid bearer POST /api/v1/agents status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Valid Bearer token on GET /api/v1/events streams SSE snapshot.
	ts := httptest.NewServer(srv)
	defer ts.Close()
	evCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	evReq, _ := http.NewRequestWithContext(evCtx, "GET", ts.URL+"/api/v1/events", nil)
	evReq.Header.Set("Authorization", "Bearer "+validToken)
	evResp, err := ts.Client().Do(evReq)
	if err != nil {
		t.Fatal("GET /api/v1/events:", err)
	}
	defer evResp.Body.Close()
	if evResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/events status = %d, want 200", evResp.StatusCode)
	}
	buf := make([]byte, 256)
	n, _ := evResp.Body.Read(buf)
	cancel()
	if !strings.Contains(string(buf[:n]), "event: snapshot") {
		t.Fatalf("GET /api/v1/events missing snapshot event: %q", string(buf[:n]))
	}
}
