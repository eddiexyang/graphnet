package control_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	srv, err := control.New(db, control.Options{
		Password: "admin-password-1234",
		APIToken: "secret-api-token-xyz",
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
	req.Header.Set("Authorization", "Bearer secret-api-token-xyz")
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
	req.Header.Set("Authorization", "Bearer secret-api-token-xyz")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"`+string(rune('0'+st.Revision))+`"`)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("valid bearer POST /api/v1/agents status = %d body=%s", rec.Code, rec.Body.String())
	}
}
