package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

type testChallengeRoundTripper struct {
	base           http.RoundTripper
	id             model.ID
	key            ed25519.PrivateKey
	challengeValue string
	overrideMethod string
	overridePath   string
	overrideWSKey  *string
}

func (rt *testChallengeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if rt.challengeValue != "" {
		method := cloned.Method
		if rt.overrideMethod != "" {
			method = rt.overrideMethod
		}
		path := cloned.URL.Path
		if rt.overridePath != "" {
			path = rt.overridePath
		}
		wsKey := strings.TrimSpace(cloned.Header.Get("Sec-WebSocket-Key"))
		if rt.overrideWSKey != nil {
			wsKey = *rt.overrideWSKey
		}
		cloned.Header.Set(model.AgentIDHeader, string(rt.id))
		cloned.Header.Set(model.AgentChallengeHeader, rt.challengeValue)
		cloned.Header.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(rt.key, model.AgentChallengeMessage(rt.id, rt.challengeValue, method, path, wsKey))))
	}
	return rt.base.RoundTrip(cloned)
}

func TestSignedChallengeRequiresTLSAndBindsRequest(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	current, _ := db.Read()
	fixture := testutil.Topology()
	state, err := db.Update(current.Revision, func(s *model.State) error { *s = fixture; return nil })
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db, Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seed := make([]byte, 32)
	seed[0] = 1
	key := ed25519.NewKeyFromSeed(seed)
	id := state.Agents[0].ID

	// Plaintext requests are rejected before challenge issuance or verification.
	plain := httptest.NewServer(s)
	defer plain.Close()
	if resp, err := http.Get(plain.URL + model.AgentChallengePath); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUpgradeRequired {
			t.Fatalf("plaintext challenge status=%d, want %d", resp.StatusCode, http.StatusUpgradeRequired)
		}
	}

	server := httptest.NewUnstartedServer(s)
	server.TLS, err = s.ca.ServerTLS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	server.TLS.Certificates = nil // serve the controller certificate, not httptest's
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.ca.PEM)
	baseTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer baseTransport.CloseIdleConnections()
	tlsClient := &http.Client{Transport: baseTransport}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	challenge := func() string {
		t.Helper()
		resp, err := tlsClient.Get(server.URL + model.AgentChallengePath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct{ Challenge string }
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Challenge == "" {
			t.Fatalf("challenge: status=%d err=%v", resp.StatusCode, err)
		}
		return body.Challenge
	}

	// Plaintext request carrying a valid challenge issued over TLS is still rejected.
	cPlain := challenge()
	plainReq, _ := http.NewRequest("GET", plain.URL+model.AgentRegistrationPath, nil)
	plainReq.Header.Set(model.AgentIDHeader, string(id))
	plainReq.Header.Set(model.AgentChallengeHeader, cPlain)
	plainReq.Header.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, model.AgentChallengeMessage(id, cPlain, "GET", model.AgentRegistrationPath, ""))))
	if resp, err := http.DefaultClient.Do(plainReq); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("plaintext registration status=%d, want 401", resp.StatusCode)
		}
	}

	dial := func(rt http.RoundTripper) (*websocket.Conn, int) {
		t.Helper()
		hc := &http.Client{Transport: rt}
		conn, resp, err := websocket.Dial(ctx, strings.Replace(server.URL, "https://", "wss://", 1)+"/api/v1/agent/control", &websocket.DialOptions{HTTPClient: hc, Subprotocols: []string{model.DeltaSubprotocol}})
		if err != nil {
			if resp == nil {
				t.Fatal(err)
			}
			return nil, resp.StatusCode
		}
		return conn, http.StatusSwitchingProtocols
	}

	used := challenge()
	conn, status := dial(&testChallengeRoundTripper{base: baseTransport, id: id, key: key, challengeValue: used})
	if conn == nil {
		t.Fatalf("signed agent rejected: %d", status)
	}
	var first model.ControlMessage
	if err := wsjson.Read(ctx, conn, &first); err != nil || first.Type != "config" {
		t.Fatalf("first message %q: %v", first.Type, err)
	}
	conn.CloseNow()

	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	expired := challenge()
	s.challengeMu.Lock()
	s.challenges[expired] = time.Now().Add(-time.Second)
	s.challengeMu.Unlock()
	wrongWSKey := "dGhlIHNhbXBsZSBub25jZQ=="
	emptyWSKey := ""
	for name, rt := range map[string]*testChallengeRoundTripper{
		"replayed challenge":    {base: baseTransport, id: id, key: key, challengeValue: used},
		"unknown challenge":     {base: baseTransport, id: id, key: key, challengeValue: "never-issued"},
		"expired challenge":     {base: baseTransport, id: id, key: key, challengeValue: expired},
		"wrong key":             {base: baseTransport, id: id, key: other, challengeValue: challenge()},
		"other agent id":        {base: baseTransport, id: state.Agents[1].ID, key: key, challengeValue: challenge()},
		"wrong method signed":   {base: baseTransport, id: id, key: key, challengeValue: challenge(), overrideMethod: "POST"},
		"wrong path signed":     {base: baseTransport, id: id, key: key, challengeValue: challenge(), overridePath: model.AgentRegistrationPath},
		"wrong ws key signed":   {base: baseTransport, id: id, key: key, challengeValue: challenge(), overrideWSKey: &wrongWSKey},
		"omitted ws key signed": {base: baseTransport, id: id, key: key, challengeValue: challenge(), overrideWSKey: &emptyWSKey},
		"no signature":          {base: baseTransport},
	} {
		if conn, status := dial(rt); conn != nil || status != http.StatusUnauthorized {
			if conn != nil {
				conn.CloseNow()
			}
			t.Errorf("%s: status=%d, want 401", name, status)
		}
	}

	// Cross-route HTTP replay: signature made for /api/v1/agent/update/latest moved to /api/v1/agent/registration.
	crossChallenge := challenge()
	crossReq, _ := http.NewRequest("GET", server.URL+model.AgentRegistrationPath, nil)
	crossReq.Header.Set(model.AgentIDHeader, string(id))
	crossReq.Header.Set(model.AgentChallengeHeader, crossChallenge)
	crossReq.Header.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, model.AgentChallengeMessage(id, crossChallenge, "GET", "/api/v1/agent/update/latest", ""))))
	if resp, err := tlsClient.Do(crossReq); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("cross-path replay status=%d, want 401", resp.StatusCode)
		}
	}

	if _, err := db.Update(state.Revision, func(s *model.State) error { s.Agents[0].Revoked = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if conn, status := dial(&testChallengeRoundTripper{base: baseTransport, id: id, key: key, challengeValue: challenge()}); conn != nil || status != http.StatusUnauthorized {
		t.Errorf("revoked agent: status=%d, want 401", status)
	}
}

func TestBoundedAuthTablesEvictOldestAndPurgeExpiredRecords(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	apiToken := "0123456789abcdef0123456789abcdef"
	s, err := New(db, Options{Password: "strong-admin-password-123", APIToken: apiToken})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	cur, _ := db.Read()
	_, _ = db.Update(cur.Revision, func(st *model.State) error {
		st.ClusterID = model.NewID()
		st.ClusterCA = ca.PEM
		st.Servers = []model.Server{{ID: model.NewID(), Name: "c1", PublicKey: pub}}
		return nil
	})
	server := httptest.NewUnstartedServer(s)
	server.TLS, err = ca.ServerTLS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	server.TLS.Certificates = nil // serve the controller certificate, not httptest's
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}

	// 1. Overfilling maxAgentChallenges (4096) evicts oldest instead of returning 503.
	s.challengeMu.Lock()
	s.challenges["oldest-challenge"] = time.Now().Add(10 * time.Second)
	for i := range maxAgentChallenges - 1 {
		s.challenges[string(rune(i+1))+"-c"] = time.Now().Add(50 * time.Second)
	}
	s.challengeMu.Unlock()
	resp, err := tlsClient.Get(server.URL + model.AgentChallengePath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("agentChallenge under flood returned %d, want 200", resp.StatusCode)
	}
	if s.consumeChallenge("oldest-challenge") {
		t.Fatal("oldest challenge was not evicted at capacity")
	}

	// 2. Enrollment attempt flood from 4100 IPs neither locks out a fresh IP nor affects loginAttempts.
	for i := range 4100 {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", nil)
		req.RemoteAddr = "198.51.100.1:" + string(rune(i+1000))
		// Distinct host IPs:
		req.RemoteAddr = net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String() + ":12345"
		if !s.auth.allowEnrollAttempt(req) {
			t.Fatalf("allowEnrollAttempt rejected fresh IP %d under flood", i)
		}
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
	loginReq.RemoteAddr = "10.0.0.1:54321"
	if !s.auth.allowAttempt(loginReq) {
		t.Fatal("enrollment flood polluted loginAttempts bucket")
	}

	// 3. Expired enrollment/* and server-join/* records are deterministically purged on write.
	expiredRaw, _ := json.Marshal(map[string]any{"expires": time.Now().Add(-time.Minute)})
	if err := db.WriteRecords(func(r *store.Records) error {
		_ = r.Put("enrollment/deadbeef", expiredRaw)
		_ = r.Put("enrollment/deadbeef/receipt", expiredRaw)
		return r.Put("server-join/cafebabe", expiredRaw)
	}); err != nil {
		t.Fatal(err)
	}
	tokReq, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/enrollment-tokens", strings.NewReader(`{"ttl_seconds":60}`))
	tokReq.Header.Set("Content-Type", "application/json")
	tokReq.Header.Set("Authorization", "Bearer "+apiToken)
	tokResp, err := tlsClient.Do(tokReq)
	if err != nil {
		t.Fatal(err)
	}
	tokResp.Body.Close()
	if tokResp.StatusCode != 201 {
		t.Fatalf("createEnrollmentToken = %d", tokResp.StatusCode)
	}
	_ = db.ReadRecords(func(r *store.Records) error {
		for _, k := range []string{"enrollment/deadbeef", "enrollment/deadbeef/receipt", "server-join/cafebabe"} {
			if r.Get(k) != nil {
				t.Fatalf("expired record %s survived PurgeExpired", k)
			}
		}
		return nil
	})
}
