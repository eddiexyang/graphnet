package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// An enrolled Agent renews its certificate by a challenge signed with its
// registered key, which still works once the certificate has expired.
func TestAgentRenewsCertificateWithRegisteredKey(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	current, _ := db.Read()
	state, err := db.Update(current.Revision, func(s *model.State) error { *s = testutil.Topology(); return nil })
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

	server := httptest.NewUnstartedServer(s)
	if server.TLS, err = s.ca.ServerTLS([]string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	server.TLS.Certificates = nil // serve the controller certificate, not httptest's
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.ca.PEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}

	renew := func(signer ed25519.PrivateKey, csrKey ed25519.PrivateKey) *http.Response {
		t.Helper()
		resp, err := client.Get(server.URL + model.AgentChallengePath)
		if err != nil {
			t.Fatal(err)
		}
		var body struct{ Challenge string }
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"csr": csr})
		req, _ := http.NewRequest("POST", server.URL+model.AgentRenewPath, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if signer != nil {
			req.Header.Set(model.AgentIDHeader, string(id))
			req.Header.Set(model.AgentChallengeHeader, body.Challenge)
			req.Header.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, model.AgentChallengeMessage(id, body.Challenge, "POST", model.AgentRenewPath, ""))))
		}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := renew(key, key)
	var out struct {
		AgentID     model.ID `json:"agent_id"`
		Certificate []byte   `json:"certificate"`
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil || out.AgentID != id {
		t.Fatalf("renew: status=%d id=%s err=%v", resp.StatusCode, out.AgentID, err)
	}
	block, _ := pem.Decode(out.Certificate)
	if block == nil {
		t.Fatal("renewed certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || cert.Subject.CommonName != string(id) || !key.Public().(ed25519.PublicKey).Equal(cert.PublicKey) {
		t.Fatalf("renewed certificate: cn=%s err=%v", cert.Subject.CommonName, err)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if resp := renew(key, other); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("certificate request for another key: status=%d", resp.StatusCode)
	}
	if resp := renew(nil, key); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated renewal: status=%d", resp.StatusCode)
	}
	if resp := renew(other, key); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("renewal signed by another key: status=%d", resp.StatusCode)
	}
}
