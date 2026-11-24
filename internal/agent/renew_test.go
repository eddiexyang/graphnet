package agent

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/control"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// An enrolled Agent whose certificate is inside the renewal window renews it
// from the controller before it connects, and keeps the new one.
func TestEnrolledAgentRenewsCertificateBeforeExpiry(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cache, err := NewMemoryCache(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	fixture := testutil.Topology()
	fixture.Agents[0].PublicKey = cache.PublicKey()
	current, _ := db.Read()
	if _, err := db.Update(current.Revision, func(s *model.State) error { *s = fixture; return nil }); err != nil {
		t.Fatal(err)
	}
	server, err := control.New(db, control.Options{Password: "test-password-123"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	controller := model.Server{ID: testutil.ID(90), Name: "controller", PublicKey: fixture.Agents[1].PublicKey}
	listener := httptest.NewUnstartedServer(server)
	if listener.TLS, err = ca.ServerTLS([]string{"127.0.0.1", controller.TLSName()}); err != nil {
		t.Fatal(err)
	}
	listener.StartTLS()
	listener.TLS.Certificates = nil // serve the controller certificate, not httptest's
	defer listener.Close()
	controller.Endpoints = []model.ServerEndpoint{{ID: testutil.ID(91), Transport: "tcp", Source: model.Manual, URL: strings.Replace(listener.URL, "https://", "tcp://", 1)}}

	csr, err := cache.CSR()
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, err := ca.IssueAgent(fixture.Agents[0].ID, csr)
	if err != nil {
		t.Fatal(err)
	}
	reg := Registration{AgentID: fixture.Agents[0].ID, Server: listener.URL, Transport: "tcp", Certificate: certificate, CA: ca.PEM,
		Directory: &model.ServerDirectory{ClusterID: testutil.ID(99), Revision: 1, CA: ca.PEM, Servers: []model.Server{controller}}}
	if err := cache.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	old, _ := cache.TLSCertificate(reg)

	renewalClock = func() time.Time { return old.Leaf.NotAfter.Add(-pki.RenewBefore / 2) }
	t.Cleanup(func() { renewalClock = time.Now })

	runtime := applyRecorder{applied: make(chan model.Snapshot, 1)}
	client, err := NewClient(cache, runtime, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go client.Run(ctx)
	select {
	case <-runtime.applied:
	case <-ctx.Done():
		t.Fatal("agent received no configuration")
	}
	saved, err := cache.Registration()
	if err != nil || saved == nil {
		t.Fatal(err)
	}
	renewed, err := cache.TLSCertificate(*saved)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved.Certificate) == string(certificate) || renewed.Leaf.NotAfter.Before(old.Leaf.NotAfter) || renewed.Leaf.SerialNumber.Cmp(old.Leaf.SerialNumber) == 0 {
		t.Fatal("certificate was not renewed")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	if _, err := renewed.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}
