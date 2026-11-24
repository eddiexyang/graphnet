package cluster

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/pki"
	"github.com/eddiexyang/graphnet/internal/store"
)

// A server's client certificate is re-issued from the local cluster CA when
// it nears expiry, and the new one is saved with the identity.
func TestServerClientCertificateRenewsAndPersists(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	identity, err := LoadIdentity(db)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.LoadOrCreate(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(db, ca, &identity, nil); err != nil {
		t.Fatal(err)
	}
	issued := identity.Certificate
	if err := Initialize(db, ca, &identity, nil); err != nil || string(identity.Certificate) != string(issued) {
		t.Fatalf("a valid certificate was re-issued at startup: %v", err)
	}
	c, err := newClients(db, identity, ca)
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the certificate expires within the renewal window.
	due := *c.cert.Leaf
	due.NotAfter = time.Now().Add(time.Hour)
	c.cert.Leaf = &due
	got, err := c.certificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || pki.NeedsRenewal(got.Leaf, time.Now()) || string(c.identity.Certificate) == string(issued) {
		t.Fatal("client certificate was not renewed")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	if _, err := got.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadIdentity(db)
	if err != nil || string(saved.Certificate) != string(c.identity.Certificate) {
		t.Fatalf("renewed certificate not saved: %v", err)
	}
}
