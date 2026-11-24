// Package agent implements the in-memory Agent state and controller client.
package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"

	"github.com/eddiexyang/graphnet/internal/model"
)

const maxSnapshotBytes = 8 << 20

type Registration struct {
	CA        []byte                 `json:"ca,omitempty"`
	Transport string                 `json:"transport,omitempty"`
	Directory *model.ServerDirectory `json:"directory,omitempty"`
	AgentID   model.ID               `json:"agent_id"`
	Server    string                 `json:"server"`
	// Certificate is empty for an Agent registered by public key; it signs
	// controller challenges instead of presenting a client certificate.
	Certificate []byte `json:"certificate"`
}

// KeyOnly reports a registration by public key, without a certificate.
func (r Registration) KeyOnly() bool { return len(r.Certificate) == 0 }

func (r Registration) clone() Registration {
	out := r
	out.CA = bytes.Clone(r.CA)
	out.Certificate = bytes.Clone(r.Certificate)
	if r.Directory != nil {
		out.Directory = r.Directory.Clone()
	}
	return out
}

// Cache holds an Agent runtime state in memory; on every start the node
// registers by its configured key and fetches configuration from the
// controller. A cache from OpenDiskCache also writes configuration through to
// disk as an offline fallback (see diskcache.go); memory stays authoritative.
type Cache struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	reg     *Registration
	desired []byte
	applied []byte
	routes  []byte
	lastSrv string

	disk     *diskState
	fallback *fallback
}

// NewMemoryCache creates an in-memory cache for identity. If identity is nil,
// a fresh ephemeral key is generated (used by tests and enrollment).
func NewMemoryCache(identity ed25519.PrivateKey) (*Cache, error) {
	var key ed25519.PrivateKey
	if identity != nil {
		if len(identity) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(identity.Seed()), identity) {
			return nil, errors.New("invalid private identity")
		}
		key = bytes.Clone(identity)
	} else {
		var err error
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	return &Cache{key: key}, nil
}

func (c *Cache) Close() error                   { return c.disk.close() }
func (c *Cache) PrivateKey() ed25519.PrivateKey { return bytes.Clone(c.key) }
func (c *Cache) PublicKey() ed25519.PublicKey   { return c.key.Public().(ed25519.PublicKey) }
func (c *Cache) CSR() ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, c.key)
}

func (c *Cache) Registration() (*Registration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reg == nil {
		return nil, nil
	}
	cp := c.reg.clone()
	return &cp, nil
}

func (c *Cache) SaveRegistration(reg Registration) error {
	if err := reg.AgentID.Validate(); err != nil {
		return err
	}
	if _, err := serverURL(reg.Server); err != nil {
		return err
	}
	if reg.KeyOnly() {
		if len(reg.CA) == 0 {
			return errors.New("registration by public key requires the controller CA")
		}
	} else if _, err := c.TLSCertificate(reg); err != nil {
		return err
	}
	if err := validateDirectory(reg, reg.Directory); err != nil {
		return err
	}
	raw, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.reg != nil && !sameIdentity(*c.reg, reg) {
		// The controller answered with another identity: the state kept for
		// the previous one is not ours any more.
		c.desired, c.applied, c.routes, c.fallback = nil, nil, nil, nil
	}
	cp := reg.clone()
	c.reg = &cp
	c.mu.Unlock()
	c.disk.saveRegistration(cp, raw)
	return nil
}

// sameIdentity reports whether two registrations name the same agent in the
// same cluster under the same CA.
func sameIdentity(a, b Registration) bool {
	return a.AgentID == b.AgentID && clusterOf(a) == clusterOf(b) && bytes.Equal(a.CA, b.CA)
}

func clusterOf(r Registration) model.ID {
	if r.Directory == nil {
		return ""
	}
	return r.Directory.ClusterID
}

func verifyRegistrationCert(reg Registration, expectedPub ed25519.PublicKey) (*x509.Certificate, error) {
	block, rest := pem.Decode(reg.Certificate)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid agent certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(expectedPub) || cert.Subject.CommonName != string(reg.AgentID) {
		return nil, errors.New("certificate does not match agent identity")
	}
	return cert, nil
}

func (c *Cache) TLSCertificate(reg Registration) (tls.Certificate, error) {
	cert, err := verifyRegistrationCert(reg, c.PublicKey())
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: c.PrivateKey(), Leaf: cert}, nil
}

func (c *Cache) snapshotFromLocked(raw []byte) (*model.Snapshot, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > maxSnapshotBytes {
		return nil, errors.New("cached snapshot too large")
	}
	if c.reg == nil {
		return nil, errors.New("missing registration")
	}
	var snapshot model.Snapshot
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.Validate(c.reg.AgentID) != nil {
		return nil, nil
	}
	return &snapshot, nil
}

func (c *Cache) Snapshots() (desired, applied *model.Snapshot, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if desired, err = c.snapshotFromLocked(c.desired); err != nil {
		return nil, nil, err
	}
	applied, err = c.snapshotFromLocked(c.applied)
	return desired, applied, err
}

// SaveDesired must finish before runtime application. A revision identifies one
// immutable snapshot; replaying it with different content is an error.
func (c *Cache) SaveDesired(snapshot model.Snapshot) error {
	return c.saveSnapshot(false, snapshot)
}

func (c *Cache) MarkApplied(snapshot model.Snapshot) error {
	return c.saveSnapshot(true, snapshot)
}

func (c *Cache) saveSnapshot(applied bool, snapshot model.Snapshot) error {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if len(raw) > maxSnapshotBytes {
		return errors.New("snapshot too large")
	}
	id, changed, err := c.storeSnapshot(applied, snapshot, raw)
	if err != nil || !changed {
		return err
	}
	// Writes are ordered by the Reconciler's apply lock, not by c.mu, so a slow
	// disk never blocks readers of the in-memory state.
	key := keyDesired
	if applied {
		key = keyApplied
	}
	c.disk.put(id, key, raw)
	return nil
}

func (c *Cache) storeSnapshot(applied bool, snapshot model.Snapshot, raw []byte) (model.ID, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reg == nil {
		return "", false, errors.New("missing registration")
	}
	if err := snapshot.Validate(c.reg.AgentID); err != nil {
		return "", false, err
	}
	slot := c.desired
	if applied {
		slot = c.applied
	}
	prior, err := c.snapshotFromLocked(slot)
	if err != nil {
		return "", false, err
	}
	if prior != nil {
		if snapshot.Revision < prior.Revision {
			return "", false, errors.New("snapshot revision rollback rejected")
		}
		if snapshot.Revision == prior.Revision {
			previous, _ := json.Marshal(prior)
			if !bytes.Equal(raw, previous) {
				return "", false, errors.New("snapshot revision changed content")
			}
			return "", false, nil
		}
	}
	if applied {
		desired, err := c.snapshotFromLocked(c.desired)
		if err != nil {
			return "", false, err
		}
		if desired == nil {
			return "", false, errors.New("cannot apply before persisting desired snapshot")
		}
		expected, _ := json.Marshal(desired)
		if !bytes.Equal(raw, expected) {
			return "", false, errors.New("applied snapshot differs from desired state")
		}
		c.applied = raw
	} else {
		c.desired = raw
	}
	return c.reg.AgentID, true, nil
}
