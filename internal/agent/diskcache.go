package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/controltransport"
	"github.com/eddiexyang/graphnet/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The disk cache keeps an enrolled or registered Agent's controller metadata
// (never its private key) and the last configuration a previous process
// received so an Agent that restarts without bootstrap flags or cannot reach
// any controller at startup still connects and forwards traffic. Snapshot
// fallback never feeds revision ordering: the controller stays authoritative.
var (
	stateBucket     = []byte("agent-v2")
	legacyBucket    = []byte("agent-v1") // pre-stateless layout, held the private key
	keyPublic       = []byte("public-key")
	keyAgentID      = []byte("agent-id")
	keyRegistration = []byte("registration")
	keyDesired      = []byte("desired")
	keyApplied      = []byte("applied")
	keyRoutes       = []byte("routes")
	keyConfigHash   = []byte("config-hash")
)

// ErrCacheInUse reports a disk cache held by another process or instance.
var ErrCacheInUse = errors.New("agent cache is in use by another process")

// fallback is what a previous process left on disk, validated once at open.
type fallback struct {
	miss    bool // stored under another configuration hash; nothing loaded
	agentID model.ID
	reg     *Registration
	desired *model.Snapshot // last received; may have failed to apply
	applied *model.Snapshot // last applied successfully
	routes  *model.RouteUpdate
}

type diskState struct {
	db     *bolt.DB
	log    *slog.Logger
	pub    ed25519.PublicKey
	hash   []byte // configuration hash this process runs with; nil for a bare start
	broken atomic.Bool
	closed atomic.Bool
	// miss is set while the file holds state of another configuration. Nothing
	// is written or cleared until the controller accepts this configuration.
	miss   atomic.Bool
	routes []byte // last persisted route update, to skip identical writes
}

// ConfigHash identifies the configuration a node was started with. A disk
// cache opened with it only serves state written under the same hash.
func ConfigHash(pub ed25519.PublicKey, server, transport string, ca, gatewayCA []byte) []byte {
	h := sha256.New()
	for _, field := range [][]byte{pub, []byte(server), []byte(transport), ca, gatewayCA} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	return h.Sum(nil)
}

// OpenDiskCache opens an Agent cache for identity whose configuration is also
// written to path. Unreadable or inconsistent state is discarded, never fatal;
// if the file cannot be used at all the Agent runs without a fallback. Only a
// second process holding the same file is an error. It serves an Agent that
// starts without explicit configuration: stored state is validated by its
// public key and certificate only.
func OpenDiskCache(path string, identity ed25519.PrivateKey, log *slog.Logger) (*Cache, error) {
	return openDiskCache(path, identity, nil, log)
}

// OpenConfiguredDiskCache opens a disk cache for a node started with explicit
// configuration, identified by configHash (see ConfigHash). State stored under
// another hash is a cache miss: none of it is loaded, and the file is left
// untouched until the controller accepts a registration, which then replaces
// it in one transaction.
func OpenConfiguredDiskCache(path string, identity ed25519.PrivateKey, configHash []byte, log *slog.Logger) (*Cache, error) {
	if len(configHash) == 0 {
		return nil, errors.New("disk cache requires a configuration hash")
	}
	return openDiskCache(path, identity, configHash, log)
}

func openDiskCache(path string, identity ed25519.PrivateKey, configHash []byte, log *slog.Logger) (*Cache, error) {
	if identity == nil {
		return nil, errors.New("disk cache requires a configured identity")
	}
	cache, err := NewMemoryCache(identity)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	db, fb, err := openState(path, cache.PublicKey(), configHash, log)
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("%w: %s", ErrCacheInUse, path)
	}
	if err != nil {
		log.Warn("agent disk cache unavailable; starting without offline fallback", "path", path, "error", err)
		return cache, nil
	}
	cache.disk = &diskState{db: db, log: log, pub: cache.PublicKey(), hash: bytes.Clone(configHash)}
	if fb.miss {
		cache.disk.miss.Store(true)
		log.Info("agent disk cache: stored state belongs to another configuration; not loaded", "path", path)
		return cache, nil
	}
	if fb.reg != nil {
		cp := fb.reg.clone()
		cache.reg = &cp
	}
	if fb.desired != nil || fb.applied != nil {
		cache.fallback = fb
		if fb.routes != nil {
			cache.disk.routes, _ = json.Marshal(fb.routes)
		}
	}
	return cache, nil
}

func openState(path string, pub ed25519.PublicKey, configHash []byte, log *slog.Logger) (*bolt.DB, *fallback, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	db, fb, err := openStateOnce(path, pub, configHash, log)
	if err == nil || errors.Is(err, bolt.ErrTimeout) {
		return db, fb, err
	}
	// A corrupted file is only a lost fallback: replace it.
	log.Warn("discarding unreadable agent disk cache", "path", path, "error", err)
	if rm := os.Remove(path); rm != nil && !errors.Is(rm, os.ErrNotExist) {
		return nil, nil, errors.Join(err, rm)
	}
	return openStateOnce(path, pub, configHash, log)
}

func openStateOnce(path string, pub ed25519.PublicKey, configHash []byte, log *slog.Logger) (db *bolt.DB, fb *fallback, err error) {
	if db, err = bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second}); err != nil {
		return nil, nil, err
	}
	fb = &fallback{}
	var dropped []string
	err = func() (err error) {
		// bbolt panics on some page corruption instead of returning an error.
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("corrupted agent cache: %v", p)
			}
		}()
		if configHash != nil {
			if err := db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket(stateBucket)
				fb.miss = b == nil || !bytes.Equal(b.Get(keyConfigHash), configHash) || !bytes.Equal(b.Get(keyPublic), pub)
				return nil
			}); err != nil || fb.miss {
				return err
			}
		}
		return db.Update(func(tx *bolt.Tx) error {
			if tx.Bucket(legacyBucket) != nil {
				if err := tx.DeleteBucket(legacyBucket); err != nil {
					return err
				}
				dropped = append(dropped, "legacy agent-v1 state")
			}
			b, err := tx.CreateBucketIfNotExists(stateBucket)
			if err != nil {
				return err
			}
			if stored := b.Get(keyPublic); stored != nil && !bytes.Equal(stored, pub) {
				// State of another identity is never a fallback for this one.
				if err := tx.DeleteBucket(stateBucket); err != nil {
					return err
				}
				if b, err = tx.CreateBucket(stateBucket); err != nil {
					return err
				}
				dropped = append(dropped, "state of a different private key")
			}
			if err := b.Put(keyPublic, pub); err != nil {
				return err
			}
			reasons, err := loadFallback(b, pub, fb)
			dropped = append(dropped, reasons...)
			return err
		})
	}()
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	for _, reason := range dropped {
		log.Warn("agent disk cache: discarded inconsistent state", "path", path, "reason", reason)
	}
	return db, fb, nil
}

// loadFallback reads the persisted configuration and deletes every part that
// is unreadable or contradicts the rest, so what remains is safe to apply.
func loadFallback(b *bolt.Bucket, pub ed25519.PublicKey, fb *fallback) (dropped []string, err error) {
	drop := func(reason string, keys ...[]byte) {
		dropped = append(dropped, reason)
		for _, k := range keys {
			if e := b.Delete(k); e != nil && err == nil {
				err = e
			}
		}
	}
	id := model.ID(b.Get(keyAgentID))
	if id.Validate() != nil {
		if b.Get(keyRegistration) != nil || b.Get(keyDesired) != nil || b.Get(keyApplied) != nil || b.Get(keyRoutes) != nil {
			drop("configuration without a valid agent id", keyAgentID, keyRegistration, keyDesired, keyApplied, keyRoutes)
		}
		return dropped, err
	}
	fb.agentID = id
	if raw := b.Get(keyRegistration); raw != nil {
		var reg Registration
		if len(raw) > maxSnapshotBytes || json.Unmarshal(raw, &reg) != nil || validateDiskRegistration(reg, id, pub) != nil {
			drop("unreadable registration", keyRegistration)
		} else {
			fb.reg = &reg
		}
	}
	read := func(key []byte) *model.Snapshot {
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		var s model.Snapshot
		// A snapshot from another schema version or agent is skipped, not fatal.
		if len(raw) > maxSnapshotBytes || json.Unmarshal(raw, &s) != nil || s.Validate(id) != nil {
			drop("unreadable "+string(key)+" snapshot", key)
			return nil
		}
		return &s
	}
	fb.desired, fb.applied = read(keyDesired), read(keyApplied)
	if d, a := fb.desired, fb.applied; d != nil && a != nil {
		switch {
		case d.Revision < a.Revision:
			// A failed write left desired behind what was later applied.
			drop("desired snapshot older than applied", keyDesired)
			fb.desired = nil
		case d.Revision == a.Revision && !sameSnapshot(*d, *a):
			drop("desired and applied differ at one revision", keyDesired)
			fb.desired = nil
		}
	}
	if raw := b.Get(keyRoutes); raw != nil {
		var update model.RouteUpdate
		var base *model.Snapshot
		if len(raw) <= maxSnapshotBytes && json.Unmarshal(raw, &update) == nil && update.Revision != 0 {
			for _, s := range []*model.Snapshot{fb.applied, fb.desired} {
				if s != nil && s.Revision == update.Revision {
					base = s
					break
				}
			}
		}
		if base == nil {
			drop("live routes for another revision", keyRoutes)
		} else if _, e := update.Apply(*base); e != nil {
			drop("live routes inconsistent with their configuration", keyRoutes)
		} else {
			fb.routes = &update
		}
	}
	return dropped, err
}

func sameSnapshot(a, b model.Snapshot) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// put records one value for agentID. Failures only age the fallback, so they
// are logged and the in-memory state stays authoritative.
func (d *diskState) put(agentID model.ID, key, raw []byte) {
	if d == nil || d.broken.Load() || d.closed.Load() || d.miss.Load() {
		return
	}
	if bytes.Equal(key, keyRoutes) && bytes.Equal(raw, d.routes) {
		return
	}
	err := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				d.broken.Store(true)
				err = fmt.Errorf("corrupted agent cache: %v", p)
			}
		}()
		return d.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(stateBucket)
			if b == nil {
				return errors.New("missing state bucket")
			}
			if !bytes.Equal(b.Get(keyAgentID), []byte(agentID)) {
				// The controller assigned a new agent id: older state is not ours.
				for _, k := range [][]byte{keyRegistration, keyDesired, keyApplied, keyRoutes} {
					if err := b.Delete(k); err != nil {
						return err
					}
				}
				if err := b.Put(keyAgentID, []byte(agentID)); err != nil {
					return err
				}
			}
			return b.Put(key, raw)
		})
	}()
	if err != nil {
		d.log.Warn("agent disk cache write failed; offline fallback may be stale", "key", string(key), "error", err)
		return
	}
	if bytes.Equal(key, keyRoutes) {
		d.routes = bytes.Clone(raw)
	}
}

// saveRegistration records a registration the controller just returned. When
// the file holds another configuration, or the controller assigned another
// agent, cluster or CA, all older state is replaced in the same transaction.
func (d *diskState) saveRegistration(reg Registration, raw []byte) {
	if d == nil || d.broken.Load() || d.closed.Load() {
		return
	}
	reset := false
	err := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				d.broken.Store(true)
				err = fmt.Errorf("corrupted agent cache: %v", p)
			}
		}()
		return d.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(stateBucket)
			reset = d.miss.Load() || b == nil || d.hash != nil && !bytes.Equal(b.Get(keyConfigHash), d.hash) || !sameRegistrationIdentity(b, reg)
			if reset {
				for _, name := range [][]byte{legacyBucket, stateBucket} {
					if tx.Bucket(name) != nil {
						if err := tx.DeleteBucket(name); err != nil {
							return err
						}
					}
				}
				var err error
				if b, err = tx.CreateBucket(stateBucket); err != nil {
					return err
				}
				if err := b.Put(keyPublic, d.pub); err != nil {
					return err
				}
			}
			if d.hash != nil {
				if err := b.Put(keyConfigHash, d.hash); err != nil {
					return err
				}
			}
			if err := b.Put(keyAgentID, []byte(reg.AgentID)); err != nil {
				return err
			}
			return b.Put(keyRegistration, raw)
		})
	}()
	if err != nil {
		d.log.Warn("agent disk cache write failed; offline fallback may be stale", "key", string(keyRegistration), "error", err)
		return
	}
	d.miss.Store(false)
	if reset {
		d.routes = nil
	}
}

// sameRegistrationIdentity reports whether the stored state belongs to the
// agent, cluster and CA of reg.
func sameRegistrationIdentity(b *bolt.Bucket, reg Registration) bool {
	if !bytes.Equal(b.Get(keyAgentID), []byte(reg.AgentID)) {
		return false
	}
	raw := b.Get(keyRegistration)
	if raw == nil {
		return true
	}
	var old Registration
	return json.Unmarshal(raw, &old) == nil && sameIdentity(old, reg)
}

func (d *diskState) close() error {
	if d == nil {
		return nil
	}
	d.closed.Store(true)
	return d.db.Close()
}

// takeFallback hands the persisted configuration to the caller once. It is
// discarded when this process already holds a registration for another agent id.
func (c *Cache) takeFallback() *fallback {
	c.mu.Lock()
	defer c.mu.Unlock()
	fb := c.fallback
	c.fallback = nil
	if fb == nil || c.reg != nil && c.reg.AgentID != fb.agentID {
		return nil
	}
	return fb
}

func (c *Cache) dropFallback() {
	c.mu.Lock()
	c.fallback = nil
	c.mu.Unlock()
}

// persistApplied records a fallback snapshot that applied again, outside the
// in-memory ordering which only tracks this process's controller snapshots.
func (c *Cache) persistApplied(agentID model.ID, snapshot model.Snapshot) {
	if raw, err := json.Marshal(snapshot); err == nil {
		c.disk.put(agentID, keyApplied, raw)
	}
}

func validateDiskRegistration(reg Registration, expectedID model.ID, pub ed25519.PublicKey) error {
	if reg.AgentID != expectedID || reg.AgentID.Validate() != nil {
		return errors.New("registration agent id mismatch")
	}
	if _, err := serverURL(reg.Server); err != nil {
		return err
	}
	if err := controltransport.Validate(reg.Transport); err != nil {
		return err
	}
	if len(reg.CA) > 0 && !x509.NewCertPool().AppendCertsFromPEM(reg.CA) {
		return errors.New("invalid registration CA")
	}
	if reg.KeyOnly() {
		if len(reg.CA) == 0 {
			return errors.New("key registration missing CA")
		}
	} else if _, err := verifyRegistrationCert(reg, pub); err != nil {
		return err
	}
	return validateDirectory(reg, reg.Directory)
}
