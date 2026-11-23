package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The disk cache is an offline fallback only. It keeps the last configuration
// a previous process received so an Agent that cannot reach any controller at
// startup still forwards traffic. It never feeds registration, controller
// selection or revision ordering: the controller stays authoritative, so a
// rebuilt controller (new CA, reset revisions) cannot be locked out by stale
// local state.
var (
	stateBucket  = []byte("agent-v2")
	legacyBucket = []byte("agent-v1") // pre-stateless layout, held the private key
	keyPublic    = []byte("public-key")
	keyAgentID   = []byte("agent-id")
	keyDesired   = []byte("desired")
	keyApplied   = []byte("applied")
	keyRoutes    = []byte("routes")
)

// ErrCacheInUse reports a disk cache held by another process or instance.
var ErrCacheInUse = errors.New("agent cache is in use by another process")

// fallback is what a previous process left on disk, validated once at open.
type fallback struct {
	agentID model.ID
	desired *model.Snapshot // last received; may have failed to apply
	applied *model.Snapshot // last applied successfully
	routes  *model.RouteUpdate
}

type diskState struct {
	db     *bolt.DB
	log    *slog.Logger
	broken atomic.Bool
	routes []byte // last persisted route update, to skip identical writes
}

// OpenDiskCache opens an Agent cache for identity whose configuration is also
// written to path. Unreadable or inconsistent state is discarded, never fatal;
// if the file cannot be used at all the Agent runs without a fallback. Only a
// second process holding the same file is an error.
func OpenDiskCache(path string, identity ed25519.PrivateKey, log *slog.Logger) (*Cache, error) {
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
	db, fb, err := openState(path, cache.PublicKey(), log)
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("%w: %s", ErrCacheInUse, path)
	}
	if err != nil {
		log.Warn("agent disk cache unavailable; starting without offline fallback", "path", path, "error", err)
		return cache, nil
	}
	cache.disk = &diskState{db: db, log: log}
	if fb.desired != nil || fb.applied != nil {
		cache.fallback = fb
		if fb.routes != nil {
			cache.disk.routes, _ = json.Marshal(fb.routes)
		}
	}
	return cache, nil
}

func openState(path string, pub ed25519.PublicKey, log *slog.Logger) (*bolt.DB, *fallback, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	db, fb, err := openStateOnce(path, pub, log)
	if err == nil || errors.Is(err, bolt.ErrTimeout) {
		return db, fb, err
	}
	// A corrupted file is only a lost fallback: replace it.
	log.Warn("discarding unreadable agent disk cache", "path", path, "error", err)
	if rm := os.Remove(path); rm != nil && !errors.Is(rm, os.ErrNotExist) {
		return nil, nil, errors.Join(err, rm)
	}
	return openStateOnce(path, pub, log)
}

func openStateOnce(path string, pub ed25519.PublicKey, log *slog.Logger) (db *bolt.DB, fb *fallback, err error) {
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
			reasons, err := loadFallback(b, fb)
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
func loadFallback(b *bolt.Bucket, fb *fallback) (dropped []string, err error) {
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
		if b.Get(keyDesired) != nil || b.Get(keyApplied) != nil || b.Get(keyRoutes) != nil {
			drop("configuration without a valid agent id", keyAgentID, keyDesired, keyApplied, keyRoutes)
		}
		return dropped, err
	}
	fb.agentID = id
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
	if d == nil || d.broken.Load() {
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
				for _, k := range [][]byte{keyDesired, keyApplied, keyRoutes} {
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

func (d *diskState) close() error {
	if d == nil {
		return nil
	}
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
