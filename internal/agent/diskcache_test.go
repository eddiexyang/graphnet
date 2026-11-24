package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	bolt "go.etcd.io/bbolt"
)

type recordingRuntime struct {
	mu      sync.Mutex
	applied []uint64
	fail    map[uint64]bool
}

func (r *recordingRuntime) revisions() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint64{}, r.applied...)
}

func (r *recordingRuntime) Apply(_ context.Context, s model.Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail[s.Revision] {
		return errors.New("refused")
	}
	r.applied = append(r.applied, s.Revision)
	return nil
}
func (r *recordingRuntime) Report() []model.LinkStatus { return nil }

type diskFixture struct {
	path     string
	key      ed25519.PrivateKey
	reg      Registration
	snapshot model.Snapshot
}

func newDiskFixture(t *testing.T) diskFixture {
	t.Helper()
	mem, _, _ := registeredController(t)
	reg, _ := mem.Registration()
	desired, _, _ := mem.Snapshots()
	return diskFixture{path: filepath.Join(t.TempDir(), "state", "agent.db"), key: mem.PrivateKey(), reg: *reg, snapshot: *desired}
}

func (f diskFixture) open(t *testing.T) *Cache {
	t.Helper()
	c, err := OpenDiskCache(f.path, f.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seed runs one controller session: register, then accept each snapshot.
func (f diskFixture) seed(t *testing.T, snapshots ...model.Snapshot) {
	t.Helper()
	c := f.open(t)
	defer c.Close()
	if err := c.SaveRegistration(f.reg); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler(c, &recordingRuntime{})
	for _, s := range snapshots {
		if err := r.Accept(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
}

func (f diskFixture) rev(n uint64) model.Snapshot {
	s := f.snapshot.Clone()
	s.Revision = n
	return s
}

func (f diskFixture) edit(t *testing.T, fn func(b *bolt.Bucket) error) {
	t.Helper()
	db, err := bolt.Open(f.path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error { return fn(tx.Bucket(stateBucket)) }); err != nil {
		t.Fatal(err)
	}
}

func TestDiskFallbackRestoresOnlyUntilControllerConfirms(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(500))

	c := f.open(t)
	defer c.Close()
	rt := &recordingRuntime{}
	r := NewReconciler(c, rt)
	got, err := r.RestoreFallback(t.Context())
	if err != nil || got != 500 {
		t.Fatalf("restore = %d, %v", got, err)
	}
	if rep := r.Report(""); rep.AppliedRevision != 0 {
		t.Fatalf("restored revision reported to controller: %d", rep.AppliedRevision)
	}
	if again, _ := r.RestoreFallback(t.Context()); again != 0 {
		t.Fatal("fallback applied twice")
	}
	// A rebuilt controller restarts revisions: it still wins over the cache.
	if err := c.SaveRegistration(f.reg); err != nil {
		t.Fatal(err)
	}
	if err := r.Accept(t.Context(), f.rev(3)); err != nil {
		t.Fatal("controller snapshot behind cached revision refused:", err)
	}
	if rep := r.Report(""); rep.AppliedRevision != 3 || rep.ConfigError != "" {
		t.Fatalf("report after controller snapshot: %+v", rep)
	}
	c.Close()
	c = f.open(t)
	defer c.Close()
	if c.fallback == nil || c.fallback.applied == nil || c.fallback.applied.Revision != 3 || c.fallback.desired.Revision != 3 {
		t.Fatalf("disk not rewritten by new controller generation: %+v", c.fallback)
	}
}

func TestDiskFallbackSameRevisionDifferentContentReapplies(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(7))
	c := f.open(t)
	defer c.Close()
	rt := &recordingRuntime{}
	r := NewReconciler(c, rt)
	if got, _ := r.RestoreFallback(t.Context()); got != 7 {
		t.Fatal("not restored")
	}
	c.SaveRegistration(f.reg)
	same := f.rev(7)
	if err := r.Accept(t.Context(), same); err != nil || len(rt.applied) != 1 {
		t.Fatalf("identical snapshot re-applied: %v %v", rt.applied, err)
	}
	if rep := r.Report(""); rep.AppliedRevision != 7 {
		t.Fatal("identical snapshot not confirmed")
	}

	f2 := newDiskFixture(t)
	f2.seed(t, f2.rev(7))
	c2 := f2.open(t)
	defer c2.Close()
	rt2 := &recordingRuntime{}
	r2 := NewReconciler(c2, rt2)
	r2.RestoreFallback(t.Context())
	c2.SaveRegistration(f2.reg)
	changed := f2.rev(7)
	changed.Networks[0].Name += "-rebuilt"
	if err := r2.Accept(t.Context(), changed); err != nil || len(rt2.applied) != 2 {
		t.Fatalf("different content at cached revision not applied: %v %v", rt2.applied, err)
	}
}

func TestDiskFallbackNotUsedOnceConfigured(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(5))
	c := f.open(t)
	defer c.Close()
	c.SaveRegistration(f.reg)
	rt := &recordingRuntime{}
	r := NewReconciler(c, rt)
	if err := r.Accept(t.Context(), f.rev(6)); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.RestoreFallback(t.Context()); got != 0 || len(rt.applied) != 1 {
		t.Fatalf("fallback replaced controller configuration: %d %v", got, rt.applied)
	}
}

func TestDiskFallbackFailedDesiredUsesApplied(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(5))
	f.edit(t, func(b *bolt.Bucket) error { raw, _ := json.Marshal(f.rev(6)); return b.Put(keyDesired, raw) })
	c := f.open(t)
	defer c.Close()
	r := NewReconciler(c, &recordingRuntime{fail: map[uint64]bool{6: true}})
	got, err := r.RestoreFallback(t.Context())
	var apply *ApplyError
	if got != 5 || !errors.As(err, &apply) {
		t.Fatalf("restore = %d, %v", got, err)
	}
	if r.Report("").ConfigError == "" {
		t.Fatal("failed desired revision not reported")
	}
}

func TestDiskCacheDiscardsInconsistentState(t *testing.T) {
	cases := map[string]struct {
		edit        func(f diskFixture, b *bolt.Bucket) error
		wantDesired uint64
		wantApplied uint64
	}{
		"unreadable desired": {func(f diskFixture, b *bolt.Bucket) error { return b.Put(keyDesired, []byte("{")) }, 0, 5},
		"older schema": {func(f diskFixture, b *bolt.Bucket) error {
			s := f.rev(6)
			s.Schema--
			raw, _ := json.Marshal(s)
			return b.Put(keyDesired, raw)
		}, 0, 5},
		"desired behind applied": {func(f diskFixture, b *bolt.Bucket) error {
			raw, _ := json.Marshal(f.rev(4))
			return b.Put(keyDesired, raw)
		}, 0, 5},
		"same revision other content": {func(f diskFixture, b *bolt.Bucket) error {
			s := f.rev(5)
			s.Networks[0].Name += "-x"
			raw, _ := json.Marshal(s)
			return b.Put(keyDesired, raw)
		}, 0, 5},
		"missing agent id": {func(f diskFixture, b *bolt.Bucket) error { return b.Delete(keyAgentID) }, 0, 0},
		"routes for other revision": {func(f diskFixture, b *bolt.Bucket) error {
			raw, _ := json.Marshal(model.RouteUpdate{Revision: 9})
			return b.Put(keyRoutes, raw)
		}, 5, 5},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newDiskFixture(t)
			f.seed(t, f.rev(5))
			f.edit(t, func(b *bolt.Bucket) error { return tc.edit(f, b) })
			c := f.open(t)
			defer c.Close()
			var d, a uint64
			if fb := c.fallback; fb != nil {
				if fb.desired != nil {
					d = fb.desired.Revision
				}
				if fb.applied != nil {
					a = fb.applied.Revision
				}
				if fb.routes != nil {
					t.Fatal("inconsistent routes kept")
				}
			}
			if d != tc.wantDesired || a != tc.wantApplied {
				t.Fatalf("desired=%d applied=%d, want %d %d", d, a, tc.wantDesired, tc.wantApplied)
			}
		})
	}
}

func TestDiskCacheIdentityAndFileFailures(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(5))

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	c, err := OpenDiskCache(f.path, other, nil)
	if err != nil || c.fallback != nil {
		t.Fatalf("state of another key kept: %v", err)
	}
	c.Close()

	f.seed(t, f.rev(5))
	held := f.open(t)
	if _, err := OpenDiskCache(f.path, f.key, nil); err == nil {
		t.Fatal("second process opened a held cache")
	}
	held.Close()

	if err := os.WriteFile(f.path, []byte("not a bolt database, definitely not"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = f.open(t)
	if c.fallback != nil || c.disk == nil {
		t.Fatal("corrupted file not replaced with an empty cache")
	}
	c.Close()

	// The pre-stateless layout stored the private key on disk; it is removed.
	db, _ := bolt.Open(f.path, 0o600, nil)
	db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists(legacyBucket)
		return b.Put([]byte("identity"), f.key)
	})
	db.Close()
	f.open(t).Close()
	db, _ = bolt.Open(f.path, 0o600, nil)
	defer db.Close()
	db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(legacyBucket) != nil {
			t.Fatal("legacy bucket with private key kept")
		}
		return nil
	})
}

// Run applies the disk fallback when no controller answers at startup, keeps
// it running while it retries, and without a fallback still exits as before.
func TestRunUsesDiskFallbackOnlyWhenControllerUnreachable(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(5))
	c := f.open(t)
	defer c.Close()
	rt := &recordingRuntime{}
	client, err := NewClient(c, rt, Options{Server: "https://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(rt.revisions()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatal("Run exited with a fallback running:", err)
	default:
	}
	if got := rt.revisions(); len(got) != 1 || got[0] != 5 {
		t.Fatalf("fallback applied: %v", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	empty, err := OpenDiskCache(filepath.Join(t.TempDir(), "agent.db"), f.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	client, err = NewClient(empty, &recordingRuntime{}, Options{Server: "https://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Run(t.Context()); !controllerUnreachable(err) {
		t.Fatal("without a fallback Run must exit on an unreachable controller:", err)
	}
}

func TestDiskCachePersistsRegistrationAndDirectoryWithoutPrivateKey(t *testing.T) {
	f := newDiskFixture(t)
	f.seed(t, f.rev(5))

	// Reopening with the same key restores registration, certificate, CA and directory.
	c := f.open(t)
	reg, err := c.Registration()
	if err != nil || reg == nil {
		t.Fatalf("registration not persisted: %+v, %v", reg, err)
	}
	if reg.AgentID != f.reg.AgentID || reg.Server != f.reg.Server || len(reg.Certificate) == 0 || reg.Directory == nil || reg.Directory.Revision != 1 {
		t.Fatalf("persisted registration incomplete: %+v", reg)
	}
	updatedDir := reg.Directory.Clone()
	updatedDir.Revision = 2
	if err := c.SaveDirectory(updatedDir, nil); err != nil {
		t.Fatal("SaveDirectory:", err)
	}
	c.Close()

	// Private key seed/bytes must never appear anywhere in agent.db.
	rawDB, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContains(rawDB, f.key.Seed()) {
		t.Fatal("private key seed written to agent.db")
	}

	c2 := f.open(t)
	reg2, err := c2.Registration()
	if err != nil || reg2 == nil || reg2.Directory == nil || reg2.Directory.Revision != 2 {
		c2.Close()
		t.Fatalf("updated directory not persisted: %+v, %v", reg2, err)
	}
	// NewClient succeeds with no Server or Roots flags, using persisted registration.
	cl, err := NewClient(c2, &recordingRuntime{}, Options{})
	if err != nil {
		c2.Close()
		t.Fatal("NewClient from persisted registration failed:", err)
	}
	cl.Close()
	c2.Close()

	// Opening with a different private key wipes the old registration cleanly.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	c3, err := OpenDiskCache(f.path, otherKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if got, err := c3.Registration(); err != nil || got != nil {
		t.Fatalf("registration of another key kept: %+v, %v", got, err)
	}
}

func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
