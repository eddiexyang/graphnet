package agent

import (
	"encoding/json"
	"testing"

)

// A snapshot cached by a version this one cannot read is skipped, not fatal:
// the Agent starts and takes the controller's next snapshot.
func TestUnreadableCachedSnapshotIsSkipped(t *testing.T) {
	cache, _, _ := registeredController(t)
	desired, _, err := cache.Snapshots()
	if err != nil || desired == nil {
		t.Fatal("no cached snapshot", err)
	}
	old := *desired
	old.Schema--
	raw, _ := json.Marshal(old)
	cache.mu.Lock()
	cache.desired = raw
	cache.mu.Unlock()
	if got, _, err := cache.Snapshots(); err != nil || got != nil {
		t.Fatalf("unreadable snapshot restored: %v %v", got, err)
	}
	if err := NewReconciler(cache, controllerTestRuntime{}).Restore(t.Context()); err != nil {
		t.Fatal("restore failed:", err)
	}
	next := desired.Clone()
	next.Revision++
	if err := cache.SaveDesired(next); err != nil {
		t.Fatal("the next snapshot was refused:", err)
	}
}
