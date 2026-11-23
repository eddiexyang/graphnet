package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/resources"
)

// Runtime.Apply must either install the whole snapshot or return an error while
// retaining its previous working configuration. Report must be concurrency safe.
// Controller disconnection never invokes Apply or closes the runtime.
type Runtime interface {
	Apply(context.Context, model.Snapshot) error
	Report() []model.LinkStatus
}

type ApplyError struct{ Err error }

func (e *ApplyError) Error() string { return "apply configuration: " + e.Err.Error() }
func (e *ApplyError) Unwrap() error { return e.Err }

type Reconciler struct {
	cache       *Cache
	resources   *resources.Sampler
	runtime     Runtime
	applyMu     sync.Mutex
	mu          sync.Mutex
	applied     uint64
	running     bool
	configError string
	routingHash string
	// restored is the disk fallback snapshot running before any controller
	// snapshot was accepted. It came from an earlier controller generation,
	// so its revision is not reported or compared against the controller's.
	restored []byte
}

func NewReconciler(cache *Cache, runtime Runtime) *Reconciler {
	return &Reconciler{cache: cache, runtime: runtime, resources: resources.New()}
}
func (r *Reconciler) Report(version string) model.AgentReport {
	r.mu.Lock()
	report := model.AgentReport{Version: version, AppliedRevision: r.applied, ConfigError: r.configError, RoutingHash: r.routingHash, Capabilities: []string{model.CapabilityMultiExit}}
	if r.restored != nil {
		// A rebuilt controller may be behind the cached revision and rejects
		// reports ahead of it; report nothing applied until it confirms one.
		report.AppliedRevision, report.RoutingHash = 0, ""
	}
	r.mu.Unlock()
	report.Resources = r.resources.Sample()
	report.Links = r.runtime.Report()
	if ls, ok := r.runtime.(interface {
		LinkStateReport() *model.LinkStateReport
	}); ok {
		report.LinkState = ls.LinkStateReport()
	}
	if counters, ok := r.runtime.(interface{ Counters() map[string]uint64 }); ok {
		report.Counters = counters.Counters()
	}
	if health, ok := r.runtime.(interface{ Health() error }); ok {
		if err := health.Health(); err != nil {
			report.RuntimeError = err.Error()
			if len(report.RuntimeError) > 4096 {
				report.RuntimeError = report.RuntimeError[:4096]
			}
		}
	}
	return report
}
func (r *Reconciler) status(revision uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = revision
	r.routingHash = ""
	r.running = true
	r.configError = ""
	if err != nil {
		r.configError = err.Error()
		if len(r.configError) > 4096 {
			r.configError = r.configError[:4096]
		}
	}
}
func (r *Reconciler) failure(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configError = err.Error()
	if len(r.configError) > 4096 {
		r.configError = r.configError[:4096]
	}
}

// Restore starts the last durable desired configuration without contacting the
// controller. If it cannot be applied, the last successful snapshot is restored.
func (r *Reconciler) Restore(ctx context.Context) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	desired, applied, err := r.cache.Snapshots()
	if err != nil {
		return err
	}
	if desired == nil {
		return nil
	}
	if err = r.runtime.Apply(ctx, desired.Clone()); err == nil {
		if err := r.cache.MarkApplied(*desired); err != nil {
			return err
		}
		r.status(desired.Revision, nil)
		return r.restoreRoutes(desired.Revision)
	}
	failure := &ApplyError{Err: err}
	if applied != nil && applied.Revision != desired.Revision {
		if err := r.runtime.Apply(ctx, applied.Clone()); err != nil {
			return errors.Join(failure, fmt.Errorf("restore prior configuration: %w", err))
		}
		r.status(applied.Revision, failure)
		return r.restoreRoutes(applied.Revision)
	}
	r.failure(failure)
	return failure
}

// Accept provides the ordering boundary: validate -> persist -> apply -> ACK.
// The report never advances to a revision that failed runtime application.
func (r *Reconciler) Accept(ctx context.Context, snapshot model.Snapshot) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if err := r.cache.SaveDesired(snapshot); err != nil {
		r.failure(err)
		return err
	}
	r.mu.Lock()
	restored := r.restored
	alreadyApplied := r.running && r.applied == snapshot.Revision && r.configError == ""
	if restored != nil {
		// Equal revisions across controller generations need equal content.
		raw, _ := json.Marshal(snapshot)
		alreadyApplied = alreadyApplied && bytes.Equal(raw, restored)
	}
	r.mu.Unlock()
	if alreadyApplied && restored == nil {
		return nil
	}
	if !alreadyApplied {
		if err := r.runtime.Apply(ctx, snapshot.Clone()); err != nil {
			failure := &ApplyError{Err: err}
			r.failure(failure)
			return failure
		}
	}
	if err := r.cache.MarkApplied(snapshot); err != nil {
		r.failure(err)
		return err
	}
	r.status(snapshot.Revision, nil)
	r.mu.Lock()
	r.restored = nil
	r.mu.Unlock()
	r.cache.dropFallback()
	return nil
}

// Configured reports whether any configuration is running.
func (r *Reconciler) Configured() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// RestoreFallback applies the configuration a previous process left on disk,
// for an Agent that cannot reach the controller at startup. It runs at most
// once and never replaces a configuration that is already running. The newest
// snapshot is tried first; the last applied one is the fallback if it fails.
func (r *Reconciler) RestoreFallback(ctx context.Context) (revision uint64, err error) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if r.Configured() {
		return 0, nil
	}
	fb := r.cache.takeFallback()
	if fb == nil {
		return 0, nil
	}
	candidates := []*model.Snapshot{fb.desired}
	if fb.applied != nil && (fb.desired == nil || fb.applied.Revision != fb.desired.Revision) {
		candidates = append(candidates, fb.applied)
	}
	var failures error
	for _, s := range candidates {
		if s == nil {
			continue
		}
		if err := r.runtime.Apply(ctx, s.Clone()); err != nil {
			failures = errors.Join(failures, &ApplyError{Err: fmt.Errorf("cached revision %d: %w", s.Revision, err)})
			continue
		}
		raw, _ := json.Marshal(s)
		r.status(s.Revision, failures)
		r.mu.Lock()
		r.restored = raw
		r.mu.Unlock()
		if s == fb.desired && (fb.applied == nil || fb.applied.Revision != s.Revision) {
			r.cache.persistApplied(fb.agentID, *s)
		}
		if fb.routes != nil && fb.routes.Revision == s.Revision {
			if err := r.applyRoutes(*fb.routes); err != nil {
				failures = errors.Join(failures, fmt.Errorf("cached live routes: %w", err))
			}
		}
		return s.Revision, failures
	}
	if failures != nil {
		r.failure(failures)
	}
	return 0, failures
}
