package agent

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/eddiexyang/graphnet/internal/linkstate"
	"github.com/eddiexyang/graphnet/internal/model"
)

// Keep the installed live paths across discovery/configuration revisions. A new
// config must never briefly reinstate a static route through a known-down edge.
func carryLiveRoutes(snapshot model.Snapshot, previous *model.RouteUpdate) model.Snapshot {
	if previous == nil {
		return snapshot
	}
	next := snapshot.Clone()
	old := map[model.ID][]model.Route{}
	for _, n := range previous.Networks {
		old[n.ID] = n.Routes
	}
	for i := range next.Networks {
		n := &next.Networks[i]
		n.Routes = append([]model.Route{}, old[n.ID]...)
		// Topology edits may invalidate a retained route. Withdraw that network
		// until its new live table arrives instead of falling back to static paths.
		check := next
		check.Networks = []model.NetworkConfig{*n}
		if check.Validate(snapshot.AgentID) != nil {
			n.Routes = nil
		}
	}
	return next
}

func (r *DataPlane) ApplyRoutes(update model.RouteUpdate) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	return r.applyRoutesLocked(update)
}

func (r *DataPlane) applyRoutesLocked(update model.RouteUpdate) error {
	state := r.state.Load()
	if r.closed || state == nil {
		return errors.New("runtime unavailable for route update")
	}
	if update.Revision < state.snapshot.Revision {
		return linkstate.ErrSuperseded
	}
	next, err := update.Apply(state.snapshot)
	if err != nil {
		return err
	}
	if err = state.router.Configure(next); err != nil {
		return err
	}
	r.routesChanged()
	// Keep an owned copy for same-revision TUN repair; never recreate peer Links.
	owned := model.RouteUpdate{Revision: update.Revision, Networks: []model.NetworkRoutes{}}
	for _, n := range next.Networks {
		owned.Networks = append(owned.Networks, model.NetworkRoutes{ID: n.ID, Routes: n.Routes})
	}
	r.lastRoutes = &owned
	return nil
}

func (c *Cache) saveRoutes(update model.RouteUpdate) error {
	raw, err := json.Marshal(update)
	if err != nil {
		return err
	}
	if len(raw) > maxSnapshotBytes {
		return errors.New("route update too large")
	}
	c.mu.Lock()
	snapshot, err := c.snapshotFromLocked(c.applied)
	if err == nil && snapshot == nil {
		err = errors.New("missing applied configuration")
	}
	if err == nil {
		_, err = update.Apply(*snapshot)
	}
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.routes = raw
	id := c.reg.AgentID
	c.mu.Unlock()
	c.disk.put(id, keyRoutes, raw)
	return nil
}

func (r *Reconciler) restoreRoutes(revision uint64) error {
	r.cache.mu.Lock()
	raw := bytes.Clone(r.cache.routes)
	r.cache.mu.Unlock()
	if raw == nil {
		return nil
	}
	var update model.RouteUpdate
	if err := json.Unmarshal(raw, &update); err != nil {
		return err
	}
	if update.Revision == 0 || update.Revision != revision {
		return nil
	}
	return r.applyRoutes(update)
}

func (r *Reconciler) applyRoutes(update model.RouteUpdate) error {
	runtime, ok := r.runtime.(interface{ ApplyRoutes(model.RouteUpdate) error })
	if !ok {
		return errors.New("runtime does not support live routes")
	}
	if err := runtime.ApplyRoutes(update); err != nil {
		return err
	}
	r.mu.Lock()
	r.routingHash = update.Hash()
	r.mu.Unlock()
	return nil
}

func (r *Reconciler) AcceptRoutes(update model.RouteUpdate) error {
	if local, ok := r.runtime.(interface{ LocalRouting() bool }); ok && local.LocalRouting() {
		return nil // Routes converge from link-state advertisements instead.
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	// Routes for a restored disk snapshot wait for the controller's own snapshot.
	current := r.running && r.applied == update.Revision && r.restored == nil
	r.mu.Unlock()
	if !current {
		return nil
	} // A queued update cannot overwrite another configuration.
	if err := r.cache.saveRoutes(update); err != nil {
		return err
	}
	return r.applyRoutes(update)
}
