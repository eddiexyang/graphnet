package agent

import (
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/routing"
)

// A new configuration wakes everything waiting on ForwardingChanged.
func TestForwardingChangedFiresOnApply(t *testing.T) {
	agents, _, state := graphAgents(t, model.UDP, streamOptions{}, 4, 4)
	changed := agents[0].ForwardingChanged()
	state.Revision++
	snapshot, err := routing.Compile(state, state.Agents[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agents[0].Apply(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("applying a configuration did not signal a forwarding change")
	}
}
