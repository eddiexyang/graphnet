//go:build !linux

package agent

import (
	"net/netip"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
)

func checkSNATRoute(state *runtimeState, network model.ID, dst netip.Addr) error {
	if state == nil || !dst.IsValid() || dst.Is4In6() || !dst.IsGlobalUnicast() {
		return forwarding.ErrDestination
	}
	for _, n := range state.snapshot.Networks {
		if n.CIDR.Contains(dst) {
			if n.ID == network || !explicitCrossNetwork(state, network, n.ID, dst) {
				return forwarding.ErrDestination
			}
		}
	}
	return nil
}
