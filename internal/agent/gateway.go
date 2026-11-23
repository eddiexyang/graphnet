package agent

import (
	"net/netip"

	"github.com/eddiexyang/graphnet/internal/gateway"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
)

func gatewayEntries(state *runtimeState) []gateway.Entry {
	if state == nil {
		return nil
	}
	var entries []gateway.Entry
	for _, n := range state.snapshot.Networks {
		device := state.devices[n.ID]
		if device == nil || device.failure.Load() != nil {
			continue
		}
		for _, s := range n.Self.AdvertisedSubnets {
			entries = append(entries, gateway.Entry{Interface: device.Name(), Overlay: n.CIDR, Subnet: s.Prefix, Mode: s.GatewayMode})
		}
	}
	return entries
}

// matchedAdvertisedSubnet returns the longest-prefix AdvertisedSubnet on
// network's Self node that contains addr (excluding network's own overlay CIDR).
func matchedAdvertisedSubnet(state *runtimeState, network model.ID, addr netip.Addr) (model.AdvertisedSubnet, bool) {
	if state == nil || !addr.IsGlobalUnicast() {
		return model.AdvertisedSubnet{}, false
	}
	for _, n := range state.snapshot.Networks {
		if n.ID != network || n.CIDR.Contains(addr) {
			continue
		}
		bestBits := -1
		var best model.AdvertisedSubnet
		for _, s := range n.Self.AdvertisedSubnets {
			if s.Prefix.Contains(addr) && s.Prefix.Bits() > bestBits {
				bestBits = s.Prefix.Bits()
				best = s
			}
		}
		if bestBits >= 0 {
			return best, true
		}
		return model.AdvertisedSubnet{}, false
	}
	return model.AdvertisedSubnet{}, false
}

// explicitCrossNetwork reports whether network explicitly advertised a prefix
// at least as specific as targetNet's CIDR covering addr (so broad routes such
// as 0.0.0.0/0 never cross between networks, while an explicit advertisement
// of another network's CIDR or subnet does).
func explicitCrossNetwork(state *runtimeState, network, targetNet model.ID, addr netip.Addr) bool {
	if state == nil || network == targetNet {
		return false
	}
	best, ok := matchedAdvertisedSubnet(state, network, addr)
	if !ok || best.Prefix.Bits() == 0 {
		return false
	}
	for _, n := range state.snapshot.Networks {
		if n.ID == targetNet {
			return best.Prefix.Bits() >= n.CIDR.Bits() && n.CIDR.Contains(best.Prefix.Addr())
		}
	}
	return false
}

// snatDestination reports whether addr matches an advertised subnet of this
// Node whose longest matching prefix in network uses SNAT gateway mode.
func snatDestination(state *runtimeState, network model.ID, addr netip.Addr) bool {
	if state == nil || !addr.IsGlobalUnicast() {
		return false
	}
	device := state.devices[network]
	if device == nil || device.failure.Load() != nil {
		return false
	}
	best, ok := matchedAdvertisedSubnet(state, network, addr)
	return ok && best.GatewayMode == model.GatewaySNAT
}

// crossNetwork reports whether a packet delivered from network is addressed to
// another network this Agent belongs to without an explicit advertisement of
// that target network's prefix.
func crossNetwork(state *runtimeState, network model.ID, raw []byte) bool {
	info, err := packet.InspectAddresses(raw)
	if err != nil {
		return false
	}
	for _, n := range state.snapshot.Networks {
		if n.ID != network && n.CIDR.Contains(info.Destination) {
			return !explicitCrossNetwork(state, network, n.ID, info.Destination)
		}
	}
	return false
}

func allowedSNATLocalAddr(state *runtimeState, network model.ID, local, dst netip.Addr) bool {
	if state == nil || !local.IsValid() {
		return false
	}
	local = local.Unmap()
	if local.IsLoopback() {
		return false
	}
	for id, self := range state.selfAddress {
		if self != local {
			continue
		}
		if id == network {
			return false
		}
		if !explicitCrossNetwork(state, network, id, dst) {
			return false
		}
	}
	return true
}
