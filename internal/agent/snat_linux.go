//go:build linux

package agent

import (
	"net"
	"net/netip"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// checkSNATRoute ensures an SNAT gateway TCP dial respects network isolation:
//   - standard loopback (127.0.0.0/8, ::1) and same-network overlay routes are always blocked;
//   - host-local addresses on non-loopback, non-GraphNet-TUN interfaces (e.g. WAN public IP) are allowed;
//   - host-local unicast addresses bound on lo (e.g. an advertised /32) are allowed only when
//     explicitly advertised (prefix length > 0), never via 0.0.0.0/0;
//   - routes targeting another GraphNet network on this host are allowed only when that
//     network's CIDR (or a more specific subnet) is explicitly advertised.
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
	routes, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil || len(routes) == 0 {
		return forwarding.ErrDestination
	}
	best, matched := matchedAdvertisedSubnet(state, network, dst)
	for _, r := range routes {
		if r.Type == unix.RTN_LOCAL {
			if !allowLocalSNATDestination(state, network, dst, best, matched) {
				return forwarding.ErrDestination
			}
			continue
		}
		if r.Type != unix.RTN_UNICAST {
			return forwarding.ErrDestination
		}
		if len(r.Src) > 0 {
			if src, ok := netip.AddrFromSlice(r.Src); ok {
				if !allowedSNATLocalAddr(state, network, src, dst) {
					return forwarding.ErrDestination
				}
			}
		}
		if len(r.MultiPath) > 0 {
			for _, nh := range r.MultiPath {
				if !validSNATLink(state, network, nh.LinkIndex, dst) {
					return forwarding.ErrDestination
				}
			}
			continue
		}
		if !validSNATLink(state, network, r.LinkIndex, dst) {
			return forwarding.ErrDestination
		}
	}
	return nil
}

func allowLocalSNATDestination(state *runtimeState, network model.ID, dst netip.Addr, best model.AdvertisedSubnet, matched bool) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	found := false
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasDst := false
		for _, raw := range addrs {
			var ip netip.Addr
			switch a := raw.(type) {
			case *net.IPNet:
				ip, _ = netip.AddrFromSlice(a.IP)
			case *net.IPAddr:
				ip, _ = netip.AddrFromSlice(a.IP)
			}
			if ip.IsValid() && ip.Unmap() == dst {
				hasDst = true
				break
			}
		}
		if !hasDst {
			continue
		}
		found = true
		if owner, isTUN := ownedTUNNetwork(state, iface.Index); isTUN {
			if owner == network || !explicitCrossNetwork(state, network, owner, dst) {
				return false
			}
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			if !matched || best.Prefix.Bits() == 0 {
				return false
			}
			continue
		}
	}
	if !found {
		return matched && best.Prefix.Bits() > 0
	}
	return true
}

func validSNATLink(state *runtimeState, network model.ID, index int, dst netip.Addr) bool {
	if index <= 0 {
		return false
	}
	if owner, isTUN := ownedTUNNetwork(state, index); isTUN {
		return owner != network && explicitCrossNetwork(state, network, owner, dst)
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	return true
}

func ownedTUNNetwork(state *runtimeState, index int) (model.ID, bool) {
	for id, dev := range state.devices {
		if dev == nil {
			continue
		}
		if indexed, ok := dev.Device.(interface{ Index() int }); ok {
			if indexed.Index() == index {
				return id, true
			}
			continue
		}
		if iface, err := net.InterfaceByName(dev.Name()); err == nil && iface.Index == index {
			return id, true
		}
	}
	return "", false
}
