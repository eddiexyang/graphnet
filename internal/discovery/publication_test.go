package discovery

import (
	"net"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
)

func TestObservedLeasePublication(t *testing.T) {
	start := time.Unix(1000, 0)
	prior := model.Endpoint{ID: "mapping", URL: "udp://192.0.2.1:24752", Transport: model.UDP, Source: model.Observed, ExpiresAt: start.Add(ObservedLifetime)}
	for _, seconds := range []int{20, 59, 60, 120, 140} {
		now := start.Add(time.Duration(seconds) * time.Second)
		fresh := prior
		fresh.ExpiresAt = now.Add(ObservedLifetime)
		out := CoalesceEndpoints([]model.Endpoint{prior}, []model.Endpoint{fresh}, now)
		want := fresh.ExpiresAt
		if seconds < 60 {
			want = prior.ExpiresAt
		}
		if out[0].ExpiresAt != want {
			t.Fatalf("incorrect lease at %ds", seconds)
		}
	}
	shortened := start.Add(time.Minute)
	if PublishedExpiry(prior.ExpiresAt, shortened, start) != shortened {
		t.Fatal("extended shortened observation")
	}
	if len(CoalesceEndpoints([]model.Endpoint{prior}, nil, start)) != 0 {
		t.Fatal("retained removed endpoint")
	}
}

func TestInterfaceEndpointsSkipsUnsafeIPv6ZoneNames(t *testing.T) {
	ifaces := []net.Interface{
		{Index: 1, Name: "eth0", Flags: net.FlagUp},
		{Index: 2, Name: "bad/if#1", Flags: net.FlagUp},
	}
	physical := map[int]bool{1: true, 2: true}
	_, ipnet6, _ := net.ParseCIDR("fe80::1/64")
	_, ipnet4, _ := net.ParseCIDR("192.0.2.5/24")
	eps, err := interfaceEndpoints([]byte("agent"), 24752, ifaces, physical, func(iface net.Interface) ([]net.Addr, error) {
		if iface.Index == 2 {
			return []net.Addr{ipnet6, ipnet4}, nil
		}
		return []net.Addr{ipnet6}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range eps {
		if err := ep.Validate(); err != nil {
			t.Fatalf("generated invalid endpoint %+v: %v", ep, err)
		}
	}
	// eth0 gets IPv6 link-local (2 endpoints: udp+tcp) and bad/if#1 gets IPv4 only (2 endpoints), skipping unsafe IPv6 zone.
	if len(eps) != 4 {
		t.Fatalf("expected 4 valid endpoints, got %d: %+v", len(eps), eps)
	}
}
