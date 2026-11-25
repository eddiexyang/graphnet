// Package sockets carries per-instance socket hooks through contexts. A host
// application that embeds GraphNet can apply its own socket options and DNS to
// GraphNet's sockets, preventing underlay connections from looping back into a
// host-managed tunnel interface.
//
// Hooks travel in the context because every dial, listen and lookup already
// derives from the context the embedding host starts GraphNet with. Without
// hooks, behavior is unchanged.
package sockets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

// Hooks are applied to every socket GraphNet creates and every name it resolves.
type Hooks struct {
	// Control runs after GraphNet's own socket options, before bind/connect.
	Control func(network, address string, c syscall.RawConn) error
	// Lookup resolves host for network "ip", "ip4" or "ip6".
	Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type hooksKey struct{}

// With returns a context whose sockets and lookups use hooks.
func With(ctx context.Context, hooks Hooks) context.Context {
	return context.WithValue(ctx, hooksKey{}, hooks)
}

// From returns the hooks of ctx, or none.
func From(ctx context.Context) Hooks {
	hooks, _ := ctx.Value(hooksKey{}).(Hooks)
	return hooks
}

// Control chains own, GraphNet's socket options, with the hook of ctx.
func Control(ctx context.Context, own func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	hook := From(ctx).Control
	if hook == nil {
		return own
	}
	return func(network, address string, c syscall.RawConn) error {
		if own != nil {
			if err := own(network, address, c); err != nil {
				return err
			}
		}
		return hook(network, address, c)
	}
}

// LookupNetIP resolves host with the hook of ctx, or the default resolver.
func LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if lookup := From(ctx).Lookup; lookup != nil {
		return lookup(ctx, network, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// NetworkDial connects to a TCP address through a network GraphNet runs,
// instead of a host socket.
type NetworkDial func(ctx context.Context, address netip.AddrPort) (net.Conn, error)

type networkKey struct{}

// WithNetwork returns a context whose TCP dials go through dial. Only the
// dials made with this context use it; the hooks of ctx still resolve names.
func WithNetwork(ctx context.Context, dial NetworkDial) context.Context {
	return context.WithValue(ctx, networkKey{}, dial)
}

// Dial connects with dialer's options plus the hooks of ctx. With a Lookup
// hook, a host name is resolved by it and each address is tried in turn.
// A context from WithNetwork dials each address through that network.
func Dial(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	if through, _ := ctx.Value(networkKey{}).(NetworkDial); through != nil {
		return dialNetwork(ctx, dialer, network, address, through)
	}
	hooks := From(ctx)
	if hooks.Control == nil && hooks.Lookup == nil {
		return dialer.DialContext(ctx, network, address)
	}
	d := *dialer
	d.Control = Control(ctx, dialer.Control)
	host, port, err := net.SplitHostPort(address)
	if err != nil || hooks.Lookup == nil {
		return d.DialContext(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.DialContext(ctx, network, address)
	}
	family := "ip"
	switch network {
	case "tcp4", "udp4":
		family = "ip4"
	case "tcp6", "udp6":
		family = "ip6"
	}
	addresses, err := hooks.Lookup(ctx, family, host)
	if err != nil {
		return nil, err
	}
	var errs error
	for _, a := range addresses {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		errs = errors.Join(errs, err)
	}
	if errs == nil {
		errs = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	return nil, errs
}

// dialNetwork resolves address as Dial does and dials each address through
// the network, each within dialer's timeout.
func dialNetwork(ctx context.Context, dialer *net.Dialer, network, address string, through NetworkDial) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("dial %s %s through the network: only TCP is supported", network, address)
	}
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("dial %s: invalid port %q", address, rawPort)
	}
	family := "ip"
	switch network {
	case "tcp4":
		family = "ip4"
	case "tcp6":
		family = "ip6"
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else if addresses, err = LookupNetIP(ctx, family, host); err != nil {
		return nil, err
	}
	var errs error
	for _, a := range addresses {
		attempt, cancel := ctx, context.CancelFunc(func() {})
		if dialer.Timeout > 0 {
			attempt, cancel = context.WithTimeout(ctx, dialer.Timeout)
		}
		conn, err := through(attempt, netip.AddrPortFrom(a.Unmap(), uint16(port)))
		cancel()
		if err == nil {
			return conn, nil
		}
		errs = errors.Join(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if errs == nil {
		errs = &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	return nil, errs
}
