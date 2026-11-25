// Package client embeds a GraphNet client node in another application. The
// application hands it connections to IP destinations; the client sends them
// into the GraphNet network, which routes them.
//
// A client node is a full Agent on the network side: it connects to the
// controller, discovers and reports its endpoints, and reaches its peers with
// every transport, including NAT hole punching. It differs from an Agent only
// in what the embedding application does not need: it has no TUN interface
// (packet connections use a user-space stack), manages no host routes or gateway
// rules, accepts no inbound connections, and never carries other nodes'
// traffic. The controller marks its node as a client.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/eddiexyang/graphnet/internal/agent"
	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/sockets"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"github.com/eddiexyang/graphnet/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Config struct {
	// Server is the controller's HTTPS origin.
	Server string
	// ServerTransport is the controller carrier: tcp (default), websocket,
	// grpc, wss, or https for a TLS-terminating gateway.
	ServerTransport string
	// CA is the controller CA in PEM. Empty trusts the system roots.
	CA []byte
	// GatewayCA is the optional PEM CA for an HTTPS/WSS gateway entrance.
	// Empty trusts the system roots (plus CA when set).
	GatewayCA []byte
	// PrivateKey is the node identity. The controller knows its public key,
	// registered by an operator or by enrollment.
	PrivateKey ed25519.PrivateKey
	// Control is applied to every socket the client opens, after its own
	// options; Lookup resolves every name it dials. The embedding application
	// passes the options of its own outbound connections here, so the
	// client's sockets do not loop back into the application.
	Control func(network, address string, c syscall.RawConn) error
	Lookup  func(ctx context.Context, network, host string) ([]netip.Addr, error)
	Logger  *slog.Logger
	// QUICStreamReceiveWindow caps a QUIC Link per-stream receive window. Zero defaults to 32 MiB.
	QUICStreamReceiveWindow uint64
	// QUICConnectionReceiveWindow caps a QUIC Link connection receive window. Zero defaults to 48 MiB.
	QUICConnectionReceiveWindow uint64
	// StreamReceiveWindow caps the mux stream receive window when a Link does not
	// expose a kernel socket receive buffer (such as QUIC). Zero defaults to 32 MiB.
	StreamReceiveWindow uint64
	// WebSocketRoots overrides the CA roots trusted when dialing WSS peer endpoints
	// (nil trusts system roots for public CDNs plus direct peer identity pins).
	WebSocketRoots *x509.CertPool
	// PreferredTransport selects a preferred peer data-plane transport (for
	// example "quic" or "tcp") when allowed by the Edge, falling back to other
	// allowed transports automatically if unreachable.
	PreferredTransport string
	// StateFile, when set, keeps the last controller configuration in this
	// file. It is applied only if no controller can be reached when the node
	// starts; registration still comes from the controller. Empty keeps no
	// state on disk. Requires PrivateKey. A file held by another running node
	// is skipped with a warning. State is keyed by a hash of PrivateKey,
	// Server, ServerTransport, CA and GatewayCA: state written under any other
	// value is not loaded, and is replaced once the controller accepts the
	// node's registration.
	StateFile string
}

func parseServerURL(raw, explicitTransport string) (origin, transport string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" {
		return "", "", errors.New("graphnet: server must be a controller origin URL (https://, tcp://, ws://, wss://, or grpc://)")
	}
	var schemeTransport string
	switch strings.ToLower(u.Scheme) {
	case "https":
		schemeTransport = "https"
	case "tcp":
		schemeTransport = "tcp"
	case "ws", "websocket":
		schemeTransport = "websocket"
	case "wss":
		schemeTransport = "wss"
	case "grpc":
		schemeTransport = "grpc"
	default:
		return "", "", fmt.Errorf("graphnet: unsupported server scheme %q (use https, tcp, ws, wss, or grpc)", u.Scheme)
	}
	transport = strings.TrimSpace(explicitTransport)
	if transport == "" {
		transport = schemeTransport
	}
	u.Scheme = "https"
	u.Path = ""
	return u.String(), transport, nil
}

// ErrUnreachable means the network has no route to a destination.
var ErrUnreachable = errors.New("graphnet: destination is not reachable in the network")

type Client struct {
	ctx     context.Context
	cancel  context.CancelFunc
	cache   *agent.Cache
	runtime *agent.DataPlane
	control *agent.Client
	done    chan struct{}
	mu      sync.Mutex
	stacks  map[netip.Addr]*netstack
	rawIP   *rawIPRelay
}

// Start connects the client node. It returns once the node is running; the
// first configuration may still be on its way, which DialTCP waits for.
func Start(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("graphnet: invalid private key")
	}
	serverOrigin, serverTransport, err := parseServerURL(cfg.Server, cfg.ServerTransport)
	if err != nil {
		return nil, err
	}
	var prefTransport model.Transport
	if pref := strings.TrimSpace(cfg.PreferredTransport); pref != "" {
		prefTransport = model.Transport(strings.ToLower(pref))
		if !prefTransport.Valid() {
			return nil, fmt.Errorf("graphnet: unsupported preferred transport %q", cfg.PreferredTransport)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	var gatewayRoots *x509.CertPool
	if len(cfg.GatewayCA) > 0 {
		gatewayRoots = x509.NewCertPool()
		if !gatewayRoots.AppendCertsFromPEM(cfg.GatewayCA) {
			return nil, errors.New("graphnet: gateway CA contains no certificates")
		}
	} else if len(cfg.CA) > 0 {
		gatewayRoots, _ = x509.SystemCertPool()
		if gatewayRoots == nil {
			gatewayRoots = x509.NewCertPool()
		}
		gatewayRoots.AppendCertsFromPEM(cfg.CA)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(cfg.CA) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.CA) {
			return nil, errors.New("graphnet: CA contains no certificates")
		}
	}
	c := &Client{stacks: map[netip.Addr]*netstack{}, rawIP: newRawIPRelay(), done: make(chan struct{})}
	if cfg.StateFile != "" {
		// State is keyed by the whole configuration: a file written under any
		// other server, carrier, CA or key is a cache miss, never a fallback.
		hash := agent.ConfigHash(cfg.PrivateKey.Public().(ed25519.PublicKey), serverOrigin, serverTransport, cfg.CA, cfg.GatewayCA)
		c.cache, err = agent.OpenConfiguredDiskCache(cfg.StateFile, cfg.PrivateKey, hash, cfg.Logger)
		if errors.Is(err, agent.ErrCacheInUse) {
			// An embedding application may start a replacement node before it
			// closes the previous one; that node keeps the file, this one runs
			// without an offline fallback instead of failing.
			cfg.Logger.Warn("graphnet state file in use; running without disk state", "file", cfg.StateFile)
			c.cache, err = agent.NewMemoryCache(cfg.PrivateKey)
		}
	} else {
		c.cache, err = agent.NewMemoryCache(cfg.PrivateKey)
	}
	if err != nil {
		return nil, fmt.Errorf("graphnet: open state: %w", err)
	}
	c.ctx, c.cancel = context.WithCancel(sockets.With(context.WithoutCancel(ctx), sockets.Hooks{Control: cfg.Control, Lookup: cfg.Lookup}))
	var control *agent.Client
	c.runtime, err = agent.NewDataPlane(c.ctx, cfg.PrivateKey, agent.DataPlaneOptions{
		TunnelFactory: c.newStack,
		Embedded:                    true,
		QUICStreamReceiveWindow:     cfg.QUICStreamReceiveWindow,
		QUICConnectionReceiveWindow: cfg.QUICConnectionReceiveWindow,
		StreamReceiveWindow:         cfg.StreamReceiveWindow,
		WebSocketRoots:              cfg.WebSocketRoots,
		PreferredTransport:          prefTransport,
		Logger:        cfg.Logger,
		Endpoints: func(endpoints []model.Endpoint) error {
			if control == nil {
				return nil
			}
			return control.SetEndpoints(endpoints)
		},
	})
	if err != nil {
		c.cancel()
		c.cache.Close()
		return nil, err
	}
	control, err = agent.NewClient(c.cache, c.runtime, agent.Options{Server: serverOrigin, ServerTransport: serverTransport, Roots: roots, CA: cfg.CA, GatewayRoots: gatewayRoots, Version: "client", Logger: cfg.Logger, EagerFallback: true})
	if err != nil {
		c.runtime.Close()
		c.cancel()
		c.cache.Close()
		return nil, err
	}
	c.control = control
	go func() {
		defer close(c.done)
		// An Agent process exits on a registration error and its service
		// manager restarts it. Nothing restarts an embedded node, so retry
		// here: the controller may be briefly unreachable, or the key not yet
		// registered.
		delay := time.Second
		for {
			err := control.Run(c.ctx)
			if c.ctx.Err() != nil {
				return
			}
			cfg.Logger.Warn("graphnet client node restarting", "error", err, "retry_in", delay)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(2*delay, time.Minute)
		}
	}()
	return c, nil
}

func (c *Client) newStack(config tunnel.Config) (tunnel.Device, error) {
	n, err := newNetstack(config)
	if err != nil {
		return nil, err
	}
	n.setRawIPHandler(func(raw []byte) bool { return c.rawIP.deliver(config.Address.Addr(), raw) })
	c.mu.Lock()
	c.stacks[config.Address.Addr()] = n
	c.mu.Unlock()
	return &trackedStack{netstack: n, client: c}, nil
}

// trackedStack forgets its stack when the data plane closes it.
type trackedStack struct {
	*netstack
	client *Client
}

func (t *trackedStack) Close() error {
	t.client.mu.Lock()
	if t.client.stacks[t.address()] == t.netstack {
		delete(t.client.stacks, t.address())
	}
	t.client.mu.Unlock()
	return t.netstack.Close()
}

// route waits for the configuration that routes destination, and returns the
// stack of that Network.
func (c *Client) route(ctx context.Context, destination netip.Addr) (model.ID, *netstack, error) {
	delay := 10 * time.Millisecond
	for {
		// A route appears with a configuration or route change: wake on it
		// rather than at the next poll, which only covers changes it misses.
		changed := c.runtime.ForwardingChanged()
		network, local, err := c.runtime.NetworkFor(destination.Unmap())
		if err == nil {
			c.mu.Lock()
			n := c.stacks[local]
			c.mu.Unlock()
			if n != nil {
				return network, n, nil
			}
		} else if !errors.Is(err, agent.ErrNotConfigured) && !errors.Is(err, forwarding.ErrUnreachable) {
			// No node owns the destination: fail at once so the application
			// can choose another way. A missing route is waited for, as
			// routes converge after start and after Link changes.
			return "", nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, destination, err)
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
			return "", nil, fmt.Errorf("graphnet: waiting for a route to %s: %w", destination, err)
		case <-c.ctx.Done():
			return "", nil, net.ErrClosed
		case <-changed:
			continue
		case <-time.After(delay):
		}
		delay = min(2*delay, 250*time.Millisecond)
	}
}

// DialTCP connects to destination through the network.
func (c *Client) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	network, n, err := c.route(ctx, destination.Addr())
	if err != nil {
		return nil, err
	}
	if n.address().Is4() != destination.Addr().Is4() {
		return nil, fmt.Errorf("%w: %s is not in the network's address family", ErrUnreachable, destination)
	}
	port, releasePort, err := n.allocPort()
	if err != nil {
		return nil, err
	}
	source := netip.AddrPortFrom(n.address(), port)
	stream, err := c.runtime.OpenEmbeddedTCP(ctx, network, source, destination)
	if err != nil {
		releasePort()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, &net.OpError{Op: "connect", Net: "tcp", Source: net.TCPAddrFromAddrPort(source), Addr: net.TCPAddrFromAddrPort(destination), Err: err}
	}
	if stream == nil {
		endpoint, err := n.bindTCP(port, releasePort)
		if err != nil {
			return nil, err
		}
		return endpoint.connect(ctx, destination)
	}
	return streamproxy.ClientConn(c.ctx, stream, source, destination, releasePort), nil
}

// ListenUDP returns an unconnected UDP socket in the Network that routes
// destination. It can send to and receive from any address of that Network.
func (c *Client) ListenUDP(ctx context.Context, destination netip.Addr) (net.PacketConn, error) {
	destination = destination.Unmap()
	_, n, err := c.route(ctx, destination)
	if err != nil {
		return nil, err
	}
	if n.address().Is4() != destination.Is4() {
		return nil, fmt.Errorf("%w: %s is not in the network's address family", ErrUnreachable, destination)
	}
	conn, err := gonet.DialUDP(n.stack, nil, nil, n.protocol())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Close disconnects the node and releases its state.
func (c *Client) Close() error {
	c.cancel()
	<-c.done
	// Release the state file first, so a replacement node can open it while
	// this one is still tearing down its data plane.
	err := c.cache.Close()
	err = errors.Join(err, c.runtime.Close())
	c.control.Close()
	return err
}

