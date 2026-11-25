package client

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/tunnel"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstack stands in for a TUN interface. The embedding application's
// connections live in this user-space stack at the node's overlay address;
// its packets go to the data plane exactly as a TUN's would.
type netstack struct {
	config   tunnel.Config
	stack    *stack.Stack
	link     *netstackLink
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	portMu   sync.Mutex
	ports    map[uint16]struct{}
	nextPort uint16
	rawIP    atomic.Pointer[func([]byte) bool]
}

const netstackQueue = 1024

// gVisor reads checksum capabilities at NIC ingress. Serialize injection so
// only packets submitted by the local TCP offload path can skip verification.
type netstackLink struct {
	*channel.Endpoint
	mu       sync.Mutex
	verified atomic.Bool
}

func (l *netstackLink) Capabilities() stack.LinkEndpointCapabilities {
	caps := l.Endpoint.Capabilities()
	if l.verified.Load() {
		caps |= stack.CapabilityRXChecksumOffload
	}
	return caps
}

func (l *netstackLink) inject(protocol tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer, verified bool) {
	l.mu.Lock()
	l.verified.Store(verified)
	l.Endpoint.InjectInbound(protocol, packet)
	l.verified.Store(false)
	l.mu.Unlock()
}

func newNetstack(config tunnel.Config) (*netstack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	n := &netstack{config: config, ctx: ctx, cancel: cancel}
	n.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	n.link = &netstackLink{Endpoint: channel.New(netstackQueue, uint32(config.MTU), "")}
	n.link.SupportedGSOKind = stack.HostGSOSupported
	if err := n.stack.CreateNIC(1, n.link); err != nil {
		n.Close()
		return nil, errors.New(err.String())
	}
	address := config.Address.Addr()
	protocol := ipv4.ProtocolNumber
	if address.Is6() {
		protocol = ipv6.ProtocolNumber
	}
	if err := n.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(address.AsSlice()), PrefixLen: config.Address.Bits()}}, stack.AddressProperties{}); err != nil {
		n.Close()
		return nil, errors.New(err.String())
	}
	// Every destination goes to the data plane, which owns routing.
	n.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	return n, nil
}

func (n *netstack) Name() string                 { return "netstack" }
func (n *netstack) Configuration() tunnel.Config { return n.config }
func (n *netstack) address() netip.Addr          { return n.config.Address.Addr() }
func (n *netstack) protocol() tcpip.NetworkProtocolNumber {
	if n.address().Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

// A bound endpoint reserves a source port common to streams and packet TCP.
// Only the packet route connects the endpoint and starts a TCP handshake.
type boundTCP struct {
	tcpip.Endpoint
	queue    waiter.Queue
	port     uint16
	stackCtx context.Context
	release  func()
}

func (b *boundTCP) abortAndRelease() {
	b.Close()
	if b.release != nil {
		b.release()
	}
}

func (n *netstack) allocPort() (uint16, func(), error) {
	n.portMu.Lock()
	defer n.portMu.Unlock()
	const minPort, maxPort = 32768, 65535
	if n.ports == nil {
		n.ports = make(map[uint16]struct{})
		// Start anywhere in the range: a restarted node beginning at the same
		// port reuses the last run's tuples while far ends still hold them.
		n.nextPort = minPort + uint16(rand.IntN(maxPort-minPort+1))
	}
	for i := 0; i <= maxPort-minPort; i++ {
		p := n.nextPort
		if n.nextPort == maxPort {
			n.nextPort = minPort
		} else {
			n.nextPort++
		}
		if _, used := n.ports[p]; !used {
			n.ports[p] = struct{}{}
			return p, func() {
				n.portMu.Lock()
				delete(n.ports, p)
				n.portMu.Unlock()
			}, nil
		}
	}
	return 0, nil, errors.New("graphnet: no ephemeral source port available")
}

func (n *netstack) bindTCP(port uint16, release func()) (*boundTCP, error) {
	onceRelease := sync.OnceFunc(release)
	b := &boundTCP{port: port, stackCtx: n.ctx, release: onceRelease}
	endpoint, err := n.stack.NewEndpoint(tcp.ProtocolNumber, n.protocol(), &b.queue)
	if err != nil {
		onceRelease()
		return nil, errors.New(err.String())
	}
	b.Endpoint = endpoint
	if err := endpoint.Bind(fullAddress(netip.AddrPortFrom(n.address(), port))); err != nil {
		b.abortAndRelease()
		return nil, errors.New(err.String())
	}
	return b, nil
}

func (b *boundTCP) connect(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		b.abortAndRelease()
		return nil, err
	}
	entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
	b.queue.EventRegister(&entry)
	defer b.queue.EventUnregister(&entry)
	err := b.Connect(fullAddress(destination))
	if _, pending := err.(*tcpip.ErrConnectStarted); pending {
		select {
		case <-ctx.Done():
			b.abortAndRelease()
			return nil, ctx.Err()
		case <-ready:
			err = b.LastError()
		}
	}
	if err != nil {
		b.abortAndRelease()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: net.TCPAddrFromAddrPort(destination), Err: errors.New(err.String())}
	}
	conn := gonet.NewTCPConn(&b.queue, b.Endpoint)
	go func() {
		closeEntry, closed := waiter.NewChannelEntry(waiter.EventHUp)
		b.queue.EventRegister(&closeEntry)
		defer b.queue.EventUnregister(&closeEntry)
		for {
			state := tcp.EndpointState(b.Endpoint.State())
			if state == tcp.StateClose || state == tcp.StateTimeWait || state == tcp.StateError {
				b.release()
				return
			}
			select {
			case <-b.stackCtx.Done():
				b.release()
				return
			case <-closed:
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	return conn, nil
}

// Read returns the next packet the stack sends, for the data plane.
func (n *netstack) Read(p []byte) (int, error) {
	packet := n.link.ReadContext(n.ctx)
	if packet == nil {
		return 0, net.ErrClosed
	}
	defer packet.DecRef()
	return copyPacketViews(p, packet)
}

func copyPacketViews(dst []byte, packet *stack.PacketBuffer) (int, error) {
	if len(dst) < packet.Size() {
		return 0, io.ErrShortBuffer
	}
	views, offset := packet.AsViewList()
	var copied int
	for view := views.Front(); view != nil; view = view.Next() {
		chunk := view.AsSlice()
		if offset >= len(chunk) {
			offset -= len(chunk)
			continue
		}
		copied += copy(dst[copied:], chunk[offset:])
		offset = 0
	}
	return copied, nil
}

// ReadOwnedOffloadBatch hands the access stack the original TCP payload.
// The byte view is for admission and for routes that still forward IP packets.
func (n *netstack) ReadOwnedOffloadBatch(buffers [][]byte, sizes, segmentSizes []int, owners []*stack.PacketBuffer) (int, error) {
	packet := n.link.ReadContext(n.ctx)
	if packet == nil {
		return 0, net.ErrClosed
	}
	defer packet.DecRef()

	size, err := copyPacketViews(buffers[0], packet)
	if err != nil {
		return 0, err
	}
	sizes[0], segmentSizes[0], owners[0] = size, 0, nil

	gso := packet.GSOOptions
	if gso.Type == stack.GSOTCPv4 || gso.Type == stack.GSOTCPv6 {
		if gso.MSS > 0 && packet.Data().Size() > int(gso.MSS) {
			segmentSizes[0] = packet.HeaderSize() + int(gso.MSS)
		}
		inbound := packet.CloneToInbound()
		inbound.NetworkProtocolNumber = packet.NetworkProtocolNumber
		// The metadata comes from the local TCP stack, not the wire.
		inbound.RXChecksumValidated = gso.NeedsCsum
		owners[0] = inbound
	}
	return 1, nil
}

func (n *netstack) setRawIPHandler(fn func([]byte) bool) {
	if fn == nil {
		n.rawIP.Store(nil)
		return
	}
	n.rawIP.Store(&fn)
}

// Write delivers a packet from the data plane to the stack.
func (n *netstack) Write(p []byte) (int, error) {
	if n.ctx.Err() != nil {
		return 0, tunnel.ErrUnavailable
	}
	if len(p) == 0 {
		return 0, nil
	}
	if proto, ok := ipUpperProtocol(p); ok && proto != 6 && proto != 17 {
		if fn := n.rawIP.Load(); fn != nil && (*fn)(p) {
			return len(p), nil
		}
	}
	protocol := ipv4.ProtocolNumber
	if p[0]>>4 == 6 {
		protocol = ipv6.ProtocolNumber
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	n.link.inject(protocol, packet, false)
	packet.DecRef()
	return len(p), nil
}

// WriteTCPPacket delivers the local access stack's TCP output without
// flattening its packet buffer or splitting a coalesced segment.
func (n *netstack) WriteTCPPacket(packet *stack.PacketBuffer) error {
	if n.ctx.Err() != nil {
		return tunnel.ErrUnavailable
	}
	inbound := packet.CloneToInbound()
	defer inbound.DecRef()
	// Host GSO output carries a partial checksum in this in-process handoff.
	n.link.inject(packet.NetworkProtocolNumber, inbound, packet.GSOOptions.NeedsCsum)
	return nil
}

func (n *netstack) Close() error {
	n.once.Do(func() {
		n.cancel()
		n.link.Close()
		n.stack.Close()
	})
	return nil
}

func fullAddress(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}
}
