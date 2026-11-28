package mesh

import (
	"context"

	"github.com/eddiexyang/graphnet/internal/link"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
)

type StreamHandler func(context.Context, model.ID, model.ID, streamproxy.Conn)

// EnableStreams is called before this Mesh is published to the dataplane.
func (m *Mesh) EnableStreams(handler StreamHandler) {
	m.mu.Lock()
	m.streamHandler = handler
	m.mu.Unlock()
}

// DisableResume carries streams without TCP sessions, as Agents before them
// did. It is called before this Mesh is published to the dataplane.
func (m *Mesh) DisableResume() {
	m.mu.Lock()
	m.noResume = true
	m.mu.Unlock()
}

func (m *Mesh) resumeEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamHandler != nil && !m.noResume
}

func (m *Mesh) streamsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamHandler != nil
}

// Streams need ordered, reliable delivery from the Link's transport.
func streamTransport(t model.Transport) bool {
	return t == model.TCP || t == model.QUIC || t == model.WS || t == model.WSS
}

// StreamsAvailable reports whether the Edge to remote can carry a new stream.
func (m *Mesh) StreamsAvailable(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && (g.quicStreamLink() != nil || g.mux.Available())
}

// StreamCarrier reports whether the Edge to remote carries TCP as streams:
// its streams have a Link, or are moving between its TCP-backed Links, which
// never carry TCP as packets.
func (m *Mesh) StreamCarrier(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	return g != nil && (g.quicStreamLink() != nil || g.mux.Available() || g.tcpBacked())
}

// tcpBacked reports whether the Edge carries TCP as streams rather than packets.
func (g *group) tcpBacked() bool {
	if g.edge.ActiveTCPBacked() {
		return true
	}
	if g.edge.Active() != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range g.links {
		if l.TCPBacked() {
			return true
		}
	}
	return false
}

func (g *group) allowsStreamLink() bool {
	cfg := g.policy.Load()
	if cfg == nil {
		return false
	}
	for _, t := range cfg.peer.Edge.Transports {
		if !streamTransport(t) {
			continue
		}
		for _, ep := range cfg.peer.Endpoints {
			if ep.Transport == t {
				return true
			}
		}
		for _, ep := range cfg.endpoints {
			if ep.Transport == t {
				return true
			}
		}
	}
	return false
}

// PacketsOnly reports whether the Edge to remote has a selected Link that
// carries no streams, such as UDP: TCP crosses it only as packets.
func (m *Mesh) PacketsOnly(network, remote model.ID) bool {
	streamOn := m.streamsEnabled()
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	if streamOn && g.allowsStreamLink() {
		return false
	}
	return g.edge.Active() != nil && !g.mux.Available() && !g.tcpBacked()
}

// TCPCarrier reports whether the Edge to remote sends on a TCP, WS, WSS or
// gRPC Link, which carries TCP only as streams, never as packets.
func (m *Mesh) TCPCarrier(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	return g.edge.ActiveTCPBacked()
}

// ResumeAvailable reports whether a stream to remote can carry a resumable TCP
// session: both Agents support them.
func (m *Mesh) ResumeAvailable(network, remote model.ID) bool {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return false
	}
	if l := g.quicStreamLink(); l != nil {
		return l.Resume()
	}
	return g.mux.Resumable()
}

// OpenStream starts a stream on the Edge's current Link. It sends nothing until
// the caller writes, and never dials, handshakes or probes candidates.
func (m *Mesh) OpenStream(ctx context.Context, network, remote model.ID) (streamproxy.Conn, error) {
	m.mu.Lock()
	g := m.groups[key{network, remote}]
	m.mu.Unlock()
	if g == nil {
		return nil, link.ErrUnavailable
	}
	if l := g.quicStreamLink(); l != nil {
		return g.openQUICStream(ctx, l)
	}
	return g.mux.Open(ctx)
}

func (m *Mesh) acceptMuxStream(g *group, s *muxStream) {
	m.acceptConnStream(g, s)
}

func (m *Mesh) acceptConnStream(g *group, s streamproxy.Conn) {
	m.mu.Lock()
	handler := m.streamHandler
	if handler == nil || m.closed {
		m.mu.Unlock()
		if aborter, ok := s.(interface{ Abort() }); ok {
			aborter.Abort()
		} else {
			_ = s.Close()
		}
		return
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer s.Close()
		cfg := g.policy.Load()
		handler(g.ctx, cfg.network, cfg.peer.Node.ID, s)
	}()
}
