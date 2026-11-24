package mesh

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// connIngress receives already-classified connections from the main
// TCP listener. It has no independently bound port or unbounded accept queue.
type connIngress struct {
	address net.Addr
	pending chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func (l *connIngress) Addr() net.Addr { return l.address }
func (l *connIngress) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *connIngress) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn := <-l.pending:
		return conn, nil
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Release an admission slot exactly once. HTTP/1 holds a classifier slot until
// request headers finish or upgrade hijacks the socket.
type ingressConn struct {
	net.Conn
	raw     net.Conn
	release func()
}

func (c *ingressConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (c *bufferedConn) Read(raw []byte) (int, error) { return c.reader.Read(raw) }

func (c *bufferedConn) UseKernelWriteBacklog() error {
	return transport.UseKernelTCPBacklog(c.Conn)
}

// ReceiveWindow reports the kernel's receive buffer of the connection.
func (c *bufferedConn) ReceiveWindow() (int, bool) {
	return transport.TCPReceiveWindow(c.Conn)
}

// Only the read side has buffered admission bytes. Gather writes can use the
// underlying connection without flattening ciphertext or bypassing its writer.
func (c *bufferedConn) WriteBuffers(parts net.Buffers) (int64, error) {
	return parts.WriteTo(c.Conn)
}

func (m *Mesh) startHTTP() {
	m.webListener = &connIngress{address: m.listener.Addr(), pending: make(chan net.Conn), done: make(chan struct{})}
	m.webServer = &http.Server{
		Handler:           http.HandlerFunc(m.acceptWebSocket),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    8192,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if ic, ok := c.(*ingressConn); ok {
				if ic.raw != nil {
					ctx = context.WithValue(ctx, wsRawConnKey{}, ic.raw)
				}
				if tc, ok := ic.Conn.(*tls.Conn); ok {
					state := tc.ConnectionState()
					ctx = context.WithValue(ctx, wsTLSStateKey{}, &state)
				}
			}
			return ctx
		},
	}
	m.webServer.SetKeepAlivesEnabled(false)
	m.webServer.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateActive || state == http.StateClosed || state == http.StateHijacked {
			conn.(*ingressConn).release()
		}
	}
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.webServer.Serve(m.webListener) }()
}

func (m *Mesh) classify(conn net.Conn) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		conn.Close()
		return
	}
	select {
	case m.sniffSlots <- struct{}{}:
	default:
		m.mu.Unlock()
		conn.Close()
		return
	}
	m.pending[conn] = true
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		defer func() { m.mu.Lock(); delete(m.pending, conn); m.mu.Unlock() }()
		release := sync.OnceFunc(func() { <-m.sniffSlots })
		transferred := false
		defer func() {
			if !transferred {
				conn.Close()
				release()
			}
		}()
		ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReaderSize(conn, 4096)
		first, err := reader.Peek(1)
		if err != nil {
			return
		}
		var current net.Conn = &bufferedConn{Conn: conn, reader: reader}
		switch first[0] {
		case 0x16: // TLS 1.3 handshake record for WSS (optionally with mTLS origin pull).
			secured := tls.Server(current, m.wssTLS)
			if err := secured.HandshakeContext(ctx); err != nil {
				return
			}
			current = secured
			fallthrough
		case 'G': // HTTP/1.1 WebSocket upgrade (direct WS/WSS or reverse-proxied).
			conn.SetReadDeadline(time.Time{})
			if !stop() {
				return
			}
			select {
			case m.webListener.pending <- &ingressConn{Conn: current, raw: conn, release: release}:
				transferred = true
			case <-ctx.Done():
			case <-m.webListener.done:
			}
		default:
			preface, err := reader.Peek(transport.PunchPrefaceSize)
			if err != nil {
				return
			}
			if _, ok := transport.MatchPunchPreface(m.identity, preface, m.allowedTCPPunchPeers()); ok {
				session, err := transport.NewPunchMux(ctx, current, m.identity, m.tls, m.allowedTCPPunchPeers, true)
				if err != nil {
					return
				}
				if !stop() {
					session.Close()
					return
				}
				transferred = m.installPunch(session)
				if transferred {
					release()
				} else {
					session.Close()
				}
				return
			}
			conn.SetReadDeadline(time.Time{})
			if !stop() {
				return
			}
			transferred = true
			release()
			m.accept(transport.NewStream(current), model.TCP)
		}
	}()
}

func (m *Mesh) allowsEndpoint(kind model.Transport, path string) bool {
	allowed := false
	m.mu.Lock()
	if !m.closed {
		for _, g := range m.groups {
			for _, endpoint := range g.policy.Load().endpoints {
				if endpoint.Source != model.Manual || endpoint.Transport != kind {
					continue
				}
				parsed, _ := url.Parse(endpoint.URL)
				if transport.WebSocketPath(parsed) == path {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
	}
	m.mu.Unlock()
	return allowed
}
