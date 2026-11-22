package streamproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ClientConn exposes a GraphNet stream directly as a net.Conn with zero
// intermediate goroutines or per-stream pipe buffers, preserving deadlines,
// half-close, and TCP RST semantics on close with unread data.
func ClientConn(parent context.Context, stream Conn, from, to netip.AddrPort, release func()) net.Conn {
	app := &clientConn{
		stream:  stream,
		local:   net.TCPAddrFromAddrPort(from),
		remote:  net.TCPAddrFromAddrPort(to),
		release: sync.OnceFunc(func() {
			if release != nil {
				release()
			}
		}),
	}
	if parent != nil {
		app.stopCancel = context.AfterFunc(parent, func() {
			app.abortStream()
		})
	}
	if end, ok := stream.(interface{ OnDone(func()) }); ok {
		end.OnDone(func() {
			if app.stopCancel != nil {
				app.stopCancel()
			}
			app.release()
		})
	}
	return app
}

type clientConn struct {
	stream     Conn
	local      net.Addr
	remote     net.Addr
	release    func()
	stopCancel func() bool
	closing    sync.Once
	eof        atomic.Bool
	inWrite    atomic.Int32
}

func (c *clientConn) hasUnread() bool {
	if u, ok := c.stream.(interface{ HasUnread() bool }); ok {
		return u.HasUnread()
	}
	if b, ok := c.stream.(interface{ Buffered() int }); ok {
		return b.Buffered() > 0
	}
	return false
}

func (c *clientConn) abortStream() {
	if s, ok := c.stream.(interface{ Abort() }); ok {
		s.Abort()
	} else {
		_ = c.stream.Close()
	}
	c.release()
}

func (c *clientConn) Read(b []byte) (int, error) {
	n, err := c.stream.Read(b)
	if err == io.EOF {
		c.eof.Store(true)
	}
	return n, err
}

func (c *clientConn) Write(b []byte) (int, error) {
	c.inWrite.Add(1)
	defer c.inWrite.Add(-1)
	return c.stream.Write(b)
}

func (c *clientConn) CloseWrite() error {
	return c.stream.CloseWrite()
}

func (c *clientConn) Close() error {
	c.closing.Do(func() {
		if c.stopCancel != nil {
			c.stopCancel()
		}
		if c.hasUnread() || c.inWrite.Load() > 0 {
			c.abortStream()
			return
		}
		_ = c.stream.CloseWrite()
		_ = c.stream.Close()
		if end, hasOnDone := c.stream.(interface{ OnDone(func()) }); !hasOnDone {
			c.release()
		} else if !c.eof.Load() {
			timer := time.AfterFunc(orphanLifetime, c.abortStream)
			end.OnDone(func() { timer.Stop() })
		}
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr  { return c.local }
func (c *clientConn) RemoteAddr() net.Addr { return c.remote }

func (c *clientConn) SetReadDeadline(t time.Time) error {
	if dl, ok := c.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		return dl.SetReadDeadline(t)
	}
	return nil
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	if dl, ok := c.stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return dl.SetWriteDeadline(t)
	}
	return nil
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
