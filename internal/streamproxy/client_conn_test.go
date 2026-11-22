package streamproxy

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestClientConnCloseResetsUnreadData(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	stream := &clientCloseTestStream{Conn: local, aborted: make(chan struct{}), finished: make(chan struct{}), unread: true}
	released := make(chan struct{})
	addr := netip.MustParseAddrPort("192.0.2.1:1024")
	conn := ClientConn(t.Context(), stream, addr, addr, func() { close(released) })
	defer conn.Close()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stream.aborted:
	default:
		t.Fatal("Close did not reset the stream")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("Close did not release the port")
	}
	select {
	case <-stream.finished:
		t.Fatal("Close sent a FIN for the reset")
	default:
	}
}

type clientCloseTestStream struct {
	net.Conn
	aborted, finished chan struct{}
	abort, finish     sync.Once
	unread            bool
}

func (c *clientCloseTestStream) HasUnread() bool { return c.unread }

func (c *clientCloseTestStream) Abort() {
	c.abort.Do(func() {
		close(c.aborted)
		c.Conn.Close()
	})
}

func (c *clientCloseTestStream) CloseWrite() error {
	c.finish.Do(func() { close(c.finished) })
	return nil
}
