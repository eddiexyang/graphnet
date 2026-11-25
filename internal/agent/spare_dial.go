package agent

import (
	"context"
	"net"
	"sync"
	"time"
)

// spareDial lifetime: a spare tunnel nobody takes is closed after this long.
const spareTunnelIdle = 10 * time.Second

// spareDialer prepares one more tunnel to the controller in the background
// when its transport first dials. net/http keeps WebSocket upgrades apart
// from other requests, so the control session's upgrade never reuses the
// connection its own challenge or the registration used; with a spare, it
// does not wait for another tunnel to be built.
type spareDialer struct {
	dial func(context.Context, string, string) (net.Conn, error)

	mu      sync.Mutex
	used    bool // the one spare was started
	pending chan struct{}
	conn    net.Conn
	err     error
	key     string
}

func newSpareDialer(dial func(context.Context, string, string) (net.Conn, error)) *spareDialer {
	return &spareDialer{dial: dial}
}

func (d *spareDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if conn := d.take(ctx, network+" "+address); conn != nil {
		return conn, nil
	}
	conn, err := d.dial(ctx, network, address)
	if err == nil {
		d.prepare(ctx, network, address)
	}
	return conn, err
}

// prepare starts the spare after the first successful dial. It keeps the
// dial's values, such as the socket hooks that resolve and mark its
// connections, but not its cancellation.
func (d *spareDialer) prepare(parent context.Context, network, address string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.used {
		return
	}
	d.used, d.key, d.pending = true, network+" "+address, make(chan struct{})
	pending := d.pending
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), spareTunnelIdle)
		defer cancel()
		conn, err := d.dial(ctx, network, address)
		d.mu.Lock()
		d.conn, d.err = conn, err
		d.mu.Unlock()
		close(pending)
		if conn != nil {
			time.AfterFunc(spareTunnelIdle, func() {
				d.mu.Lock()
				stale := d.conn == conn
				if stale {
					d.conn = nil
				}
				d.mu.Unlock()
				if stale {
					conn.Close()
				}
			})
		}
	}()
}

// take returns the spare for key, waiting for it while it is being dialed.
func (d *spareDialer) take(ctx context.Context, key string) net.Conn {
	d.mu.Lock()
	pending, match := d.pending, d.key == key
	d.mu.Unlock()
	if pending == nil || !match {
		return nil
	}
	select {
	case <-pending:
	case <-ctx.Done():
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conn := d.conn
	d.conn = nil
	return conn
}

// close drops an untaken spare.
func (d *spareDialer) close() {
	d.mu.Lock()
	conn := d.conn
	d.conn = nil
	d.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}
