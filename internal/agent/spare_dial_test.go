package agent

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// The second dial to the same address takes the tunnel prepared after the
// first, without dialing again; an untaken spare closes with its dialer.
func TestSpareDialerHandsOutPreparedTunnel(t *testing.T) {
	var dials atomic.Int32
	var conns []net.Conn
	dial := func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		conns = append(conns, b)
		return a, nil
	}
	d := newSpareDialer(dial)
	first, err := d.DialContext(t.Context(), "tcp", "controller:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := d.DialContext(t.Context(), "tcp", "controller:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want the first and its spare", dials.Load())
	}
	// Only one spare per dialer: a third dial dials.
	third, _ := d.DialContext(t.Context(), "tcp", "controller:443")
	third.Close()
	if dials.Load() != 3 {
		t.Fatalf("dials = %d after a third dial, want 3", dials.Load())
	}

	unused := newSpareDialer(func(context.Context, string, string) (net.Conn, error) {
		a, _ := net.Pipe()
		return a, nil
	})
	c, _ := unused.DialContext(t.Context(), "tcp", "controller:443")
	c.Close()
	deadline := time.Now().Add(time.Second)
	for {
		unused.mu.Lock()
		ready := unused.conn
		unused.mu.Unlock()
		if ready != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spare not prepared")
		}
		time.Sleep(time.Millisecond)
	}
	spare := unused.conn
	unused.close()
	if _, err := spare.Write([]byte{0}); err == nil {
		t.Fatal("the untaken spare stayed open")
	}
}
