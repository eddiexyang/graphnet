package streamproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type replacementResetHop struct {
	chunkHop
	finished chan bool
	done     chan struct{}
	writing  chan struct{}
	once     sync.Once
}

func (h *replacementResetHop) Done() <-chan struct{} { return h.done }

type receivedResetHop struct {
	*replacementResetHop
	reset bool
}

func (h *receivedResetHop) Aborted() bool { return h.reset }

func newReplacementResetHop() *replacementResetHop {
	return &replacementResetHop{finished: make(chan bool, 1), done: make(chan struct{})}
}

func (h *replacementResetHop) Abort()        { h.stop(false) }
func (h *replacementResetHop) AbortSession() { h.stop(true) }
func (h *replacementResetHop) stop(reset bool) {
	h.once.Do(func() {
		h.finished <- reset
		close(h.done)
	})
}

func (h *replacementResetHop) Write(p []byte) (int, error) {
	if h.writing == nil {
		return len(p), nil
	}
	close(h.writing)
	<-h.done
	return 0, net.ErrClosed
}

func TestAbortReachesReplacingHop(t *testing.T) {
	for _, duringReplay := range []bool{false, true} {
		name := "opening"
		if duringReplay {
			name = "replaying"
		}
		t.Run(name, func(t *testing.T) {
			first, replacement := newReplacementResetHop(), newReplacementResetHop()
			opening, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			if duringReplay {
				replacement.writing = make(chan struct{})
				unblock()
			}
			end, err := StartIngress(t.Context(), func(_ context.Context, gen uint32, _, _ uint64) (Hop, uint64, error) {
				if gen == 0 {
					return first, 0, nil
				}
				close(opening)
				<-release
				return replacement, 0, nil
			}, &Counters{})
			if err != nil {
				t.Fatal(err)
			}
			defer end.Abort()
			ready := opening
			if duringReplay {
				end.keep.Add([]byte("replay"), nil, 0)
				ready = replacement.writing
			}
			end.Reroute()
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("replacement did not enter", name)
			}
			end.Abort()
			unblock()
			select {
			case reset := <-replacement.finished:
				if !reset {
					t.Fatal("replacement received a hop abort, want session reset")
				}
			case <-time.After(time.Second):
				t.Fatal("replacement did not receive reset")
			}
		})
	}
}

func TestAbortReachesUnansweredOpening(t *testing.T) {
	first, opening := newReplacementResetHop(), newReplacementResetHop()
	waiting := make(chan struct{})
	end, err := StartIngress(t.Context(), func(ctx context.Context, gen uint32, _, _ uint64) (Hop, uint64, error) {
		if gen == 0 {
			return first, 0, nil
		}
		if !TrackOpeningHop(ctx, opening) {
			return nil, 0, net.ErrClosed
		}
		close(waiting)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}, &Counters{})
	if err != nil {
		t.Fatal(err)
	}
	defer end.Abort()
	end.Reroute()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("replacement did not reach its handshake")
	}
	end.Abort()
	select {
	case reset := <-opening.finished:
		if !reset {
			t.Fatal("opening received a hop abort, want session reset")
		}
	case <-time.After(time.Second):
		t.Fatal("opening did not receive reset")
	}
}

func TestEgressEndsOnResetWhileAnsweringReplacement(t *testing.T) {
	e := NewEgress(t.Context(), newReplacementResetHop(), func(uint32) {}, &Counters{})
	defer e.Abort()
	newHop := &receivedResetHop{replacementResetHop: newReplacementResetHop(), reset: true}
	err := e.Accept(newHop, 1, 0, 0, true, func(uint64) error { return io.ErrClosedPipe })
	if !errors.Is(err, ErrSessionReset) {
		t.Fatalf("accept error = %v", err)
	}
	select {
	case <-e.Done():
	default:
		t.Fatal("peer reset left the egress waiting for another chain")
	}
}

func TestWatchOpeningUpstreamForwardsTermination(t *testing.T) {
	for _, reset := range []bool{false, true} {
		up := &receivedResetHop{replacementResetHop: newReplacementResetHop(), reset: reset}
		down := newReplacementResetHop()
		stop := WatchOpeningUpstream(up, down)
		up.Abort()
		stop()
		select {
		case got := <-down.finished:
			if got != reset {
				t.Fatalf("forwarded terminal reset = %t, want %t", got, reset)
			}
		default:
			t.Fatal("relay did not terminate the opening hop")
		}
	}
}

type partialLeftoverHop struct {
	chunkHop
	keep     *Keep
	leftover []byte
	failAt   int
	written  []byte
}

func (h *partialLeftoverHop) SetRetention(k *Keep) { h.keep = k }
func (h *partialLeftoverHop) Leftover() []byte {
	out := h.leftover
	h.leftover = nil
	return out
}
func (h *partialLeftoverHop) ReadFrom(r io.Reader) (int64, error) {
	data, _ := io.ReadAll(r)
	if len(data) == 0 {
		return 0, nil
	}
	h.leftover = data
	return 0, io.ErrClosedPipe
}
func (h *partialLeftoverHop) Write(p []byte) (int, error) {
	if h.failAt > 0 && len(p) > h.failAt {
		part := p[:h.failAt]
		if h.keep != nil {
			h.keep.Add(part, nil, 0)
		}
		h.written = append(h.written, part...)
		return len(part), io.ErrClosedPipe
	}
	if h.keep != nil {
		h.keep.Add(p, nil, 0)
	}
	h.written = append(h.written, p...)
	return len(p), nil
}

func TestPartialLeftoverWriteDoesNotDuplicateBytesAndCanceledRebuildMonotonicGen(t *testing.T) {
	hop0 := &partialLeftoverHop{}
	hop1 := &partialLeftoverHop{failAt: 5}
	hop2 := &partialLeftoverHop{}
	var gens []uint32
	canceledOnce := false
	end, err := StartIngress(t.Context(), func(ctx context.Context, gen uint32, _, _ uint64) (Hop, uint64, error) {
		gens = append(gens, gen)
		switch gen {
		case 0:
			return hop0, 0, nil
		case 1:
			if !canceledOnce {
				canceledOnce = true
				return nil, 0, context.Canceled
			}
			t.Fatalf("reused canceled generation %d", gen)
			return nil, 0, context.Canceled
		case 2:
			return hop1, 0, nil
		default:
			return hop2, 0, nil
		}
	}, &Counters{})
	if err != nil {
		t.Fatal(err)
	}
	defer end.Abort()

	msg := []byte("0123456789abcdef")
	n, err := end.Write(msg)
	if err != nil || n != len(msg) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(msg))
	}
	if string(hop2.written) != string(msg) {
		t.Fatalf("hop2 received %q, want %q (gens=%v)", hop2.written, msg, gens)
	}

	egress := NewEgress(t.Context(), newReplacementResetHop(), func(uint32) {}, &Counters{})
	defer egress.Abort()
	if err := egress.Accept(newReplacementResetHop(), 2, 0, 0, true, func(uint64) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := egress.Accept(newReplacementResetHop(), 1, 0, 0, true, func(uint64) error { return nil }); !errors.Is(err, ErrStaleGen) {
		t.Fatalf("stale gen error = %v, want ErrStaleGen", err)
	}
}
