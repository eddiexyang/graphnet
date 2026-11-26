package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/link"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

var memChannelID atomic.Uint64

// memChannel is one end of an in-memory, ordered and reliable Channel.
type memChannel struct {
	id   string
	in   chan []byte
	out  chan []byte
	done chan struct{}
	peer *memChannel
	once sync.Once
	sent atomic.Uint64
	// streamKinds counts sent stream hello and stream messages.
	streamKinds atomic.Uint64
}

func memChannelPair() (*memChannel, *memChannel) {
	a2b, b2a := make(chan []byte, 4096), make(chan []byte, 4096)
	id := fmt.Sprintf("mem-%d", memChannelID.Add(1))
	a := &memChannel{id: id, in: b2a, out: a2b, done: make(chan struct{})}
	b := &memChannel{id: id, in: a2b, out: b2a, done: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}
func (c *memChannel) ID() string { return c.id }
func (c *memChannel) Send(ctx context.Context, raw []byte) error {
	c.sent.Add(1)
	if len(raw) > 0 && (raw[0] == streamMessageKind || raw[0] == streamMessageKind-1) {
		c.streamKinds.Add(1)
	}
	select {
	case c.out <- append([]byte(nil), raw...):
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-c.peer.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// testHeaders rebuilds no packet header: these tests carry no IP messages.
type testHeaders struct{}

func (testHeaders) Rebuild([]byte, [16]byte, uint8, []byte) bool { return false }

// zeroHeaders rebuilds an all-zero packet header, as the punch tests send.
type zeroHeaders struct{}

func (zeroHeaders) Rebuild(header []byte, _ [16]byte, _ uint8, _ []byte) bool {
	clear(header)
	return true
}

// receiveEach adapts a per-frame receiver to Receive; frames are copies.
func receiveEach(receive func(context.Context, model.ID, []byte) error) Receive {
	return func(ctx context.Context, peer model.ID, owners []*packetbuf.Buffer) error {
		defer packetbuf.ReleaseAll(owners)
		for _, b := range owners {
			receive(ctx, peer, bytes.Clone(b.Data))
		}
		return nil
	}
}

func ownedBatch(raw []byte, err error) ([]*packetbuf.Buffer, error) {
	if err != nil {
		return nil, err
	}
	return []*packetbuf.Buffer{packetbuf.Wrap(raw)}, nil
}
func (c *memChannel) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	return ownedBatch(c.Receive(ctx))
}
func (c *memChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case raw := <-c.in:
		return raw, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-c.peer.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *memChannel) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *memChannel) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *memChannel) NeedsRekey() bool     { return false }
func (c *memChannel) Created() time.Time   { return time.Now() }

type muxPair struct {
	ctx      context.Context
	a, b     *mux
	accepted chan *muxStream
}

func newMuxPair(t testing.TB) *muxPair {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &muxPair{ctx: ctx, accepted: make(chan *muxStream, 64)}
	p.a = newMux(&group{ctx: ctx}, true, func(s *muxStream) { s.Abort() })
	p.b = newMux(&group{ctx: ctx}, false, func(s *muxStream) { p.accepted <- s })
	return p
}

var linkOptions = link.Options{Heartbeat: 20 * time.Millisecond, Timeout: 400 * time.Millisecond}

// connect creates one Link on each side. The acceptor (b) announces streams
// unless it does not support them.
func (p *muxPair) connect(t testing.TB, acceptorStreams bool) (*link.Link, *link.Link, *memChannel) {
	t.Helper()
	ca, cb := memChannelPair()
	info := func(peer int) link.Info {
		return link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(peer), CandidateID: ca.id, Transport: model.TCP}
	}
	oa, ob := linkOptions, linkOptions
	oa.Streams = p.a
	if acceptorStreams {
		ob.Streams, ob.StreamHello = p.b, true
	}
	la, err := link.New(p.ctx, ca, info(3), testHeaders{}, oa)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := link.New(p.ctx, cb, info(4), testHeaders{}, ob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { la.Close(); lb.Close() })
	return la, lb, ca
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *muxPair) accept(t *testing.T) *muxStream {
	t.Helper()
	select {
	case s := <-p.accepted:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not accepted")
		return nil
	}
}

func TestMuxStreamsShareOneLink(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	const count = 16
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := range count {
		s, err := p.a.Open(p.ctx)
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{byte(i)}, 300*1024+i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.Close()
			if _, err := s.Write(payload); err != nil {
				errs <- err
				return
			}
			s.CloseWrite()
			echo, err := io.ReadAll(s)
			if err == nil && !bytes.Equal(echo, payload) {
				err = errors.New("echo changed")
			}
			errs <- err
		}()
	}
	for range count {
		s := p.accept(t)
		go func() {
			defer s.Close()
			raw, err := io.ReadAll(s)
			if err == nil {
				s.Write(raw)
				s.CloseWrite()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "graceful stream cleanup", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return len(p.a.streams) == 0
	})
}

// Closing the Link in use moves streams to another Link; unacknowledged bytes
// are sent again and the receiver keeps each byte exactly once, in order.
func TestMuxStreamSurvivesLinkChange(t *testing.T) {
	p := newMuxPair(t)
	p.a.g.mesh = &Mesh{}
	first, _, _ := p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	p.connect(t, true)
	waitFor(t, "second link health", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		healthy := 0
		for l := range p.a.ready {
			if l.Healthy() {
				healthy++
			}
		}
		return healthy == 2
	})
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 48<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	want := sha256.Sum256(payload)
	writeErr := make(chan error, 1)
	go func() {
		_, err := s.Write(payload)
		if err == nil {
			err = s.CloseWrite()
		}
		writeErr <- err
	}()
	r := p.accept(t)
	half := make([]byte, 16<<20)
	if _, err := io.ReadFull(r, half); err != nil {
		t.Fatal(err)
	}
	first.Close()
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(append(half, rest...)); got != want {
		t.Fatalf("bytes changed across the Link change: got %d bytes", len(half)+len(rest))
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if p.a.g.mesh.Counters()["mux_resent_frames"] == 0 {
		t.Fatal("frames sent again after the Link change were not counted")
	}
}

// One stream whose reader stops must not hold up another on the same Link.
func TestMuxFlowControlIsolatesStreams(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	stalled, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	filled := make(chan error, 1)
	go func() {
		_, err := stalled.Write(make([]byte, muxWindow))
		filled <- err
	}()
	idle := p.accept(t) // never read
	if err := <-filled; err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	go func() {
		stalled.Write([]byte{1})
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("write beyond the receive window did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	other, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("other"), 200*1024)
	go func() {
		other.Write(payload)
		other.CloseWrite()
	}()
	r := p.accept(t)
	raw, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("second stream was held up", err)
	}
	// Reading the first stream reopens its window.
	if _, err := io.ReadFull(idle, make([]byte, muxWindow)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("window did not reopen")
	}
}

func TestMuxResetReachesPeer(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	s, err := p.a.Open(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello"))
	r := p.accept(t)
	if _, err := io.ReadFull(r, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	s.Abort()
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal("reset not delivered", err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("write after abort")
	}
}

// An acceptor without stream support never receives a stream frame, which
// would make it close the Link.
func TestMuxRequiresAcceptorSupport(t *testing.T) {
	p := newMuxPair(t)
	la, lb, channel := p.connect(t, false)
	waitFor(t, "link health", la.Healthy)
	time.Sleep(100 * time.Millisecond)
	if p.a.Available() {
		t.Fatal("streams offered without acceptor support")
	}
	if _, err := p.a.Open(p.ctx); err == nil {
		t.Fatal("stream opened without acceptor support")
	}
	if !la.Healthy() || !lb.Healthy() {
		t.Fatal("link closed")
	}
	if channel.streamKinds.Load() != 0 || channel.peer.streamKinds.Load() != 0 {
		t.Fatal("stream message sent without acceptor support")
	}
}

// Each ReadInto models one small access-stack read while the TCP connection
// remains open. It deliberately never fills the mux batch.
type sparseMuxReader struct {
	payload []byte
	reads   int
}

func (r *sparseMuxReader) Read([]byte) (int, error) { panic("ReadInto bypassed") }
func (r *sparseMuxReader) ReadInto(w io.Writer) (int, error) {
	if r.reads == 0 {
		return 0, io.EOF
	}
	r.reads--
	return w.Write(r.payload)
}

// A builder takes one pooled buffer per frame it fills, however much the read
// window allowed.
func TestMuxSparseBatchStorage(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	for _, size := range []int{1, 31, muxMaxData - 1, muxMaxData, muxMaxData + 7, 64 << 10, muxBurst * muxMaxData} {
		b := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData)
		payload := bytes.Repeat([]byte("x"), size)
		b.Write(payload)
		if err := s.publish(b); err != nil {
			t.Fatal(err)
		}
		if want := (size + muxMaxData - 1) / muxMaxData; len(b.frames) != want {
			t.Errorf("%d bytes took %d frames, want %d", size, len(b.frames), want)
		}
		var got []byte
		for _, f := range b.frames {
			if f.buf == nil || &f.raw[0] != &f.buf.Data[0] {
				t.Fatal("frame not in its pooled buffer")
			}
			got = append(got, f.raw[muxDataHeader:]...)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("payload changed")
		}
		p.a.receiveAck(s.id, s.sendNext, muxWindow, 0, false)
	}
}

func TestMuxSparseACKAndCredit(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	const reads = 72
	payload := bytes.Repeat([]byte("x"), 31)
	transfer := func(from, to *mux) int {
		var dst [128][]byte
		var owners [128]*packetbuf.Buffer
		n := from.PullStream(nil, dst[:], owners[:])
		for i, raw := range dst[:n] {
			if !to.ReceiveStream(nil, raw[1:], nil) {
				t.Fatal("invalid frame")
			}
			owners[i].Release()
		}
		return n
	}
	for cycle := range 8 {
		if n, err := s.ReadFrom(&sparseMuxReader{payload, reads}); err != nil || n != reads*int64(len(payload)) {
			t.Fatal(n, err)
		}
		if transfer(p.a, p.b) != reads {
			t.Fatal("missing frames")
		}
		if cycle == 0 {
			<-p.accepted
		}
		r := p.b.streams[s.id]
		// A Link change replays the compacted, unacknowledged frames. The
		// receiver must retain each byte once and acknowledge the same offset.
		p.a.switchLocked(nil)
		if transfer(p.a, p.b) != reads+1 {
			t.Fatal("Link change did not resend data and receive state")
		}
		if r.recvBytes != reads*len(payload) || r.received != uint64((cycle+1)*reads*len(payload)) {
			t.Fatal("Link change duplicated sparse messages")
		}
		before := s.peerLimit
		p.b.maintain()
		if transfer(p.b, p.a) != 1 || len(s.frames) != 0 {
			t.Fatal("small unread messages were not acknowledged")
		}
		if s.peerLimit != before {
			t.Fatal("unread bytes granted receive credit")
		}
		got := make([]byte, reads*len(payload))
		if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, bytes.Repeat(payload, reads)) {
			t.Fatal("payload changed", err)
		}
		p.b.maintain()
		if transfer(p.b, p.a) != 1 || s.peerLimit != before+uint64(len(got)) {
			t.Fatal("small reads did not reopen credit")
		}
		p.b.maintain()
		if transfer(p.b, p.a) != 0 {
			t.Fatal("idle stream emitted ACK")
		}
	}
}

func BenchmarkMuxBatchPublish(b *testing.B) {
	for _, size := range []int{31, 64 << 10, muxBurst * muxMaxData} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := newMux(&group{ctx: ctx}, true, nil)
			s := m.newStreamLocked(2, false)
			payload := bytes.Repeat([]byte("x"), size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				batch := newFrameBuilder(s.id, s.sendNext, muxBurst*muxMaxData)
				batch.Write(payload)
				if err := s.publish(batch); err != nil {
					b.Fatal(err)
				}
				m.receiveAck(s.id, s.sendNext, s.sendNext+muxWindow, 0, false)
			}
		})
	}
}

// Keep the receiver alive across sender restarts, as happens when only one
// production Agent is upgraded. Both live streams and tombstones survive.
func TestMuxRestartKeepsNewStreamsDistinct(t *testing.T) {
	for _, even := range []bool{false, true} {
		t.Run(fmt.Sprint(even), func(t *testing.T) {
			p := newMuxPair(t)
			p.b = newMux(&group{ctx: p.ctx}, !even, func(s *muxStream) { p.accepted <- s })
			seen := map[uint64]bool{}
			for restart := range 16 {
				fresh := newMux(&group{ctx: p.ctx}, even, nil)
				// Open only needs a selected Link. Frames are delivered below
				// synchronously so old receive state survives deterministically.
				fresh.current = &link.Link{}
				s, err := fresh.Open(p.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if s.id == 0 || (s.id%2 == 0) != even || seen[s.id] {
					t.Fatalf("restart %d reused or invalidated stream ID %d", restart, s.id)
				}
				seen[s.id] = true
				payload := fmt.Sprintf("request after restart %d", restart)
				if _, err := s.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				if !p.b.ReceiveStream(nil, s.frames[0].raw[1:], nil) || len(p.accepted) != 1 {
					t.Fatal("surviving peer rejected the new stream")
				}
				r := <-p.accepted
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(r, got); err != nil || string(got) != payload {
					t.Fatal("restart changed payload", err)
				}
				if restart%2 == 0 {
					r.Close()
				}
				fresh.close()
			}
		})
	}
}

func TestMuxStreamIDExhaustion(t *testing.T) {
	p := newMuxPair(t)
	p.a.current = &link.Link{}
	p.a.next = ^uint64(0) - 1
	s, err := p.a.Open(p.ctx)
	if err != nil || s.id != ^uint64(0)-1 {
		t.Fatal("last ID was not usable", err)
	}
	if _, err := p.a.Open(p.ctx); err == nil {
		t.Fatal("stream ID wrapped around")
	}
}

// A data frame's pooled buffer returns only after the stream, the session's
// keep and the sending Link have all let it go, in any order.
func TestMuxFrameBufferOwners(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	s.Begin(0)
	keep := streamproxy.NewKeep()
	s.SetRetention(keep)
	if _, err := s.Write(bytes.Repeat([]byte("x"), 3*muxMaxData)); err != nil {
		t.Fatal(err)
	}
	frames := append([]muxFrame(nil), s.frames...)
	var dst [16][]byte
	var owners [16]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	freed := func() int {
		count := 0
		for _, f := range frames {
			if f.buf.Data == nil {
				count++
			}
		}
		return count
	}
	p.a.receiveAck(s.id, s.sendNext, muxWindow, 0, false) // the stream lets go
	keep.Release(uint64(3 * muxMaxData))                  // delivered
	if freed() != 0 {
		t.Fatal("a buffer returned while the Link still sent it")
	}
	packetbuf.ReleaseAll(owners[:n])
	if freed() != len(frames) {
		t.Fatalf("%d of %d buffers returned", freed(), len(frames))
	}
}

// Frames built in reused pooled storage carry no stale header bytes.
func TestMuxFrameHeaderInReusedStorage(t *testing.T) {
	for range 64 {
		b := packetbuf.Get(muxDataHeader + muxMaxData)
		for i := range b.Data {
			b.Data[i] = 0xff
		}
		b.Release()
	}
	builder := newFrameBuilder(7, 100, 3)
	builder.Write([]byte("abc"))
	frame := builder.finish()[0]
	want := make([]byte, muxDataHeader)
	frameHeader(want, muxData, 7)
	binary.BigEndian.PutUint64(want[10:18], 100)
	if !bytes.Equal(frame.raw[:muxDataHeader], want) {
		t.Fatalf("header %x, want %x", frame.raw[:muxDataHeader], want)
	}
	builder.release()
}

// Received bytes stay in the Link's buffer, which returns once they are read.
func TestMuxReceiveKeepsLinkBuffer(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var dst [4][]byte
	var owners [4]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	packetbuf.ReleaseAll(owners[:n])
	received := packetbuf.Get(len(dst[0]) - 1)
	copy(received.Data, dst[0][1:])
	if !p.b.ReceiveStream(nil, received.Data, received) {
		t.Fatal("invalid frame")
	}
	received.Release() // the Link is done with it
	if received.Data == nil {
		t.Fatal("buffer returned while its bytes were unread")
	}
	r := <-p.accepted
	got := make([]byte, 5)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "hello" {
		t.Fatal(string(got), err)
	}
	if received.Data != nil {
		t.Fatal("buffer kept after its bytes were read")
	}
}

// A session's kept bytes go out on its next hop in the buffers that hold them,
// once no Link still sends their earlier frame, and arrive unchanged.
func TestMuxResendsKeptBuffers(t *testing.T) {
	p := newMuxPair(t)
	old := p.a.newStreamLocked(2, false)
	old.Begin(0)
	keep := streamproxy.NewKeep()
	old.SetRetention(keep)
	payload := bytes.Repeat([]byte("kept"), muxMaxData/4)
	if _, err := old.Write(payload); err != nil {
		t.Fatal(err)
	}
	original := old.frames[0]
	// A Link is still sending the old frame when the hop fails.
	var dst [4][]byte
	var owners [4]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	p.a.mu.Lock()
	old.failLocked(errStreamReset)
	p.a.mu.Unlock()

	next := p.a.newStreamLocked(4, false)
	next.Begin(0)
	chunks, ok := keep.From(0)
	if !ok || len(chunks) != 1 {
		t.Fatal("nothing kept")
	}
	sent := make(chan bool, 1)
	go func() {
		ok, err := next.WriteKept(chunks[0])
		if err != nil {
			t.Error(err)
		}
		sent <- ok
	}()
	select {
	case <-sent:
		t.Fatal("rewrote a header a Link was still sending")
	case <-time.After(50 * time.Millisecond):
	}
	packetbuf.ReleaseAll(owners[:n]) // the Link is done
	if !<-sent {
		t.Fatal("kept buffer not reused")
	}
	chunks[0].Owner.Release()
	frame := next.frames[0]
	if frame.buf != original.buf || &frame.raw[muxDataHeader] != &original.raw[muxDataHeader] {
		t.Fatal("kept bytes were copied")
	}
	if id := binary.BigEndian.Uint64(frame.raw[2:10]); id != next.id {
		t.Fatalf("frame for stream %d, want %d", id, next.id)
	}
	n = p.a.PullStream(nil, dst[:], owners[:])
	for i, raw := range dst[:n] {
		if !p.b.ReceiveStream(nil, raw[1:], nil) {
			t.Fatal("invalid frame")
		}
		owners[i].Release()
	}
	r := p.b.streams[next.id]
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("resent bytes changed", err)
	}
}

// A stream reads no further ahead of its Link than muxQueue: a writer waits
// while the Link writer has that much waiting, and continues once it pulls.
func TestMuxWritersWaitForTheLink(t *testing.T) {
	p := newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	wrote := make(chan int, 1)
	go func() {
		n, _ := s.Write(make([]byte, 3*muxQueue))
		wrote <- n
	}()
	waitFor(t, "the queue to fill", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return p.a.queued >= muxQueue
	})
	select {
	case n := <-wrote:
		t.Fatalf("wrote %d bytes past a full queue", n)
	case <-time.After(50 * time.Millisecond):
	}
	p.a.mu.Lock()
	if p.a.queued > muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("%d bytes queued, want about %d", p.a.queued, muxQueue)
	}
	p.a.mu.Unlock()
	var dst [128][]byte
	var owners [128]*packetbuf.Buffer
	done := time.After(10 * time.Second)
	for {
		select {
		case n := <-wrote:
			if n != 3*muxQueue {
				t.Fatalf("wrote %d", n)
			}
			p.a.mu.Lock()
			defer p.a.mu.Unlock()
			if p.a.queued != s.queued {
				t.Fatalf("Edge queues %d, its one stream %d", p.a.queued, s.queued)
			}
			return
		case <-done:
			t.Fatal("writer did not continue as the Link pulled")
		default:
		}
		n := p.a.PullStream(nil, dst[:], owners[:])
		packetbuf.ReleaseAll(owners[:n])
		p.a.mu.Lock()
		sent := s.sendNext
		p.a.mu.Unlock()
		p.a.receiveAck(s.id, sent, sent+muxWindow, 0, false)
		time.Sleep(time.Millisecond)
	}
}

// A stream that starts writing while another fills the queue, as a session
// sending again on a new chain does, is queued at once with its share.
func TestMuxLaterStreamIsNotQueuedBehindABacklog(t *testing.T) {
	p := newMuxPair(t)
	first := p.a.newStreamLocked(2, false)
	go first.Write(make([]byte, 3*muxQueue))
	waitFor(t, "the queue to fill", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return p.a.queued >= muxQueue
	})
	later := p.a.newStreamLocked(4, false)
	wrote := make(chan error, 1)
	go func() {
		_, err := later.Write(make([]byte, muxQueue/4))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a later stream waited behind another's backlog")
	}
	p.a.mu.Lock()
	defer p.a.mu.Unlock()
	if p.a.queued > 2*muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("%d bytes queued, want at most about %d", p.a.queued, 2*muxQueue)
	}
	if first.queued > muxQueue+muxBurst*(muxDataHeader+muxMaxData) {
		t.Errorf("the first stream queued %d bytes, want about %d", first.queued, muxQueue)
	}
}

// An Edge carries as many streams at once as there are connections; nothing
// bounds their number.
func TestMuxCarriesManyStreams(t *testing.T) {
	p := newMuxPair(t)
	p.connect(t, true)
	waitFor(t, "streams", p.a.Available)
	const count = 5000
	streams := make([]*muxStream, count)
	for i := range streams {
		s, err := p.a.Open(p.ctx)
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		streams[i] = s
	}
	go func() {
		for range count {
			var s *muxStream
			select {
			case s = <-p.accepted:
			case <-p.ctx.Done():
				return
			}
			go func() {
				defer s.Close()
				raw, err := io.ReadAll(s)
				if err == nil {
					s.Write(raw)
					s.CloseWrite()
				}
			}()
		}
	}()
	errs := make(chan error, count)
	for i, s := range streams {
		go func() {
			defer s.Close()
			payload := []byte(fmt.Sprintf("stream %d", i))
			if _, err := s.Write(payload); err != nil {
				errs <- err
				return
			}
			s.CloseWrite()
			echo, err := io.ReadAll(s)
			if err == nil && !bytes.Equal(echo, payload) {
				err = errors.New("echo changed")
			}
			errs <- err
		}()
	}
	for range count {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "graceful stream cleanup", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return len(p.a.streams) == 0
	})
}

// A relay forwards a received frame in the Link buffer it arrived in, under
// its own header, and opens its window by what it queued; forwarding
// allocates nothing.
func TestMuxRelayForwardsReceivedBuffers(t *testing.T) {
	p, q := newMuxPair(t), newMuxPair(t)
	s := p.a.newStreamLocked(2, false)
	payload := bytes.Repeat([]byte("relay"), 1000)
	if _, err := s.Write(payload); err != nil {
		t.Fatal(err)
	}
	var dst [4][]byte
	var owners [4]*packetbuf.Buffer
	n := p.a.PullStream(nil, dst[:], owners[:])
	// As a Link holds it: the message kind, then the frame.
	received := packetbuf.Get(len(dst[0]))
	copy(received.Data, dst[0])
	packetbuf.ReleaseAll(owners[:n])
	if !p.b.ReceiveStream(nil, received.Data[1:], received) {
		t.Fatal("invalid frame")
	}
	received.Release() // the Link is done with it
	up := <-p.accepted
	down := q.a.newStreamLocked(2, false)
	go up.RelayTo(down)
	t.Cleanup(up.Abort)
	waitFor(t, "the relay to queue the frame", func() bool {
		q.a.mu.Lock()
		defer q.a.mu.Unlock()
		return len(down.frames) == 1
	})
	q.a.mu.Lock()
	frame := down.frames[0]
	q.a.mu.Unlock()
	if frame.buf != received || &frame.raw[muxDataHeader] != &received.Data[muxDataHeader] {
		t.Fatal("the relay copied the frame")
	}
	if id, offset := binary.BigEndian.Uint64(frame.raw[2:10]), binary.BigEndian.Uint64(frame.raw[10:18]); id != down.id || offset != 0 || !bytes.Equal(frame.raw[muxDataHeader:], payload) {
		t.Fatalf("frame for stream %d at %d", id, offset)
	}
	waitFor(t, "the relay to read what it queued", func() bool {
		p.b.mu.Lock()
		defer p.b.mu.Unlock()
		return up.consumed == uint64(len(payload))
	})

	// The forwarded frame arrives unchanged.
	n = q.a.PullStream(nil, dst[:], owners[:])
	for i, raw := range dst[:n] {
		if !q.b.ReceiveStream(nil, raw[1:], nil) {
			t.Fatal("invalid frame")
		}
		owners[i].Release()
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(<-q.accepted, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("forwarded bytes changed", err)
	}

	next := q.a.newStreamLocked(4, false)
	next.writeMu.Lock()
	defer next.writeMu.Unlock()
	allocs := testing.AllocsPerRun(100, func() {
		buf := packetbuf.Get(muxDataHeader + 1000)
		if err := next.forward(buf.Data[muxDataHeader:], buf); err != nil {
			t.Fatal(err)
		}
		// The peer acknowledges it, and its buffer returns to the pool.
		q.a.mu.Lock()
		sent := next.sendNext
		q.a.mu.Unlock()
		q.a.receiveAck(next.id, sent, sent+muxWindow, 0, false)
	})
	if allocs != 0 {
		t.Fatalf("forwarding allocates %v times per frame", allocs)
	}
}

type mtuDropChannel struct {
	*memChannel
	maxSize int
}

func (c *mtuDropChannel) Send(ctx context.Context, raw []byte) error {
	if len(raw) >= c.maxSize {
		return nil
	}
	return c.memChannel.Send(ctx, raw)
}

func TestMuxRejectsLinkWithFailingSizeProbe(t *testing.T) {
	p := newMuxPair(t)
	ca, cb := memChannelPair()
	info := func(peer int) link.Info {
		return link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(peer), CandidateID: ca.id, Transport: model.TCP}
	}
	oa, ob := linkOptions, linkOptions
	oa.Streams, oa.SizeProbe, oa.Resume = p.a, true, true
	ob.Accepted, ob.Streams, ob.StreamHello, ob.SizeProbe, ob.SizeProbeHello, ob.Resume = true, p.b, true, true, true, true

	la, err := link.New(p.ctx, &mtuDropChannel{memChannel: ca, maxSize: 1500}, info(3), testHeaders{}, oa)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := link.New(p.ctx, &mtuDropChannel{memChannel: cb, maxSize: 1500}, info(4), testHeaders{}, ob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { la.Close(); lb.Close() })

	// streamHello and resumeHello arrive (both < 1500B), so la enters ready,
	// yet 2048B sizeProbe never completes so la must NEVER become mux.current.
	waitFor(t, "streamHello", func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return p.a.ready[la]
	})
	if !la.Resume() {
		t.Fatal("resumeHello did not precede streamHello")
	}
	for range 10 {
		p.a.maintain()
		p.b.maintain()
		if p.a.Available() || p.b.Available() {
			t.Fatal("link with failing 2048B size probe became mux.current")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestMuxResumableImmediatelyOnStreamsAvailable(t *testing.T) {
	p := newMuxPair(t)
	ca, cb := memChannelPair()
	info := func(peer int) link.Info {
		return link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(peer), CandidateID: ca.id, Transport: model.TCP}
	}
	oa, ob := linkOptions, linkOptions
	oa.Streams, oa.SizeProbe, oa.Resume = p.a, true, true
	ob.Accepted, ob.Streams, ob.StreamHello, ob.SizeProbe, ob.SizeProbeHello, ob.Resume = true, p.b, true, true, true, true

	la, err := link.New(p.ctx, ca, info(3), testHeaders{}, oa)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := link.New(p.ctx, cb, info(4), testHeaders{}, ob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { la.Close(); lb.Close() })

	for !p.a.Available() {
		time.Sleep(time.Millisecond)
	}
	if !p.a.Resumable() {
		t.Fatal("Available() became true before Resumable()")
	}
}

func TestTCPBackedIgnoresUnhealthyBackupWhenUDPActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	edgeA := link.NewCoordinatedEdge(testutil.ID(3), testutil.ID(4), "")
	edgeB := link.NewCoordinatedEdge(testutil.ID(4), testutil.ID(3), "")
	g := &group{ctx: ctx, edge: edgeA, links: map[string]*link.Link{}}
	g.mux = newMux(g, true, func(s *muxStream) { s.Abort() })

	// Bring up a healthy UDP link as active on the Edge.
	udpA, udpB := memChannelPair()
	uOpts := linkOptions
	luA, err := link.New(ctx, udpA, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(4), CandidateID: "udp", Transport: model.UDP}, testHeaders{}, uOpts)
	if err != nil {
		t.Fatal(err)
	}
	luB, err := link.New(ctx, udpB, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(3), CandidateID: "udp", Transport: model.UDP}, testHeaders{}, uOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer luA.Close()
	defer luB.Close()
	edgeA.Add(luA)
	edgeB.Add(luB)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-luA.Selections():
				edgeA.HandleSelection(luA, m)
			case m := <-luB.Selections():
				edgeB.HandleSelection(luB, m)
			}
		}
	}()
	waitFor(t, "udp healthy", func() bool { return luA.Healthy() && luB.Healthy() })
	edgeA.Tick()
	edgeB.Tick()
	waitFor(t, "udp active", func() bool { return edgeA.Active() == luA })

	// Add a TCP link whose 2048B size probe never completes.
	tcpA, tcpB := memChannelPair()
	tOptsA, tOptsB := linkOptions, linkOptions
	tOptsA.Streams, tOptsA.SizeProbe = g.mux, true
	tOptsB.Accepted, tOptsB.Streams, tOptsB.StreamHello, tOptsB.SizeProbe, tOptsB.SizeProbeHello = true, newMux(&group{ctx: ctx}, false, func(s *muxStream) { s.Abort() }), true, true, true
	ltA, err := link.New(ctx, &mtuDropChannel{memChannel: tcpA, maxSize: 1500}, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(4), CandidateID: "tcp", Transport: model.TCP}, testHeaders{}, tOptsA)
	if err != nil {
		t.Fatal(err)
	}
	ltB, err := link.New(ctx, &mtuDropChannel{memChannel: tcpB, maxSize: 1500}, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(3), CandidateID: "tcp", Transport: model.TCP}, testHeaders{}, tOptsB)
	if err != nil {
		t.Fatal(err)
	}
	defer ltA.Close()
	defer ltB.Close()
	g.links[ltA.ID()] = ltA
	edgeA.Add(ltA)

	if g.mux.Available() {
		t.Fatal("blackholed TCP link became mux.Available")
	}
	if g.tcpBacked() {
		t.Fatal("unhealthy backup TCP link marked Edge tcpBacked while healthy UDP link is active")
	}
}

type controllableChannel struct {
	*memChannel
	dropped  *atomic.Bool
	renewDue *atomic.Bool
}

func (c *controllableChannel) Send(ctx context.Context, raw []byte) error {
	if c.dropped != nil && c.dropped.Load() {
		return nil
	}
	return c.memChannel.Send(ctx, raw)
}

func (c *controllableChannel) RenewalDue(time.Duration) bool {
	return c.renewDue != nil && c.renewDue.Load()
}

type coordinatedMuxHarness struct {
	ctx       context.Context
	edgeA     *link.Edge
	edgeB     *link.Edge
	muxA      *mux
	muxB      *mux
	acceptedB chan *muxStream
}

func newCoordinatedMuxHarness(t *testing.T) *coordinatedMuxHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	edgeA := link.NewCoordinatedEdge(testutil.ID(3), testutil.ID(4), "")
	edgeB := link.NewCoordinatedEdge(testutil.ID(4), testutil.ID(3), "")
	gA := &group{ctx: ctx, edge: edgeA, links: map[string]*link.Link{}}
	gB := &group{ctx: ctx, edge: edgeB, links: map[string]*link.Link{}}
	acceptedB := make(chan *muxStream, 16)
	gA.mux = newMux(gA, true, func(s *muxStream) { s.Abort() })
	gB.mux = newMux(gB, false, func(s *muxStream) { acceptedB <- s })
	t.Cleanup(func() { gA.mux.close(); gB.mux.close() })
	return &coordinatedMuxHarness{
		ctx:       ctx,
		edgeA:     edgeA,
		edgeB:     edgeB,
		muxA:      gA.mux,
		muxB:      gB.mux,
		acceptedB: acceptedB,
	}
}

func (h *coordinatedMuxHarness) addStreamLink(t *testing.T, candidate string, transport model.Transport) (*link.Link, *link.Link, *controllableChannel, *controllableChannel) {
	t.Helper()
	caRaw, cbRaw := memChannelPair()
	dropped := &atomic.Bool{}
	renewDue := &atomic.Bool{}
	ca := &controllableChannel{memChannel: caRaw, dropped: dropped, renewDue: renewDue}
	cb := &controllableChannel{memChannel: cbRaw, dropped: dropped, renewDue: renewDue}
	oa, ob := linkOptions, linkOptions
	oa.Streams, oa.SizeProbe, oa.Resume = h.muxA, true, true
	ob.Accepted, ob.Streams, ob.StreamHello, ob.SizeProbe, ob.SizeProbeHello, ob.Resume = true, h.muxB, true, true, true, true
	la, err := link.New(h.ctx, ca, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(4), CandidateID: candidate, Transport: transport}, testHeaders{}, oa)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := link.New(h.ctx, cb, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(3), CandidateID: candidate, Transport: transport}, testHeaders{}, ob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { la.Close(); lb.Close() })
	h.edgeA.Add(la)
	h.edgeB.Add(lb)
	go func() {
		for {
			select {
			case <-h.ctx.Done():
				return
			case m := <-la.Selections():
				h.edgeA.HandleSelection(la, m)
			case m := <-lb.Selections():
				h.edgeB.HandleSelection(lb, m)
			}
		}
	}()
	return la, lb, ca, cb
}

func (h *coordinatedMuxHarness) tick() {
	h.edgeA.Tick()
	h.edgeB.Tick()
	h.muxA.maintain()
	h.muxB.maintain()
}

func muxCurrent(m *mux) *link.Link {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func TestMuxFollowsEdgeActiveFailoverAndPreferredSwitch(t *testing.T) {
	h := newCoordinatedMuxHarness(t)
	h.edgeA.SetPreferred("cand-a")
	h.edgeB.SetPreferred("cand-a")

	la1, lb1, ca1, _ := h.addStreamLink(t, "cand-a", model.WSS)
	la2, lb2, ca2, _ := h.addStreamLink(t, "cand-b", model.WSS)

	waitFor(t, "both links healthy and cand-a active", func() bool {
		h.tick()
		return la1.Healthy() && lb1.Healthy() && la2.Healthy() && lb2.Healthy() &&
			h.edgeA.Active() == la1 && h.edgeB.Active() == lb1 &&
			muxCurrent(h.muxA) == la1 && muxCurrent(h.muxB) == lb1
	})

	// Start a live stream and blackhole Active link A mid-transfer.
	sA, err := h.muxA.Open(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	part1 := bytes.Repeat([]byte("A"), 64<<10)
	part2 := bytes.Repeat([]byte("B"), 128<<10)
	if _, err := sA.Write(part1); err != nil {
		t.Fatal(err)
	}
	var sB *muxStream
	select {
	case sB = <-h.acceptedB:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for peer stream")
	}
	got1 := make([]byte, len(part1))
	if _, err := io.ReadFull(sB, got1); err != nil || !bytes.Equal(got1, part1) {
		t.Fatalf("part1 mismatch: err=%v", err)
	}

	// Blackhole A while sending part2: mux must fail over losslessly to B and
	// both ends must converge onto B.
	ca1.dropped.Store(true)
	writeDone := make(chan error, 1)
	go func() {
		_, err := sA.Write(part2)
		writeDone <- err
	}()
	stopTick := make(chan struct{})
	go func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stopTick:
				return
			case <-tk.C:
				h.tick()
			}
		}
	}()
	defer close(stopTick)

	got2 := make([]byte, len(part2))
	if _, err := io.ReadFull(sB, got2); err != nil || !bytes.Equal(got2, part2) {
		t.Fatalf("part2 failed across blackhole failover: err=%v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write failed across failover: %v", err)
	}
	waitFor(t, "edge and mux converge on cand-b", func() bool {
		return h.edgeA.Active() == la2 && h.edgeB.Active() == lb2 &&
			muxCurrent(h.muxA) == la2 && muxCurrent(h.muxB) == lb2
	})

	// Bring up fresh cand-c and switch PreferredCandidate to it: both edge and
	// mux must move off B onto C, and new traffic must flow on C (not Standby B).
	la3, lb3, ca3, _ := h.addStreamLink(t, "cand-c", model.WSS)
	waitFor(t, "cand-c healthy", func() bool { return la3.Healthy() && lb3.Healthy() })
	h.edgeA.SetPreferred("cand-c")
	h.edgeB.SetPreferred("cand-c")
	waitFor(t, "edge and mux switch to preferred cand-c", func() bool {
		return h.edgeA.Active() == la3 && h.edgeB.Active() == lb3 &&
			muxCurrent(h.muxA) == la3 && muxCurrent(h.muxB) == lb3
	})

	bBefore := ca2.streamKinds.Load()
	cBefore := ca3.streamKinds.Load()
	part3 := bytes.Repeat([]byte("C"), 64<<10)
	if _, err := sA.Write(part3); err != nil {
		t.Fatal(err)
	}
	got3 := make([]byte, len(part3))
	if _, err := io.ReadFull(sB, got3); err != nil || !bytes.Equal(got3, part3) {
		t.Fatalf("part3 failed after preferred switch: err=%v", err)
	}
	if ca3.streamKinds.Load() <= cBefore {
		t.Fatal("traffic did not flow on newly active preferred link C")
	}
	if ca2.streamKinds.Load() != bBefore {
		t.Fatalf("standby link B sent %d stream frames after switch to C", ca2.streamKinds.Load()-bBefore)
	}
}

func TestMuxRealignsAfterActiveTransientBlip(t *testing.T) {
	h := newCoordinatedMuxHarness(t)
	h.edgeA.SetPreferred("cand-a")
	h.edgeB.SetPreferred("cand-a")

	la1, lb1, ca1, _ := h.addStreamLink(t, "cand-a", model.WSS)
	la2, lb2, ca2, _ := h.addStreamLink(t, "cand-b", model.WSS)

	waitFor(t, "both healthy and cand-a active", func() bool {
		h.tick()
		return la1.Healthy() && lb1.Healthy() && la2.Healthy() && lb2.Healthy() &&
			h.edgeA.Active() == la1 && h.edgeB.Active() == lb1 &&
			muxCurrent(h.muxA) == la1 && muxCurrent(h.muxB) == lb1
	})

	// Simulate muxA drifting onto standby B (as happens after a transient blip
	// on A or a StreamsReady race) while edgeA.Active() remains A.
	h.muxA.mu.Lock()
	h.muxA.switchLocked(la2)
	h.muxA.mu.Unlock()
	if muxCurrent(h.muxA) != la2 {
		t.Fatal("expected muxA on standby B")
	}

	h.muxA.maintain()
	if muxCurrent(h.muxA) != la1 {
		t.Fatalf("muxA stayed on standby link instead of realigning to active link A")
	}

	// Verify subsequent stream bytes flow exclusively on active link A.
	aBefore := ca1.streamKinds.Load()
	bBefore := ca2.streamKinds.Load()
	sA, err := h.muxA.Open(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("R"), 32<<10)
	if _, err := sA.Write(payload); err != nil {
		t.Fatal(err)
	}
	var sB *muxStream
	select {
	case sB = <-h.acceptedB:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for peer stream")
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sB, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: err=%v", err)
	}
	if ca1.streamKinds.Load() <= aBefore {
		t.Fatal("realigned active link A carried no stream frames")
	}
	if ca2.streamKinds.Load() != bBefore {
		t.Fatalf("standby link B carried %d stream frames after realignment", ca2.streamKinds.Load()-bBefore)
	}
}

func TestMuxKeepsStreamLinkWhenUDPActive(t *testing.T) {
	h := newCoordinatedMuxHarness(t)
	h.edgeA.SetPreferred("cand-udp")
	h.edgeB.SetPreferred("cand-udp")

	udpA, udpB := memChannelPair()
	uOpts := linkOptions
	luA, err := link.New(h.ctx, udpA, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(4), CandidateID: "cand-udp", Transport: model.UDP}, testHeaders{}, uOpts)
	if err != nil {
		t.Fatal(err)
	}
	luB, err := link.New(h.ctx, udpB, link.Info{NetworkID: testutil.ID(1), EdgeID: testutil.ID(2), PeerID: testutil.ID(3), CandidateID: "cand-udp", Transport: model.UDP}, testHeaders{}, uOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { luA.Close(); luB.Close() })
	h.edgeA.Add(luA)
	h.edgeB.Add(luB)
	go func() {
		for {
			select {
			case <-h.ctx.Done():
				return
			case m := <-luA.Selections():
				h.edgeA.HandleSelection(luA, m)
			case m := <-luB.Selections():
				h.edgeB.HandleSelection(luB, m)
			}
		}
	}()

	ltA, ltB, _, _ := h.addStreamLink(t, "cand-tcp", model.TCP)
	waitFor(t, "udp active and tcp ready", func() bool {
		h.tick()
		return luA.Healthy() && luB.Healthy() && ltA.Healthy() && ltB.Healthy() &&
			h.edgeA.Active() == luA && h.edgeB.Active() == luB &&
			muxCurrent(h.muxA) == ltA && muxCurrent(h.muxB) == ltB
	})

	// Repeated maintain ticks must keep mux on the healthy TCP link while UDP is Active.
	for range 5 {
		h.tick()
		if muxCurrent(h.muxA) != ltA || muxCurrent(h.muxB) != ltB {
			t.Fatal("mux abandoned healthy stream link when UDP link was Active")
		}
	}
}

func TestMuxDoesNotPullBackToRenewingActive(t *testing.T) {
	h := newCoordinatedMuxHarness(t)
	h.edgeA.SetPreferred("cand-a")
	h.edgeB.SetPreferred("cand-a")

	la1, lb1, ca1, _ := h.addStreamLink(t, "cand-a", model.WSS)
	la2, lb2, _, _ := h.addStreamLink(t, "cand-b", model.WSS)

	waitFor(t, "cand-a active and both ready", func() bool {
		h.tick()
		return la1.Healthy() && lb1.Healthy() && la2.Healthy() && lb2.Healthy() &&
			h.edgeA.Active() == la1 && h.edgeB.Active() == lb1 &&
			muxCurrent(h.muxA) == la1 && muxCurrent(h.muxB) == lb1
	})

	// Mark active link A as RenewalDue: mux moves to fresh link B and must not
	// be pulled back onto expiring A while edgeA.Active() is still A.
	ca1.renewDue.Store(true)
	h.muxA.maintain()
	if muxCurrent(h.muxA) != la2 {
		t.Fatal("muxA did not move off renewing link A to fresh link B")
	}
	if h.edgeA.Active() != la1 {
		t.Fatal("expected edgeA.Active() to still be A before edge tick")
	}
	h.muxA.maintain()
	if muxCurrent(h.muxA) != la2 {
		t.Fatal("muxA pulled streams back onto renewing active link A")
	}
}
