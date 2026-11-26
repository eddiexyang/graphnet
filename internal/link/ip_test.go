package link

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

// pipeChannel is one end of an in-memory Channel pair that records every
// message it sends.
type pipeChannel struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
	mu      sync.Mutex
	sent    [][]byte
}

func pipePair() (*pipeChannel, *pipeChannel) {
	ab, ba, done, once := make(chan []byte, 64), make(chan []byte, 64), make(chan struct{}), &sync.Once{}
	return &pipeChannel{in: ba, out: ab, done: done, once: once}, &pipeChannel{in: ab, out: ba, done: done, once: once}
}
func (c *pipeChannel) ID() string           { return "pipe" }
func (c *pipeChannel) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *pipeChannel) NeedsRekey() bool     { return false }
func (c *pipeChannel) Created() time.Time   { return time.Now() }
func (c *pipeChannel) Close() error         { c.once.Do(func() { close(c.done) }); return nil }
func (c *pipeChannel) Send(ctx context.Context, b []byte) error {
	b = bytes.Clone(b)
	c.mu.Lock()
	c.sent = append(c.sent, b)
	c.mu.Unlock()
	select {
	case c.out <- b:
		return nil
	case <-c.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *pipeChannel) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	b, err := c.Receive(ctx)
	if err != nil {
		return nil, err
	}
	return []*packetbuf.Buffer{packetbuf.Wrap(b)}, nil
}
func (c *pipeChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-c.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dataSent returns the data messages this end has sent, by kind.
func (c *pipeChannel) dataSent() (full, ip [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.sent {
		switch b[0] {
		case dataMessage:
			full = append(full, b)
		case ipMessage:
			ip = append(ip, b)
		}
	}
	return full, ip
}

const (
	testNetwork = model.ID("11111111111111111111111111111111")
	testSource  = model.ID("22222222222222222222222222222222")
	testDest    = model.ID("33333333333333333333333333333333")
)

// testHeaders rebuilds the fixed test addresses unless the payload is marked
// unroutable with a leading 0xff.
type testHeaders struct{}

func (testHeaders) Rebuild(header []byte, network [16]byte, hop uint8, payload []byte) bool {
	if payload[0] == 0xff {
		return false
	}
	frame, _ := (packet.Packet{Header: packet.Header{Network: testNetwork, Source: testSource, Destination: testDest, HopLimit: hop}, Payload: payload}).MarshalBinary()
	if [16]byte(frame[8:24]) != network {
		return false
	}
	copy(header, frame[:packet.HeaderSize])
	return true
}

func wire(id model.ID) (out [16]byte) {
	frame, _ := (packet.Packet{Header: packet.Header{Network: id, Source: id, Destination: id, HopLimit: 1}, Payload: []byte{0}}).MarshalBinary()
	return [16]byte(frame[8:24])
}

func testFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	frame, err := (packet.Packet{Header: packet.Header{Network: testNetwork, Source: testSource, Destination: testDest, HopLimit: 9, Epoch: 7, Flow: 5, Sequence: 3}, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func newTestLink(t *testing.T, channel Channel, options Options) *Link {
	t.Helper()
	info := Info{NetworkID: testNetwork, EdgeID: testSource, PeerID: testDest, CandidateID: "candidate", Transport: model.TCP}
	l, err := New(context.Background(), channel, info, testHeaders{}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func receiveFrame(t *testing.T, l *Link) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var owners [1]*packetbuf.Buffer
	if _, err := l.ReadOwnedBatch(ctx, owners[:]); err != nil {
		t.Fatalf("frame not delivered: %v", err)
	}
	defer owners[0].Release()
	return bytes.Clone(owners[0].Data)
}

// Rebuilt frames keep every routing field; Epoch, Flow and Sequence, which
// receivers ignore, are zero.
func wantRebuilt(sent []byte) []byte {
	want := bytes.Clone(sent)
	clear(want[56:packet.HeaderSize])
	return want
}

func TestIPFraming(t *testing.T) {
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := testFrame(t, payload)

	t.Run("both", func(t *testing.T) {
		dialerEnd, acceptorEnd := pipePair()
		dialer := newTestLink(t, dialerEnd, Options{})
		acceptor := newTestLink(t, acceptorEnd, Options{})
		if err := acceptor.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, dialer); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("dialer received %x", got)
		}
		if err := dialer.Send(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		if got := receiveFrame(t, acceptor); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("acceptor received %x", got)
		}
		for name, end := range map[string]*pipeChannel{"dialer": dialerEnd, "acceptor": acceptorEnd} {
			full, ip := end.dataSent()
			if len(full) != 0 || len(ip) != 1 || !bytes.Equal(ip[0], append([]byte{ipMessage, 9}, payload...)) {
				t.Fatalf("%s sent full=%x ip=%x", name, full, ip)
			}
		}
		if dialer.tx.Load() != uint64(len(frame)) || acceptor.rx.Load() != uint64(len(frame)) {
			t.Fatal("IP messages not counted as their full frame size")
		}
	})

	t.Run("unroutable", func(t *testing.T) {
		local, remote := pipePair()
		l := newTestLink(t, local, Options{})
		remote.Send(context.Background(), append([]byte{ipMessage, 9, 0xff}, payload...))
		remote.Send(context.Background(), append([]byte{ipMessage, 9}, payload...))
		if got := receiveFrame(t, l); !bytes.Equal(got, wantRebuilt(frame)) {
			t.Fatalf("received %x", got)
		}
		if l.dropped.Load() != 1 {
			t.Fatalf("dropped = %d", l.dropped.Load())
		}
	})

	// IP packets arrive only as IP messages; a data message carrying one
	// closes the Link.
	t.Run("full header IP", func(t *testing.T) {
		local, remote := pipePair()
		l := newTestLink(t, local, Options{})
		remote.Send(context.Background(), append([]byte{dataMessage}, frame...))
		select {
		case <-l.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("Link kept a data message carrying an IP packet")
		}
	})
}

// Owned frames from the router become IP messages in place, without a copy.
func TestIPOwnedFramesInPlace(t *testing.T) {
	l := &Link{ctx: context.Background(), info: Info{Transport: model.UDP}, dataReady: make(chan struct{}, 1)}
	l.dataGeneration.Store(1)
	payload := []byte{0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	frame := testFrame(t, payload)
	headroom := packetbuf.GetHeadroom(len(frame), 1)
	copy(headroom.Data, frame)
	plain := packetbuf.Wrap(bytes.Clone(frame))
	storage := []*byte{&headroom.Data[packet.HeaderSize], &plain.Data[packet.HeaderSize]}
	if err := l.SendOwnedBatch(context.Background(), []*packetbuf.Buffer{headroom, plain}); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{ipMessage, 9}, payload...)
	for i := range 2 {
		queued := l.takeData()
		if !bytes.Equal(queued.raw, want) || &queued.raw[2] != storage[i] {
			t.Fatalf("frame %d queued as %x", i, queued.raw)
		}
		queued.buffer.Release()
	}
	if l.dataBytes != 0 {
		t.Fatal("IP messages leaked byte budget")
	}
}

// A TCP-backed Link counts the TCP packets it is given, which access TCP
// termination must keep at zero; other packets and datagram Links are not
// counted.
func TestTCPBackedLinkRefusesTCPPackets(t *testing.T) {
	tcp := make([]byte, 20)
	tcp[0], tcp[9] = 0x45, 6
	udp := bytes.Clone(tcp)
	udp[9] = 17
	for transport, want := range map[model.Transport]uint64{model.TCP: 1, model.UDP: 0} {
		l := &Link{ctx: context.Background(), info: Info{Transport: transport}, dataReady: make(chan struct{}, 1)}
		l.dataGeneration.Store(1)
		err := l.SendBatch(context.Background(), [][]byte{testFrame(t, tcp), testFrame(t, udp)})
		if want == 1 && !errors.Is(err, ErrTCPOverTCP) || want == 0 && err != nil {
			t.Fatalf("%s Link: %v", transport, err)
		}
		if got := l.tcpPackets.Load(); got != want {
			t.Fatalf("%s Link refused %d TCP packets, want %d", transport, got, want)
		}
		if queued := uint64(l.dataCount); queued != 2-want {
			t.Fatalf("%s Link queued %d packets", transport, queued)
		}
	}
}
