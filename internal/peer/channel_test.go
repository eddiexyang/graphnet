package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/secure"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// The receiver exposes only the original single-message transport API.
type legacyChannelTransport struct{ transport.Conn }

func (l legacyChannelTransport) SetLocalPublicKey(pub ed25519.PublicKey) {
	if hp, ok := l.Conn.(interface{ SetLocalPublicKey(ed25519.PublicKey) }); ok {
		hp.SetLocalPublicKey(pub)
	}
}

func (l legacyChannelTransport) SetPeerPublicKey(pub ed25519.PublicKey) {
	if hp, ok := l.Conn.(interface{ SetPeerPublicKey(ed25519.PublicKey) }); ok {
		hp.SetPeerPublicKey(pub)
	}
}

type framedChannelTransport struct {
	*transport.Stream
	framed atomic.Int32
}

func (c *framedChannelTransport) SendFramedBatch(ctx context.Context, data []byte) error {
	c.framed.Add(1)
	return c.Stream.SendFramedBatch(ctx, data)
}

func (c *framedChannelTransport) SendFramedParts(ctx context.Context, parts [][]byte, frames int) error {
	c.framed.Add(1)
	return c.Stream.SendFramedParts(ctx, parts, frames)
}

type memPacketConn struct {
	in         <-chan []byte
	out        chan<- []byte
	done       chan struct{}
	once       sync.Once
	dropSend   atomic.Int32
	mu         sync.Mutex
	recorded   bytes.Buffer
	unreliable bool
}

func newMemPair(unreliable bool) (*memPacketConn, *memPacketConn) {
	ab := make(chan []byte, 32)
	ba := make(chan []byte, 32)
	a := &memPacketConn{in: ba, out: ab, done: make(chan struct{}), unreliable: unreliable}
	b := &memPacketConn{in: ab, out: ba, done: make(chan struct{}), unreliable: unreliable}
	return a, b
}

func (m *memPacketConn) Unreliable() bool     { return m.unreliable }
func (m *memPacketConn) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (m *memPacketConn) RemoteAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (m *memPacketConn) Close() error {
	m.once.Do(func() { close(m.done) })
	return nil
}

func (m *memPacketConn) Send(ctx context.Context, payload []byte) error {
	m.mu.Lock()
	m.recorded.Write(payload)
	m.mu.Unlock()
	if m.dropSend.Add(-1) >= 0 {
		return nil
	}
	cp := bytes.Clone(payload)
	select {
	case <-m.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case m.out <- cp:
		return nil
	}
}

func (m *memPacketConn) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-m.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-m.in:
		return msg, nil
	}
}

func TestHandshakeAllTransportsHideIDsAndKeys(t *testing.T) {
	for _, kind := range []model.Transport{model.UDP, model.TCP, model.QUIC, model.WS, model.WSS} {
		t.Run(string(kind), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
			seedA[0], seedB[0] = 11, 22
			keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
			pubA, pubB := keyA.Public().(ed25519.PublicKey), keyB.Public().(ed25519.PublicKey)
			a := secure.Config{Network: testutil.ID(10), Edge: testutil.ID(20), Local: testutil.ID(30), Peer: testutil.ID(40), Transport: kind, Cipher: model.ChaCha20Poly1305, Identity: keyA, PeerIdentity: pubB}
			b := a
			b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, pubA

			recA, recB := newMemPair(kind == model.UDP)
			defer recA.Close()
			defer recB.Close()
			if kind == model.UDP {
				// Drop the responder's first reply to exercise UDP 1-RTT retransmission.
				recB.dropSend.Store(1)
			}
			replay := &secure.ReplayFilter{}
			recvMsg := make(chan []byte, 1)
			acceptErr := make(chan error, 1)
			go func() {
				ch, err := Accept(ctx, recB, kind, keyB, replay, func(secure.ClientHello) (secure.Config, error) { return b, nil })
				if err != nil {
					acceptErr <- err
					return
				}
				defer ch.Close()
				got, err := ch.Receive(ctx)
				if err != nil {
					acceptErr <- err
					return
				}
				recvMsg <- got
			}()
			sender, err := Dial(ctx, recA, a)
			if err != nil {
				t.Fatalf("dial %s: %v", kind, err)
			}
			defer sender.Close()

			msg := []byte("secret overlay data")
			if err := sender.Send(ctx, msg); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-acceptErr:
				t.Fatalf("accept/receive %s: %v", kind, err)
			case got := <-recvMsg:
				if !bytes.Equal(got, msg) {
					t.Fatalf("receive %s: %q, want %q", kind, got, msg)
				}
			}

			recA.mu.Lock()
			wire := append([]byte(nil), recA.recorded.Bytes()...)
			recA.mu.Unlock()
			recB.mu.Lock()
			wire = append(wire, recB.recorded.Bytes()...)
			recB.mu.Unlock()

			pubAX, _ := secure.Ed25519PublicToX25519(pubA)
			pubBX, _ := secure.Ed25519PublicToX25519(pubB)
			for _, id := range []model.ID{a.Network, a.Edge, a.Local, a.Peer} {
				rawID, _ := hex.DecodeString(string(id))
				if bytes.Contains(wire, rawID) || bytes.Contains(wire, []byte(id)) {
					t.Fatalf("%s wire leaked ID %s", kind, id)
				}
			}
			for _, k := range [][]byte{pubA, pubB, pubAX[:], pubBX[:], msg} {
				if bytes.Contains(wire, k) {
					t.Fatalf("%s wire leaked key or plaintext", kind)
				}
			}
		})
	}
}

func TestPacketChannelBatchWithLegacyReceiver(t *testing.T) {
	for _, cipher := range []model.CipherSuite{model.AES128GCM, model.AES256GCM, model.ChaCha20Poly1305, model.XChaCha20Poly1305} {
		for _, contiguous := range []bool{false, true} {
			name := string(cipher) + "/legacy"
			if contiguous {
				name = string(cipher) + "/contiguous"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
				seedA[0], seedB[0] = 1, 2
				keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
				a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: cipher, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
				b := a
				b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
				x, y := net.Pipe()
				defer x.Close()
				defer y.Close()
				framed := &framedChannelTransport{Stream: transport.NewStream(x)}
				var outgoing transport.Conn = framed
				if !contiguous {
					outgoing = legacyChannelTransport{Conn: framed}
				}
				type result struct {
					channel *Channel
					err     error
				}
				accepted := make(chan result, 1)
				go func() {
					channel, err := Accept(ctx, legacyChannelTransport{Conn: transport.NewStream(y)}, model.TCP, keyB, nil, func(secure.ClientHello) (secure.Config, error) { return b, nil })
					accepted <- result{channel, err}
				}()
				sender, err := Dial(ctx, outgoing, a)
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				incoming := <-accepted
				if incoming.err != nil {
					t.Fatal(incoming.err)
				}
				defer incoming.channel.Close()
				framed.framed.Store(0)
				for _, count := range []int{1, 32, 128} {
					payloads := make([][]byte, count)
					originals := make([][]byte, count)
					for i := range payloads {
						size := 1337
						if i == 0 {
							size = 9 // Control messages share the packet channel.
						} else if i == count-1 {
							size = secure.MaxPlaintext
						}
						payloads[i] = bytes.Repeat([]byte{byte(i%0x7f + 1)}, size)
						originals[i] = bytes.Clone(payloads[i])
					}
					done := make(chan error, 1)
					go func() { done <- sender.SendBatch(ctx, payloads) }()
					for _, want := range originals {
						got, err := incoming.channel.Receive(ctx)
						if err != nil || !bytes.Equal(got, want) {
							t.Fatal("legacy receiver lost an independently authenticated message", len(got), err)
						}
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					for i, want := range originals {
						if !bytes.Equal(payloads[i], want) {
							t.Fatal("batch send changed caller-owned plaintext")
						}
					}
				}
				wantCalls := int32(0)
				if contiguous {
					wantCalls = 3
				}
				if framed.framed.Load() != wantCalls {
					t.Fatal("incorrect framed transport selection", framed.framed.Load())
				}
			})
		}
	}
}
