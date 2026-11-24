package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/secure"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// Handshake initiation arrives from anyone who can reach the port.
func FuzzRespondHandshake(f *testing.F) {
	seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seedA[0], seedB[0] = 1, 2
	keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
	a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.UDP, Cipher: model.ChaCha20Poly1305, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey), Initiator: true}
	b := a
	b.Local, b.Peer, b.Identity, b.PeerIdentity, b.Initiator = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey), false
	initHS, _ := secure.NewHandshake(a)
	msg1, _, _ := initHS.Write()
	f.Add(msg1)
	f.Fuzz(func(t *testing.T, raw []byte) {
		secure.RespondHandshake(keyB, bytes.Clone(raw), nil, func(secure.ClientHello) (secure.Config, error) {
			return b, nil
		})
	})
}

// An established channel receives whatever its transport delivers, such as
// forged data messages. None may panic.
func FuzzChannelDecode(f *testing.F) {
	_, receiver := channelPair(f)
	f.Add(append([]byte{dataKind}, make([]byte, 30)...))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 {
			return
		}
		receiver.decode(context.Background(), bytes.Clone(raw))
	})
}

// channelPair returns two ends of an established TCP channel.
func channelPair(tb testing.TB) (*Channel, *Channel) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seedA, seedB := make([]byte, ed25519.SeedSize), make([]byte, ed25519.SeedSize)
	seedA[0], seedB[0] = 1, 2
	keyA, keyB := ed25519.NewKeyFromSeed(seedA), ed25519.NewKeyFromSeed(seedB)
	a := secure.Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.TCP, Cipher: model.ChaCha20Poly1305, Identity: keyA, PeerIdentity: keyB.Public().(ed25519.PublicKey)}
	b := a
	b.Local, b.Peer, b.Identity, b.PeerIdentity = a.Peer, a.Local, keyB, keyA.Public().(ed25519.PublicKey)
	x, y := net.Pipe()
	accepted := make(chan *Channel, 1)
	go func() {
		channel, _ := Accept(ctx, transport.NewStream(y), model.TCP, keyB, nil, func(secure.ClientHello) (secure.Config, error) { return b, nil })
		accepted <- channel
	}()
	sender, err := Dial(ctx, transport.NewStream(x), a)
	if err != nil {
		tb.Fatal(err)
	}
	receiver := <-accepted
	if receiver == nil {
		tb.Fatal("no channel")
	}
	tb.Cleanup(func() { sender.Close(); receiver.Close() })
	return sender, receiver
}
