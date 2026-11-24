package secure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/testutil"
	"golang.org/x/crypto/curve25519"
)

func configs(t testing.TB) (Config, Config) {
	t.Helper()
	apub, akey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bpub, bkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := Config{Network: testutil.ID(1), Edge: testutil.ID(2), Local: testutil.ID(3), Peer: testutil.ID(4), Transport: model.UDP, Cipher: model.ChaCha20Poly1305, Identity: akey, PeerIdentity: bpub, Initiator: true}
	b := a
	b.Local, b.Peer = a.Peer, a.Local
	b.Identity = bkey
	b.PeerIdentity = apub
	b.Initiator = false
	return a, b
}

func establish(t testing.TB, a, b Config) (*Session, *Session) {
	t.Helper()
	initiator, err := NewHandshake(a)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewHandshake(b)
	if err != nil {
		t.Fatal(err)
	}
	msg1, session, err := initiator.Write()
	if err != nil || session != nil {
		t.Fatal("first step", err)
	}
	if session, err := responder.Read(msg1); err != nil || session != nil {
		t.Fatal("first read", err)
	}
	msg2, bs, err := responder.Write()
	if err != nil || bs == nil {
		t.Fatal("second step", err)
	}
	as, err := initiator.Read(msg2)
	if err != nil || as == nil {
		t.Fatal("second read", err)
	}
	if as.ID() != bs.ID() {
		t.Fatal("session binding mismatch")
	}
	return as, bs
}

func TestEd25519ToX25519Consistency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privX, pubX, err := Ed25519PrivateToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := curve25519.X25519(privX[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, pubX[:]) {
		t.Fatal("X25519 basepoint scalar mult disagrees with Montgomery public key")
	}
	gotPubX, err := Ed25519PublicToX25519(pub)
	if err != nil || gotPubX != pubX {
		t.Fatal("public key conversion mismatch")
	}
}

func TestAuthenticatedSessions(t *testing.T) {
	for _, suite := range supportedTestCiphers {
		t.Run(string(suite), func(t *testing.T) { runTestAuthenticatedSessions(t, suite) })
	}
}

func runTestAuthenticatedSessions(t *testing.T, suite model.CipherSuite) {
	a, b := configs(t)
	a.Cipher, b.Cipher = suite, suite
	as, bs := establish(t, a, b)
	payload := []byte("overlay packet")
	encrypted, err := as.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, payload) {
		t.Fatal("plaintext exposed")
	}
	plaintext, err := bs.Open(encrypted)
	if err != nil || !bytes.Equal(plaintext, payload) {
		t.Fatal("decrypt", err)
	}
	reverse, err := bs.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reverse, encrypted) {
		t.Fatal("directional keys were reused")
	}
	if _, err := as.Open(reverse); err != nil {
		t.Fatal(err)
	}
	freshA, freshB := establish(t, a, b)
	if freshA.ID() == as.ID() {
		t.Fatal("reused session binding")
	}
	if _, err := freshB.Open(encrypted); err == nil {
		t.Fatal("cross-session packet accepted")
	}
	if _, err := as.Open(encrypted); err == nil {
		t.Fatal("reflected packet accepted")
	}
}

func TestHandshakeHidesIDsAndKeysOnWire(t *testing.T) {
	a, b := configs(t)
	initiator, err := NewHandshake(a)
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, err := initiator.Write()
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := RespondHandshake(b.Identity, msg1, nil, func(ClientHello) (Config, error) { return b, nil })
	if err != nil {
		t.Fatal(err)
	}
	wire := append(append([]byte{}, msg1...), msg2...)
	aPubX, _ := Ed25519PublicToX25519(a.Identity.Public().(ed25519.PublicKey))
	bPubX, _ := Ed25519PublicToX25519(b.Identity.Public().(ed25519.PublicKey))
	for _, id := range []model.ID{a.Network, a.Edge, a.Local, a.Peer} {
		rawID, _ := hex.DecodeString(string(id))
		if bytes.Contains(wire, rawID) || bytes.Contains(wire, []byte(id)) {
			t.Fatalf("wire bytes leaked ID %s", id)
		}
	}
	for _, keyBytes := range [][]byte{
		a.Identity.Public().(ed25519.PublicKey),
		b.Identity.Public().(ed25519.PublicKey),
		aPubX[:],
		bPubX[:],
	} {
		if bytes.Contains(wire, keyBytes) {
			t.Fatal("wire bytes leaked static public key")
		}
	}
}

func TestHandshakeBindsIdentityTopologyTransportAndTimestamp(t *testing.T) {
	for _, kind := range []string{"wrong_responder_key", "wrong_initiator_key", "network", "edge", "node", "transport"} {
		t.Run(kind, func(t *testing.T) {
			a, b := configs(t)
			otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
			switch kind {
			case "wrong_responder_key":
				a.PeerIdentity = otherPub
			case "wrong_initiator_key":
				b.PeerIdentity = otherPub
			case "network":
				b.Network = testutil.ID(99)
			case "edge":
				b.Edge = testutil.ID(99)
			case "node":
				b.Peer = testutil.ID(99)
			case "transport":
				b.Transport = model.TCP
			}
			initiator, err := NewHandshake(a)
			if err != nil {
				t.Fatal(err)
			}
			msg1, _, err := initiator.Write()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := RespondHandshake(b.Identity, msg1, nil, func(ClientHello) (Config, error) { return b, nil }); err == nil {
				t.Fatalf("%s accepted by responder", kind)
			}
		})
	}

	// Replay, out-of-order concurrent multi-path acceptance, and stale timestamp rejection.
	a, b := configs(t)
	replay := &ReplayFilter{}
	baseTS := HandshakeReorderWindow * 20
	a.Timestamp = baseTS
	init1, _ := NewHandshake(a)
	msg1, _, _ := init1.Write()
	if _, _, err := RespondHandshake(b.Identity, msg1, replay, func(ClientHello) (Config, error) { return b, nil }); err != nil {
		t.Fatalf("initial handshake rejected: %v", err)
	}
	// Exact replay of Message 1 is always rejected.
	if _, _, err := RespondHandshake(b.Identity, msg1, replay, func(ClientHello) (Config, error) { return b, nil }); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed msg1 err=%v, want ErrReplay", err)
	}
	// Concurrent handshake with fresh ephemeral within HandshakeReorderWindow succeeds once, then rejects replay.
	a.Timestamp = baseTS - HandshakeReorderWindow/500
	reordered, _ := NewHandshake(a)
	reorderedMsg, _, _ := reordered.Write()
	if _, _, err := RespondHandshake(b.Identity, reorderedMsg, replay, func(ClientHello) (Config, error) { return b, nil }); err != nil {
		t.Fatalf("out-of-order concurrent handshake rejected: %v", err)
	}
	if _, _, err := RespondHandshake(b.Identity, reorderedMsg, replay, func(ClientHello) (Config, error) { return b, nil }); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed out-of-order msg err=%v, want ErrReplay", err)
	}
	// Fresh ephemeral outside HandshakeReorderWindow is rejected.
	for _, ts := range []uint64{baseTS - HandshakeReorderWindow, baseTS - HandshakeReorderWindow - 1, 1} {
		a.Timestamp = ts
		older, _ := NewHandshake(a)
		olderMsg, _, _ := older.Write()
		if _, _, err := RespondHandshake(b.Identity, olderMsg, replay, func(ClientHello) (Config, error) { return b, nil }); !errors.Is(err, ErrReplay) {
			t.Fatalf("stale timestamp %d err=%v, want ErrReplay", ts, err)
		}
	}
	// Newer timestamp succeeds.
	a.Timestamp = baseTS + 1
	newer, _ := NewHandshake(a)
	newerMsg, _, _ := newer.Write()
	if _, _, err := RespondHandshake(b.Identity, newerMsg, replay, func(ClientHello) (Config, error) { return b, nil }); err != nil {
		t.Fatalf("newer timestamp rejected: %v", err)
	}
}

func TestReplayWindowAndForgery(t *testing.T) {
	a, b := configs(t)
	as, bs := establish(t, a, b)
	frames := make([][]byte, ReplayWindow+3)
	for i := range frames {
		var err error
		frames[i], err = as.Seal([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range []int{10, 0, 5} {
		if _, err := bs.Open(frames[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bs.Open(frames[5]); !errors.Is(err, ErrReplay) {
		t.Fatal("duplicate accepted")
	}
	forged := bytes.Clone(frames[11])
	binary.BigEndian.PutUint32(forged, uint32(MaxMessages-1))
	if _, err := bs.Open(forged); err == nil {
		t.Fatal("forged nonce accepted")
	}
	if _, err := bs.Open(frames[11]); err != nil {
		t.Fatal("forgery advanced window", err)
	}
	tampered := bytes.Clone(frames[12])
	tampered[len(tampered)-1] ^= 1
	if _, err := bs.Open(tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := bs.Open(frames[12]); err != nil {
		t.Fatal("bad authentication consumed nonce", err)
	}
	if _, err := bs.Open(frames[len(frames)-1]); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.Open(frames[1]); !errors.Is(err, ErrReplay) {
		t.Fatal("old packet accepted")
	}
}
