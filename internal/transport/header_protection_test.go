package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamHeaderProtectionMasksLengthsKindsAndCounters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	var wireMu sync.Mutex
	var wire bytes.Buffer
	tapLeft := &recordingNetConn{Conn: left, record: func(b []byte) {
		wireMu.Lock()
		wire.Write(b)
		wireMu.Unlock()
	}}

	sender := NewStream(tapLeft)
	sender.SetLocalPublicKey(pubA)
	sender.SetPeerPublicKey(pubB)

	receiver := NewStream(right)
	receiver.SetLocalPublicKey(pubB)
	receiver.SetPeerPublicKey(pubA)

	const count = 16
	sent := make([][]byte, count)
	for i := range sent {
		frame := make([]byte, 1+4+64)
		frame[0] = dataFrameKind
		binary.BigEndian.PutUint32(frame[1:5], uint32(i+1))
		rand.Read(frame[5:])
		sent[i] = frame
	}

	errCh := make(chan error, 1)
	go func() { errCh <- sender.SendBatch(ctx, sent) }()

	for i := range count {
		got, err := receiver.Receive(ctx)
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if !bytes.Equal(got, sent[i]) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	wireMu.Lock()
	raw := bytes.Clone(wire.Bytes())
	wireMu.Unlock()
	if len(raw) <= hpSaltSize {
		t.Fatal("missing stream salt")
	}
	if raw[0] == 0x16 || raw[0] == 'G' {
		t.Fatalf("stream salt started with reserved byte 0x%02x", raw[0])
	}
	// Verify that consecutive frame headers on the wire do not carry fixed 4B big-endian length 69 or 0x45 kind.
	plainLen := [4]byte{0, 0, 0, 69}
	unmaskedHeaders := 0
	offset := hpSaltSize
	for range count {
		if bytes.Equal(raw[offset:offset+4], plainLen[:]) && raw[offset+4] == dataFrameKind {
			unmaskedHeaders++
		}
		offset += 4 + 69
	}
	if unmaskedHeaders > 0 {
		t.Fatalf("found %d unmasked stream headers on wire", unmaskedHeaders)
	}
}

func TestUDPHeaderProtectionMasksTokenKindAndCounter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)

	hubA, err := ListenUDP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hubA.Close()
	hubA.EnableHeaderProtection(pubA)

	hubB, err := ListenUDP(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hubB.Close()
	hubB.EnableHeaderProtection(pubB)

	addrB := hubB.LocalAddr().(*net.UDPAddr).AddrPort()
	connA, err := hubA.Dial(addrB)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connA.SetPeerPublicKey(pubB)

	// Verify maskUDPParts produces distinct wire tokens across distinct ciphertexts.
	p1 := make([]byte, 172)
	p1[0] = 0x41
	rand.Read(p1[1:])
	p2 := make([]byte, 172)
	p2[0] = 0x41
	rand.Read(p2[1:])
	_, tok1, ok1 := maskUDPParts(HeaderProtectionKey(pubB), p1, nil, connA.key.token)
	_, tok2, ok2 := maskUDPParts(HeaderProtectionKey(pubB), p2, nil, connA.key.token)
	if !ok1 || !ok2 || tok1 == connA.key.token || tok1 == tok2 {
		t.Fatalf("UDP token was not masked per ciphertext: %x vs %x (raw %x)", tok1, tok2, connA.key.token)
	}

	// End-to-end over real UDP sockets (initiation 0x41 followed by batch of 0x45 data frames).
	accepted := make(chan *Datagram, 1)
	go func() {
		peer, err := hubB.Accept(ctx)
		if err == nil {
			peer.SetPeerPublicKey(pubA)
			accepted <- peer
		}
	}()

	if err := connA.Send(ctx, p1); err != nil {
		t.Fatal(err)
	}
	var connB *Datagram
	select {
	case connB = <-accepted:
	case <-ctx.Done():
		t.Fatal("masked UDP initiation was not accepted")
	}
	defer connB.Close()
	gotInit, err := connB.Receive(ctx)
	if err != nil || !bytes.Equal(gotInit, p1) {
		t.Fatalf("unmasked initiation mismatch: %v", err)
	}

	batch := make([][]byte, 8)
	originals := make([][]byte, 8)
	for i := range batch {
		msg := make([]byte, 1+4+48)
		msg[0] = dataFrameKind
		binary.BigEndian.PutUint32(msg[1:5], uint32(i+1))
		rand.Read(msg[5:])
		batch[i] = msg
		originals[i] = bytes.Clone(msg)
	}
	if err := connA.SendBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	for i, want := range originals {
		if !bytes.Equal(batch[i], want) {
			t.Fatal("UDP SendBatch mutated caller slice")
		}
		got, err := connB.Receive(ctx)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("UDP batch packet %d mismatch: %v", i, err)
		}
	}
}
