package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	quic "github.com/eddiexyang/quic-go"
)

// silent fails when anything arrives on conn within a short wait.
func silent(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 2048)); n > 0 {
		t.Fatalf("%s drew %d bytes", what, n)
	}
}

// A probe of the shared UDP port gets no answer: not garbage, not a guessed
// QUIC connection ID, not a QUIC Initial from an address that did not knock.
// A dialer that knocks connects.
func TestUDPPortAnswersNoProbe(t *testing.T) {
	_, identity, _ := ed25519.GenerateKey(nil)
	udp, err := ListenUDP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	hub, err := udp.EnableQUIC(identity)
	if err != nil {
		t.Fatal(err)
	}
	target := udp.LocalAddr().(*net.UDPAddr).AddrPort()

	prober, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	garbage := make([]byte, 1200)
	for _, first := range []byte{0x00, 0x41, 0x45, 0x47, 0x51, 0x80, 0xc0, 0xff} {
		rand.Read(garbage)
		garbage[0] = first
		prober.Write(garbage)
	}
	short := make([]byte, 64)
	rand.Read(short)
	short[0], short[1] = 0x41, quicIDPrefix
	prober.Write(short)
	knock := knockFor(identity.Public().(ed25519.PublicKey))
	knock[len(knock)-1] ^= 1
	prober.Write(knock)
	silent(t, prober, "a UDP probe")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()
	_, err = quic.Dial(ctx, stranger, net.UDPAddrFromAddrPort(target), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicProtocol}}, &quic.Config{HandshakeIdleTimeout: time.Second})
	var idle *quic.IdleTimeoutError
	var handshake *quic.HandshakeTimeoutError
	if err == nil || !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &idle) && !errors.As(err, &handshake) {
		t.Fatalf("an Initial without a knock was answered: %v", err)
	}

	dialer, err := ListenUDP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	_, dialIdentity, _ := ed25519.GenerateKey(nil)
	client, err := dialer.EnableQUIC(dialIdentity)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *QUIC, 1)
	go func() {
		link, _ := hub.Accept(context.Background())
		accepted <- link
	}()
	endpoint := model.Endpoint{ID: model.ID("00000000000000000000000000000001"), Transport: model.QUIC, Source: model.Manual, URL: "quic://" + target.String()}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	link, err := client.DialAt(dialCtx, endpoint, 4, identity.Public().(ed25519.PublicKey), netip.Addr{})
	if err != nil {
		t.Fatal("a knocked dial failed:", err)
	}
	defer link.Close()
	if err := link.Send(dialCtx, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-accepted:
		if got, err := peer.Receive(dialCtx); err != nil || string(got) != "hello" {
			t.Fatal("stream message lost", err)
		}
		peer.Close()
	case <-dialCtx.Done():
		t.Fatal("no accepted QUIC Link")
	}
}

// A TCP punch session's accepting end says nothing to a stranger, and an
// authorized handshake exposes no magic prefix or static public key in clear.
func TestPassivePunchAnswersNoProbe(t *testing.T) {
	pubA, keyA, _ := ed25519.GenerateKey(nil)
	pubB, keyB, _ := ed25519.GenerateKey(nil)
	certA, err := PeerServerTLS(keyA)
	if err != nil {
		t.Fatal(err)
	}
	certB, err := PeerServerTLS(keyB)
	if err != nil {
		t.Fatal(err)
	}
	agent, probe := net.Pipe()
	defer probe.Close()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := NewPunchMux(ctx, agent, keyA, certA, func() []ed25519.PublicKey { return []ed25519.PublicKey{pubB} }, true)
		done <- err
	}()
	hello := make([]byte, PunchPrefaceSize)
	rand.Read(hello)
	go probe.Write(hello)
	silent(t, probe, "a punch probe")
	if err := <-done; err == nil {
		t.Fatal("a stranger's punch was accepted")
	}

	// Authorized active/passive punch hides both identities and emits no HGW magic.
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var wire bytes.Buffer
	var wireMu sync.Mutex
	tap := func(c net.Conn) net.Conn {
		return &recordingNetConn{Conn: c, record: func(b []byte) {
			wireMu.Lock()
			wire.Write(b)
			wireMu.Unlock()
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	passiveCh := make(chan *PunchMux, 1)
	passiveErr := make(chan error, 1)
	go func() {
		mux, err := NewPunchMux(ctx, tap(right), keyB, certB, func() []ed25519.PublicKey { return []ed25519.PublicKey{pubA} }, true)
		if err != nil {
			passiveErr <- err
			return
		}
		passiveCh <- mux
	}()
	activeMux, err := NewPunchMux(ctx, tap(left), keyA, certA, func() []ed25519.PublicKey { return []ed25519.PublicKey{pubB} }, false)
	if err != nil {
		t.Fatalf("active punch: %v", err)
	}
	defer activeMux.Close()
	select {
	case err := <-passiveErr:
		t.Fatalf("passive punch: %v", err)
	case pm := <-passiveCh:
		defer pm.Close()
	}
	wireMu.Lock()
	recorded := bytes.Clone(wire.Bytes())
	wireMu.Unlock()
	pubAX, _ := ed25519PubToX25519(pubA)
	pubBX, _ := ed25519PubToX25519(pubB)
	for _, forbidden := range [][]byte{
		{'H', 'G', 'W', 1},
		pubA,
		pubB,
		pubAX[:],
		pubBX[:],
	} {
		if bytes.Contains(recorded[:2*PunchPrefaceSize], forbidden) {
			t.Fatal("punch preface leaked magic or public key")
		}
	}
}

type recordingNetConn struct {
	net.Conn
	record func([]byte)
}

func (r *recordingNetConn) Write(p []byte) (int, error) {
	r.record(p)
	return r.Conn.Write(p)
}
