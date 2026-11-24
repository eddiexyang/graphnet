package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/curve25519"
)

const (
	punchALPN        = "h2"
	PunchSaltSize    = 16
	PunchTagSize     = 16
	PunchPrefaceSize = PunchSaltSize + PunchTagSize
)

type PunchMux struct {
	session     *yamux.Session
	identity    ed25519.PublicKey
	streamMu    sync.Mutex
	streamLimit int
	streams     int
	socket      net.Conn
}

func ed25519PubToX25519(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("invalid Ed25519 public key")
	}
	pt, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return out, err
	}
	if new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return out, errors.New("low-order Ed25519 public key")
	}
	copy(out[:], pt.BytesMontgomery())
	return out, nil
}

func ed25519PrivToX25519(priv ed25519.PrivateKey) ([32]byte, ed25519.PublicKey, error) {
	var out [32]byte
	if len(priv) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(priv.Seed()), priv) {
		return out, nil, errors.New("invalid Ed25519 private key")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := ed25519PubToX25519(pub); err != nil {
		return out, nil, err
	}
	h := sha512.Sum512(priv.Seed())
	copy(out[:], h[:32])
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out, pub, nil
}

func punchPairKey(localPrivX [32]byte, peerPub ed25519.PublicKey) ([32]byte, error) {
	var key [32]byte
	peerX, err := ed25519PubToX25519(peerPub)
	if err != nil {
		return key, err
	}
	shared, err := curve25519.X25519(localPrivX[:], peerX[:])
	if err != nil {
		return key, err
	}
	derived, err := hkdf.Key(sha256.New, shared, nil, "GraphNet punch pair v2", 32)
	if err != nil {
		return key, err
	}
	copy(key[:], derived)
	return key, nil
}

func punchPrefaceTag(pairKey [32]byte, sender ed25519.PublicKey, salt []byte) [PunchTagSize]byte {
	mac := hmac.New(sha256.New, pairKey[:])
	mac.Write([]byte("GraphNet punch preface v2\x00"))
	mac.Write(sender)
	mac.Write(salt)
	var out [PunchTagSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func punchConfirmTag(pairKey [32]byte, sender ed25519.PublicKey, ownSalt, peerSalt []byte) [PunchTagSize]byte {
	mac := hmac.New(sha256.New, pairKey[:])
	mac.Write([]byte("GraphNet punch confirm v2\x00"))
	mac.Write(sender)
	mac.Write(ownSalt)
	mac.Write(peerSalt)
	var out [PunchTagSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func drawPunchSalt() (salt [PunchSaltSize]byte, err error) {
	for {
		if _, err := rand.Read(salt[:]); err != nil {
			return salt, err
		}
		if salt[0] != 0 && salt[0] != 0x16 && salt[0] != 'G' {
			return salt, nil
		}
	}
}

// MatchPunchPreface checks a peeked 32-byte preface against allowed peer public
// keys without writing anything to the socket.
func MatchPunchPreface(local ed25519.PrivateKey, preface []byte, peers []ed25519.PublicKey) (ed25519.PublicKey, bool) {
	if len(preface) < PunchPrefaceSize {
		return nil, false
	}
	privX, localPub, err := ed25519PrivToX25519(local)
	if err != nil {
		return nil, false
	}
	salt, tag := preface[:PunchSaltSize], preface[PunchSaltSize:PunchPrefaceSize]
	for _, candidate := range peers {
		if len(candidate) != ed25519.PublicKeySize || candidate.Equal(localPub) {
			continue
		}
		pairKey, err := punchPairKey(privX, candidate)
		if err != nil {
			continue
		}
		want := punchPrefaceTag(pairKey, candidate, salt)
		if subtle.ConstantTimeCompare(want[:], tag) == 1 {
			return bytes.Clone(candidate), true
		}
	}
	return nil, false
}

// NewPunchMux works for active/passive AND simultaneous-open TCP sockets. Both
// ends exchange salt ‖ HMAC(K_pair, salt), authorize the matched peer, then
// prove possession with mutually pinned TLS 1.3. A passive end says nothing
// until the peer's tag matches an authorized peer.
func NewPunchMux(ctx context.Context, conn net.Conn, local ed25519.PrivateKey, certificate *tls.Config, peers func() []ed25519.PublicKey, passive bool) (_ *PunchMux, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	cleanup, err := deadline(ctx, conn.SetDeadline)
	if err != nil {
		return nil, err
	}
	defer func() { cleanup() }()
	privX, localPub, err := ed25519PrivToX25519(local)
	if err != nil {
		return nil, err
	}
	ownSalt, err := drawPunchSalt()
	if err != nil {
		return nil, err
	}
	if !passive {
		allowed := peers()
		if len(allowed) != 1 || len(allowed[0]) != ed25519.PublicKeySize || allowed[0].Equal(localPub) {
			return nil, errors.New("active TCP punch requires one target peer")
		}
		pairKey, err := punchPairKey(privX, allowed[0])
		if err != nil {
			return nil, err
		}
		var own [PunchPrefaceSize]byte
		copy(own[:PunchSaltSize], ownSalt[:])
		tag := punchPrefaceTag(pairKey, localPub, ownSalt[:])
		copy(own[PunchSaltSize:], tag[:])
		if err := writeFull(conn, own[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
	}
	var hello [PunchPrefaceSize]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return nil, ctxError(ctx, err)
	}
	remote, ok := MatchPunchPreface(local, hello[:], peers())
	if !ok {
		return nil, errors.New("unconfigured TCP punch peer")
	}
	pairKey, err := punchPairKey(privX, remote)
	if err != nil {
		return nil, err
	}
	if passive {
		var own [PunchPrefaceSize]byte
		copy(own[:PunchSaltSize], ownSalt[:])
		tag := punchPrefaceTag(pairKey, localPub, ownSalt[:])
		copy(own[PunchSaltSize:], tag[:])
		if err := writeFull(conn, own[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
	}
	client := bytes.Compare(localPub, remote) < 0
	config := certificate.Clone()
	config.NextProtos = []string{punchALPN}
	config.ClientAuth = tls.RequireAnyClientCert
	config.InsecureSkipVerify = true // VerifyConnection below pins BOTH directions, with no CA fallback.
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return config.GetCertificate(nil) }
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if state.NegotiatedProtocol != punchALPN || len(state.PeerCertificates) != 1 {
			return errors.New("invalid punch TLS negotiation")
		}
		leaf := state.PeerCertificates[0]
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok || !pub.Equal(remote) {
			return errors.New("TCP punch identity mismatch")
		}
		now := time.Now()
		usage := x509.ExtKeyUsageClientAuth
		if client {
			usage = x509.ExtKeyUsageServerAuth
		}
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || len(leaf.UnhandledCriticalExtensions) != 0 || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, usage) {
			return errors.New("invalid TCP punch certificate")
		}
		return nil
	}
	var secured *tls.Conn
	if client {
		secured = tls.Client(conn, config)
	} else {
		secured = tls.Server(conn, config)
	}
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	peerSalt := hello[:PunchSaltSize]
	ownConfirm := punchConfirmTag(pairKey, localPub, ownSalt[:], peerSalt)
	var confirmed [PunchTagSize]byte
	if client {
		if err := writeFull(secured, ownConfirm[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
		if _, err := io.ReadFull(secured, confirmed[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
	} else {
		if _, err := io.ReadFull(secured, confirmed[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
		if err := writeFull(secured, ownConfirm[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
	}
	wantConfirm := punchConfirmTag(pairKey, remote, peerSalt, ownSalt[:])
	if subtle.ConstantTimeCompare(confirmed[:], wantConfirm[:]) != 1 {
		return nil, errors.New("missing authenticated TCP punch confirmation")
	}
	// Remove the establishment deadline before starting background mux reads.
	cleanup()
	cleanup = func() {}
	options := yamux.DefaultConfig()
	options.AcceptBacklog = 8
	options.KeepAliveInterval = 15 * time.Second
	options.ConnectionWriteTimeout = 2 * time.Second
	options.StreamOpenTimeout = 3 * time.Second
	options.StreamCloseTimeout = 3 * time.Second
	options.MaxStreamWindowSize = 256 * 1024
	options.LogOutput = io.Discard
	var session *yamux.Session
	if client {
		session, err = yamux.Client(secured, options)
	} else {
		session, err = yamux.Server(secured, options)
	}
	if err != nil {
		return nil, err
	}
	return &PunchMux{session: session, identity: remote, streamLimit: 32, socket: conn}, nil
}

func (p *PunchMux) Identity() ed25519.PublicKey { return bytes.Clone(p.identity) }
func (p *PunchMux) LocalAddr() net.Addr         { return p.session.LocalAddr() }
func (p *PunchMux) RemoteAddr() net.Addr        { return p.session.RemoteAddr() }
func (p *PunchMux) Done() <-chan struct{}       { return p.session.CloseChan() }
func (p *PunchMux) Close() error                { p.socket.Close(); return p.session.Close() }

// EnsureStreamCapacity increases the bounded stream allowance for controller-
// authorized topology. Only the owner may call it; peers cannot negotiate it.
// Keep the high-water mark for this physical session: reducing policy can leave
// closing streams and healthy expired-observation sessions awaiting renewal.
func (p *PunchMux) EnsureStreamCapacity(limit int) {
	p.streamMu.Lock()
	p.streamLimit = max(p.streamLimit, limit)
	p.streamMu.Unlock()
}

func (p *PunchMux) reserve(accept bool) error {
	p.streamMu.Lock()
	defer p.streamMu.Unlock()
	if p.session.IsClosed() {
		return net.ErrClosed
	}
	count := p.session.NumStreams()
	if p.streams >= p.streamLimit || count > p.streamLimit || !accept && count == p.streamLimit {
		return errors.New("TCP punch stream limit reached")
	}
	p.streams++
	return nil
}

func (p *PunchMux) release() {
	p.streamMu.Lock()
	p.streams--
	p.streamMu.Unlock()
}

func (p *PunchMux) Open(ctx context.Context) (*PunchStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.reserve(false); err != nil {
		return nil, err
	}
	type opened struct {
		stream *yamux.Stream
		err    error
	}
	result := make(chan opened)
	// OpenStream has a library-level timeout; retain the slot until it returns,
	// even when this caller cancels. Cancellation never closes unrelated streams.
	go func() {
		stream, err := p.session.OpenStream()
		select {
		case result <- opened{stream, err}:
		case <-ctx.Done():
			if stream != nil {
				stream.Close()
			}
			p.release()
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-result:
		if result.err != nil {
			p.release()
			return nil, result.err
		}
		return p.wrap(result.stream), nil
	}
}

func (p *PunchMux) Accept(ctx context.Context) (*PunchStream, error) {
	stream, err := p.session.AcceptStreamWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.reserve(true); err != nil {
		stream.Close()
		p.Close()
		return nil, err
	}
	return p.wrap(stream), nil
}

type punchConn struct {
	net.Conn
	release func()
}

func (c *punchConn) Close() error { err := c.Conn.Close(); c.release(); return err }

type PunchStream struct{ *Stream }

func (*PunchStream) TCPPunch() bool { return true }
func (p *PunchMux) wrap(stream *yamux.Stream) *PunchStream {
	return &PunchStream{NewStream(&punchConn{Conn: stream, release: sync.OnceFunc(p.release)})}
}
