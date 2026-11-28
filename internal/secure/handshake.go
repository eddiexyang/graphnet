// Package secure authenticates configured peers and encrypts packet sessions.
package secure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/edwards25519"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/flynn/noise"
)

const (
	MaxHandshake     = 1024
	handshakeVersion = 2
	helloPayloadSize = 1 + 4*16 + 1 + 1 + 8 // version, 4 IDs, transport, cipher, timestamp
)

var (
	prologueBytes  = []byte("GraphNet/peer/v2")
	wireTransports = []model.Transport{model.UDP, model.TCP, model.QUIC, model.WS, model.WSS}
	wireCiphers    = []model.CipherSuite{model.ChaCha20Poly1305, model.AES256GCM, model.AES128GCM, model.XChaCha20Poly1305}
	lastTimestamp  atomic.Uint64
)

type Config struct {
	Network      model.ID
	Edge         model.ID
	Local        model.ID
	Peer         model.ID
	Transport    model.Transport
	Cipher       model.CipherSuite
	Identity     ed25519.PrivateKey
	PeerIdentity ed25519.PublicKey
	Initiator    bool
	// Timestamp overrides the monotonic clock when non-zero (used in tests).
	Timestamp uint64
	// Replay enforces strictly increasing initiator timestamps per peer static key.
	Replay *ReplayFilter
}

// ClientHello is the encrypted Message-1 payload decrypted by the responder.
type ClientHello struct {
	Network, Edge, Initiator, Responder model.ID
	Transport                           model.Transport
	Cipher                              model.CipherSuite
	Timestamp                           uint64
	PeerStatic                          [32]byte
}

const (
	// HandshakeReorderWindow allows concurrent multi-path handshakes from one
	// peer to arrive out of order without rejecting the slower path, while
	// bounding seen ephemeral public keys per peer.
	HandshakeReorderWindow = uint64(5 * time.Second)
	maxRecentEphemerals    = 64
)

type peerReplayState struct {
	highest uint64
	ring    [maxRecentEphemerals][32]byte
	next    int
	count   int
}

// ReplayFilter rejects replayed or stale initiator handshakes using a sliding
// timestamp floor combined with initiator ephemeral-key deduplication.
type ReplayFilter struct {
	mu    sync.Mutex
	peers map[[32]byte]*peerReplayState
}

func (r *ReplayFilter) Accept(peerStatic, ephemeral [32]byte, timestamp uint64) bool {
	if timestamp == 0 || ephemeral == ([32]byte{}) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = map[[32]byte]*peerReplayState{}
	}
	st := r.peers[peerStatic]
	if st == nil {
		st = &peerReplayState{}
		r.peers[peerStatic] = st
	}
	for i := 0; i < st.count; i++ {
		if st.ring[i] == ephemeral {
			return false
		}
	}
	if st.highest > HandshakeReorderWindow && timestamp <= st.highest-HandshakeReorderWindow {
		return false
	}
	st.ring[st.next] = ephemeral
	st.next = (st.next + 1) % maxRecentEphemerals
	if st.count < maxRecentEphemerals {
		st.count++
	}
	if timestamp > st.highest {
		st.highest = timestamp
	}
	return true
}

// Prune removes state for peer static keys no longer present in keep.
func (r *ReplayFilter) Prune(keep map[[32]byte]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.peers {
		if !keep[k] {
			delete(r.peers, k)
		}
	}
}

// Ed25519PublicToX25519 converts an Ed25519 public key (Edwards form) to its
// birationally equivalent Curve25519 Montgomery u-coordinate, rejecting
// torsion/small-order points.
func Ed25519PublicToX25519(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("invalid Ed25519 public key length")
	}
	pt, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return out, errors.New("invalid Ed25519 curve point")
	}
	if new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return out, errors.New("low-order Ed25519 public key")
	}
	copy(out[:], pt.BytesMontgomery())
	return out, nil
}

// Ed25519PrivateToX25519 derives the clamped X25519 static keypair matching
// priv's Ed25519 identity.
func Ed25519PrivateToX25519(priv ed25519.PrivateKey) (privX, pubX [32]byte, err error) {
	if len(priv) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(priv.Seed()), priv) {
		return privX, pubX, errors.New("invalid private identity")
	}
	pubX, err = Ed25519PublicToX25519(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return privX, pubX, err
	}
	digest := sha512.Sum512(priv.Seed())
	copy(privX[:], digest[:32])
	privX[0] &= 248
	privX[31] &= 127
	privX[31] |= 64
	return privX, pubX, nil
}

func nextHandshakeTimestamp() uint64 {
	for {
		prev := lastTimestamp.Load()
		now := uint64(max(int64(1), time.Now().UnixNano()))
		next := max(now, prev+1)
		if lastTimestamp.CompareAndSwap(prev, next) {
			return next
		}
	}
}

func encodeClientHello(cfg Config, ts uint64) ([]byte, error) {
	var out [helloPayloadSize]byte
	out[0] = handshakeVersion
	for i, id := range []model.ID{cfg.Network, cfg.Edge, cfg.Local, cfg.Peer} {
		if err := id.Validate(); err != nil {
			return nil, err
		}
		if _, err := hex.Decode(out[1+i*16:17+i*16], []byte(id)); err != nil {
			return nil, err
		}
	}
	tIdx := -1
	for i, t := range wireTransports {
		if cfg.Transport == t {
			tIdx = i
			break
		}
	}
	cIdx := -1
	for i, c := range wireCiphers {
		if cfg.Cipher == c {
			cIdx = i
			break
		}
	}
	if tIdx < 0 || cIdx < 0 {
		return nil, errors.New("invalid handshake transport or cipher")
	}
	out[65] = byte(tIdx)
	out[66] = byte(cIdx)
	binary.BigEndian.PutUint64(out[67:75], ts)
	return out[:], nil
}

func decodeClientHello(raw []byte, peerStatic []byte) (ClientHello, error) {
	var h ClientHello
	if len(raw) != helloPayloadSize || raw[0] != handshakeVersion || len(peerStatic) != 32 {
		return h, errors.New("invalid encrypted peer hello")
	}
	if int(raw[65]) >= len(wireTransports) || int(raw[66]) >= len(wireCiphers) {
		return h, errors.New("unsupported peer transport or cipher")
	}
	for i, dst := range []*model.ID{&h.Network, &h.Edge, &h.Initiator, &h.Responder} {
		*dst = model.ID(hex.EncodeToString(raw[1+i*16 : 17+i*16]))
		if err := dst.Validate(); err != nil {
			return ClientHello{}, err
		}
	}
	h.Transport = wireTransports[raw[65]]
	h.Cipher = wireCiphers[raw[66]]
	h.Timestamp = binary.BigEndian.Uint64(raw[67:75])
	if h.Timestamp == 0 {
		return ClientHello{}, errors.New("zero handshake timestamp")
	}
	copy(h.PeerStatic[:], peerStatic)
	return h, nil
}

func validatePolicyConfig(cfg Config) error {
	for _, id := range []model.ID{cfg.Network, cfg.Edge, cfg.Local, cfg.Peer} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if cfg.Local == cfg.Peer || !cfg.Transport.Valid() || !cfg.Cipher.Valid() {
		return errors.New("invalid peer handshake policy")
	}
	return nil
}

func deriveSession(suite model.CipherSuite, initiator bool, first, second *noise.CipherState, binding []byte) (*Session, error) {
	if first == nil || second == nil {
		return nil, errors.New("incomplete Noise split")
	}
	k1, k2 := first.UnsafeKey(), second.UnsafeKey()
	raw1, err := hkdf.Key(sha256.New, k1[:], binding, "GraphNet/peer/v2/i2r/"+string(suite), 32)
	if err != nil {
		return nil, err
	}
	raw2, err := hkdf.Key(sha256.New, k2[:], binding, "GraphNet/peer/v2/r2i/"+string(suite), 32)
	if err != nil {
		return nil, err
	}
	sub1, err := hkdf.Key(sha256.New, k1[:], binding, "GraphNet/peer/v2/qstream-i2r/"+string(suite), 32)
	if err != nil {
		return nil, err
	}
	sub2, err := hkdf.Key(sha256.New, k2[:], binding, "GraphNet/peer/v2/qstream-r2i/"+string(suite), 32)
	if err != nil {
		return nil, err
	}
	var dk1, dk2, sr1, sr2 [32]byte
	copy(dk1[:], raw1)
	copy(dk2[:], raw2)
	copy(sr1[:], sub1)
	copy(sr2[:], sub2)
	fn := cipherFunction(suite)
	c1, c2 := fn.Cipher(dk1), fn.Cipher(dk2)
	send, recv := c1, c2
	sendSub, recvSub := sr1, sr2
	if !initiator {
		send, recv = c2, c1
		sendSub, recvSub = sr2, sr1
	}
	ownedBinding := bytes.Clone(binding)
	s := newSession(hex.EncodeToString(ownedBinding), ownedBinding, send, recv)
	s.suite = suite
	s.sendStreamRoot = sendSub
	s.recvStreamRoot = recvSub
	s.hasStreamRoots = true
	return s, nil
}

type Handshake struct {
	state     *noise.HandshakeState
	config    Config
	localPubX [32]byte
	failed    bool
	finished  bool
}

// NewHandshake initializes a 1-RTT Noise IK handshake using ChaChaPoly and
// X25519 static keys converted from the nodes' Ed25519 identities.
func NewHandshake(config Config) (*Handshake, error) {
	if err := validatePolicyConfig(config); err != nil {
		return nil, err
	}
	privX, pubX, err := Ed25519PrivateToX25519(config.Identity)
	if err != nil {
		return nil, err
	}
	nc := noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:       noise.HandshakeIK,
		Initiator:     config.Initiator,
		Prologue:      prologueBytes,
		StaticKeypair: noise.DHKey{Private: privX[:], Public: pubX[:]},
	}
	if config.Initiator {
		peerX, err := Ed25519PublicToX25519(config.PeerIdentity)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(pubX[:], peerX[:]) == 1 {
			return nil, errors.New("self peer identity")
		}
		nc.PeerStatic = peerX[:]
	} else if len(config.PeerIdentity) != ed25519.PublicKeySize {
		return nil, errors.New("invalid peer identity")
	}
	state, err := noise.NewHandshakeState(nc)
	if err != nil {
		return nil, err
	}
	config.PeerIdentity = bytes.Clone(config.PeerIdentity)
	config.Identity = nil
	return &Handshake{state: state, config: config, localPubX: pubX}, nil
}

// RespondHandshake authenticates an incoming Noise IK Message 1, resolves peer
// policy from the decrypted ClientHello, enforces anti-replay, and returns
// Message 2 along with the derived data Session.
func RespondHandshake(identity ed25519.PrivateKey, msg1 []byte, replay *ReplayFilter, authorize func(ClientHello) (Config, error)) ([]byte, *Session, error) {
	if len(msg1) == 0 || len(msg1) > MaxHandshake {
		return nil, nil, errors.New("invalid handshake message length")
	}
	privX, pubX, err := Ed25519PrivateToX25519(identity)
	if err != nil {
		return nil, nil, err
	}
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      prologueBytes,
		StaticKeypair: noise.DHKey{Private: privX[:], Public: pubX[:]},
	})
	if err != nil {
		return nil, nil, err
	}
	payload, _, _, err := state.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, err
	}
	hello, err := decodeClientHello(payload, state.PeerStatic())
	if err != nil {
		return nil, nil, err
	}
	cfg, err := authorize(hello)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyResponderPolicy(cfg, hello, pubX); err != nil {
		return nil, nil, err
	}
	effectiveReplay := replay
	if effectiveReplay == nil {
		effectiveReplay = cfg.Replay
	}
	if effectiveReplay != nil && !effectiveReplay.Accept(hello.PeerStatic, [32]byte(msg1[:32]), hello.Timestamp) {
		return nil, nil, ErrReplay
	}
	msg2, first, second, err := state.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	session, err := deriveSession(cfg.Cipher, false, first, second, state.ChannelBinding())
	if err != nil {
		return nil, nil, err
	}
	return msg2, session, nil
}

func verifyResponderPolicy(cfg Config, hello ClientHello, localPubX [32]byte) error {
	if err := validatePolicyConfig(cfg); err != nil {
		return err
	}
	peerX, err := Ed25519PublicToX25519(cfg.PeerIdentity)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(peerX[:], hello.PeerStatic[:]) != 1 || subtle.ConstantTimeCompare(localPubX[:], peerX[:]) == 1 {
		return errors.New("peer identity authentication failed")
	}
	if cfg.Network != hello.Network || cfg.Edge != hello.Edge || cfg.Local != hello.Responder || cfg.Peer != hello.Initiator || cfg.Transport != hello.Transport || cfg.Cipher != hello.Cipher {
		return errors.New("peer handshake policy mismatch")
	}
	return nil
}

func (h *Handshake) Write() ([]byte, *Session, error) {
	if h.failed || h.finished {
		return nil, nil, errors.New("handshake is no longer active")
	}
	if h.config.Initiator {
		if h.state.MessageIndex() != 0 {
			h.failed = true
			return nil, nil, errors.New("unexpected initiator write step")
		}
		ts := h.config.Timestamp
		if ts == 0 {
			ts = nextHandshakeTimestamp()
		}
		payload, err := encodeClientHello(h.config, ts)
		if err != nil {
			h.failed = true
			return nil, nil, err
		}
		msg1, _, _, err := h.state.WriteMessage(nil, payload)
		if err != nil {
			h.failed = true
			return nil, nil, err
		}
		return msg1, nil, nil
	}
	if h.state.MessageIndex() != 1 {
		h.failed = true
		return nil, nil, errors.New("unexpected responder write step")
	}
	msg2, first, second, err := h.state.WriteMessage(nil, nil)
	if err != nil {
		h.failed = true
		return nil, nil, err
	}
	h.finished = true
	session, err := deriveSession(h.config.Cipher, false, first, second, h.state.ChannelBinding())
	if err != nil {
		h.failed = true
		return nil, nil, err
	}
	return msg2, session, nil
}

func (h *Handshake) Read(message []byte) (*Session, error) {
	if h.failed || h.finished {
		return nil, errors.New("handshake is no longer active")
	}
	if len(message) == 0 || len(message) > MaxHandshake {
		h.failed = true
		return nil, errors.New("invalid handshake message length")
	}
	if h.config.Initiator {
		if h.state.MessageIndex() != 1 {
			h.failed = true
			return nil, errors.New("unexpected initiator read step")
		}
		payload, first, second, err := h.state.ReadMessage(nil, message)
		if err != nil {
			h.failed = true
			return nil, err
		}
		if len(payload) != 0 {
			h.failed = true
			return nil, errors.New("unexpected handshake reply payload")
		}
		h.finished = true
		session, err := deriveSession(h.config.Cipher, true, first, second, h.state.ChannelBinding())
		if err != nil {
			h.failed = true
			return nil, err
		}
		return session, nil
	}
	if h.state.MessageIndex() != 0 {
		h.failed = true
		return nil, errors.New("unexpected responder read step")
	}
	payload, _, _, err := h.state.ReadMessage(nil, message)
	if err != nil {
		h.failed = true
		return nil, err
	}
	hello, err := decodeClientHello(payload, h.state.PeerStatic())
	if err != nil {
		h.failed = true
		return nil, err
	}
	if err := verifyResponderPolicy(h.config, hello, h.localPubX); err != nil {
		h.failed = true
		return nil, err
	}
	if h.config.Replay != nil && !h.config.Replay.Accept(hello.PeerStatic, [32]byte(message[:32]), hello.Timestamp) {
		h.failed = true
		return nil, ErrReplay
	}
	return nil, nil
}
