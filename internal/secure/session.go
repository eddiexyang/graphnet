package secure

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/flynn/noise"
)

const (
	ReplayWindow = 1024
	// A fresh handshake must replace the session before either limit is reached.
	MaxMessages   = uint64(1) << 32
	RenewMessages = 3 * (uint64(1) << 30)
	MaxSessionAge = time.Hour
	// Plaintext is a Link message: its type and, for data, at most a
	// complete overlay frame. Peers enforce the same bound, so it stays.
	MaxPlaintext = packet.MaxFrame + 3
	// Overhead is a message's nonce, its sequence in 4 bytes, and its tag.
	Overhead = NonceSize + 16
	// NonceSize is the bytes of a message's sequence on the wire; a session
	// never reaches MaxMessages, so they hold all of it.
	NonceSize = 4
)

var ErrReplay = errors.New("replayed or stale encrypted packet")
var ErrRekey = errors.New("session requires a fresh handshake")

type Session struct {
	id             string
	binding        []byte
	sendAD         []byte
	receiveAD      []byte
	created        time.Time
	sendMu         sync.Mutex
	receiveMu      sync.Mutex
	send           noise.Cipher
	receive        noise.Cipher
	sequence       uint64
	highest        uint64
	seen           [ReplayWindow]uint64
	batchAD        [4][]byte
	sealAD         [2][]byte
	batchNonces    [128]uint64
	suite          model.CipherSuite
	sendStreamRoot [32]byte
	recvStreamRoot [32]byte
	hasStreamRoots bool
}

func newSession(id string, binding []byte, send, receive noise.Cipher) *Session {
	return &Session{id: id, binding: binding, sendAD: append(append([]byte{}, binding...), make([]byte, NonceSize)...), receiveAD: append(append([]byte{}, binding...), make([]byte, NonceSize)...), created: time.Now(), send: send, receive: receive}
}

func (s *Session) ID() string         { return s.id }
func (s *Session) Created() time.Time { return s.created }
func (s *Session) RenewalDue(after time.Duration) bool {
	s.sendMu.Lock()
	seq := s.sequence
	s.sendMu.Unlock()
	return seq >= RenewMessages || time.Since(s.created) >= after
}
func (s *Session) NeedsRekey() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sequence >= MaxMessages-1 || time.Since(s.created) >= MaxSessionAge
}

// Seal uses a fresh monotonic nonce even when a transport send subsequently
// fails. Nonces, keys and replay windows are never persisted or reused.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	return s.SealAppend(nil, plaintext)
}

// SealAppend appends one encrypted message to dst. The caller owns dst and must
// not overlap it with plaintext. Nonces and associated data remain session-owned.
func (s *Session) SealAppend(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, errors.New("invalid encrypted message size")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sequence >= MaxMessages-1 || time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	s.sequence++
	offset := len(dst)
	dst = binary.BigEndian.AppendUint32(dst, uint32(s.sequence))
	copy(s.sendAD[len(s.binding):], dst[offset:])
	return s.send.Encrypt(dst, s.sequence, s.sendAD, plaintext), nil
}

// SealBatchAppend appends an independently authenticated message to each dst
// entry. Destinations (including their spare capacity) and plaintexts must not
// overlap. A batch reserves unique nonces under one lock; output order and wire
// format are identical to sequential SealAppend calls.
func (s *Session) SealBatchAppend(dst, plaintexts [][]byte) error {
	if len(plaintexts) == 0 || len(plaintexts) > 128 || len(dst) != len(plaintexts) {
		return errors.New("invalid encrypted batch size")
	}
	bytes := 0
	for _, plaintext := range plaintexts {
		if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
			return errors.New("invalid encrypted message size")
		}
		bytes += len(plaintext)
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sequence >= MaxMessages-1 || uint64(len(plaintexts)) > MaxMessages-1-s.sequence || time.Since(s.created) >= MaxSessionAge {
		return ErrRekey
	}
	first := s.sequence + 1
	s.sequence += uint64(len(plaintexts))
	seal := func(worker, start, end int) {
		if s.sealAD[worker] == nil {
			s.sealAD[worker] = make([]byte, len(s.binding)+NonceSize)
			copy(s.sealAD[worker], s.binding)
		}
		ad := s.sealAD[worker]
		for i := start; i < end; i++ {
			nonce := first + uint64(i)
			out := binary.BigEndian.AppendUint32(dst[i], uint32(nonce))
			binary.BigEndian.PutUint32(ad[len(s.binding):], uint32(nonce))
			dst[i] = s.send.Encrypt(out, nonce, ad, plaintexts[i])
		}
	}
	if len(plaintexts) >= 8 && bytes >= 32*1024 && runtime.GOMAXPROCS(0) > 1 {
		var wg sync.WaitGroup
		wg.Add(1)
		mid := len(plaintexts) / 2
		go func() { defer wg.Done(); seal(1, mid, len(plaintexts)) }()
		seal(0, 0, mid)
		wg.Wait()
	} else {
		seal(0, 0, len(plaintexts))
	}
	return nil
}

// Open accepts bounded out-of-order delivery. Replay state advances only after
// authentication succeeds, so forged high nonces cannot evict valid packets.
func (s *Session) Open(frame []byte) ([]byte, error) { return s.open(nil, frame) }

// OpenInPlace consumes an exclusively owned encrypted frame. The returned
// plaintext aliases frame; it must not be used as ciphertext again.
func (s *Session) OpenInPlace(frame []byte) ([]byte, error) {
	if len(frame) <= Overhead {
		return nil, errors.New("invalid encrypted frame size")
	}
	return s.open(frame[NonceSize:NonceSize], frame)
}
func (s *Session) open(dst, frame []byte) ([]byte, error) {
	if len(frame) <= Overhead || len(frame) > MaxPlaintext+Overhead {
		return nil, errors.New("invalid encrypted frame size")
	}
	if time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	nonce := uint64(binary.BigEndian.Uint32(frame[:NonceSize]))
	if nonce == 0 {
		return nil, ErrReplay
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
		return nil, ErrReplay
	}
	copy(s.receiveAD[len(s.binding):], frame[:NonceSize])
	plaintext, err := s.receive.Decrypt(dst, nonce, s.receiveAD, frame[NonceSize:])
	if err != nil {
		return nil, err
	}
	s.seen[nonce%ReplayWindow] = nonce
	s.highest = max(s.highest, nonce)
	return plaintext, nil
}

// OpenBatchInPlace consumes distinct, exclusively owned ciphertext buffers and
// replaces successful entries with plaintext. Authentication can run in parallel,
// but replay-window commits are serialized in original receive order. A forged
// high nonce or a duplicate within the batch can never advance/evade the window.
func (s *Session) OpenBatchInPlace(frames [][]byte) []error {
	errs := make([]error, len(frames))
	if len(frames) > len(s.batchNonces) {
		clear(frames)
		for i := range errs {
			errs[i] = errors.New("encrypted batch too large")
		}
		return errs
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if time.Since(s.created) >= MaxSessionAge {
		clear(frames)
		for i := range errs {
			errs[i] = ErrRekey
		}
		return errs
	}
	bytes := 0
	for i, frame := range frames {
		if len(frame) <= Overhead || len(frame) > MaxPlaintext+Overhead {
			frames[i] = nil
			errs[i] = errors.New("invalid encrypted frame size")
			continue
		}
		nonce := uint64(binary.BigEndian.Uint32(frame[:NonceSize]))
		s.batchNonces[i] = nonce
		if nonce == 0 || s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
			frames[i] = nil
			errs[i] = ErrReplay
			continue
		}
		bytes += len(frame)
	}
	decrypt := func(worker, start, end int) {
		if s.batchAD[worker] == nil {
			s.batchAD[worker] = make([]byte, len(s.binding)+NonceSize)
			copy(s.batchAD[worker], s.binding)
		}
		ad := s.batchAD[worker]
		for i := start; i < end; i++ {
			if errs[i] != nil {
				continue
			}
			frame := frames[i]
			copy(ad[len(s.binding):], frame[:NonceSize])
			frames[i], errs[i] = s.receive.Decrypt(frame[NonceSize:NonceSize], s.batchNonces[i], ad, frame[NonceSize:])
		}
	}
	// ARM64 currently uses the generic Poly1305 path. Smaller batches there
	// justify parallel workers; vectorized amd64 crypto needs a larger payload
	// to amortize scheduling. Small/control batches always stay synchronous.
	parallelBytes := 64 * 1024
	if runtime.GOARCH == "arm64" {
		parallelBytes = 8 * 1024
	}
	if len(frames) >= 8 && bytes >= parallelBytes && runtime.GOMAXPROCS(0) > 1 {
		workers := min(4, runtime.GOMAXPROCS(0), max(2, len(frames)/8))
		var next atomic.Int32
		work := func(worker int) {
			// Small chunks let faster cores take more work on heterogeneous CPUs.
			for {
				start := int(next.Add(4)) - 4
				if start >= len(frames) {
					return
				}
				decrypt(worker, start, min(start+4, len(frames)))
			}
		}
		var wg sync.WaitGroup
		for worker := 1; worker < workers; worker++ {
			wg.Add(1)
			go func() { defer wg.Done(); work(worker) }()
		}
		work(0)
		wg.Wait()
	} else {
		decrypt(0, 0, len(frames))
	}
	for i, nonce := range s.batchNonces[:len(frames)] {
		if errs[i] == nil {
			if s.seen[nonce%ReplayWindow] == nonce || s.highest >= ReplayWindow && nonce <= s.highest-ReplayWindow {
				errs[i] = ErrReplay
			} else {
				s.seen[nonce%ReplayWindow] = nonce
				s.highest = max(s.highest, nonce)
			}
		}
		if errs[i] != nil {
			frames[i] = nil
		}
	}
	return errs
}

const (
	// SubstreamTagSize is the AEAD tag overhead on an ordered substream record.
	SubstreamTagSize = 16
)

// SubstreamCipher encrypts and decrypts in-order records on one transport
// substream derived from a Session. One writer and one reader may operate
// concurrently without contending on the control Session's locks or replay window.
type SubstreamCipher struct {
	session *Session
	send    noise.Cipher
	recv    noise.Cipher
	sendAD  []byte
	recvAD  []byte
	sendSeq uint64
	recvSeq uint64
}

// NewSubstreamCipher derives independent directional AEAD keys for streamID.
func (s *Session) NewSubstreamCipher(streamID uint64) (*SubstreamCipher, error) {
	if !s.hasStreamRoots {
		return nil, errors.New("session does not support substream ciphers")
	}
	if time.Since(s.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	var idRaw [8]byte
	binary.BigEndian.PutUint64(idRaw[:], streamID)
	sk, err := hkdf.Key(sha256.New, s.sendStreamRoot[:], idRaw[:], "GraphNet/qstream/v1", 32)
	if err != nil {
		return nil, err
	}
	rk, err := hkdf.Key(sha256.New, s.recvStreamRoot[:], idRaw[:], "GraphNet/qstream/v1", 32)
	if err != nil {
		return nil, err
	}
	var sdk, rdk [32]byte
	copy(sdk[:], sk)
	copy(rdk[:], rk)
	fn := cipherFunction(s.suite)
	adLen := len(s.binding) + 16
	sendAD := make([]byte, adLen)
	recvAD := make([]byte, adLen)
	copy(sendAD, s.binding)
	copy(recvAD, s.binding)
	binary.BigEndian.PutUint64(sendAD[len(s.binding):], streamID)
	binary.BigEndian.PutUint64(recvAD[len(s.binding):], streamID)
	return &SubstreamCipher{
		session: s,
		send:    fn.Cipher(sdk),
		recv:    fn.Cipher(rdk),
		sendAD:  sendAD,
		recvAD:  recvAD,
	}, nil
}

// SealRecord appends [4-byte ciphertext length][AEAD(kind || body)] to dst.
// Callers serialize writes on one SubstreamCipher.
func (c *SubstreamCipher) SealRecord(dst []byte, kind byte, body []byte, plainScratch *[]byte) ([]byte, error) {
	plainLen := 1 + len(body)
	if plainLen > MaxPlaintext {
		return nil, errors.New("invalid substream record size")
	}
	if c.sendSeq >= MaxMessages-1 || time.Since(c.session.created) >= MaxSessionAge {
		return nil, ErrRekey
	}
	c.sendSeq++
	seq := c.sendSeq
	binary.BigEndian.PutUint64(c.sendAD[len(c.sendAD)-8:], seq)
	if cap(*plainScratch) < plainLen {
		*plainScratch = make([]byte, plainLen)
	}
	plain := (*plainScratch)[:plainLen]
	plain[0] = kind
	copy(plain[1:], body)
	cipherLen := plainLen + SubstreamTagSize
	dst = binary.BigEndian.AppendUint32(dst, uint32(cipherLen))
	return c.send.Encrypt(dst, seq, c.sendAD, plain), nil
}

// UndoSeal rolls back the last SealRecord sequence number when zero bytes of
// that record were written to the underlying stream before a deadline expired.
func (c *SubstreamCipher) UndoSeal() {
	if c.sendSeq > 0 {
		c.sendSeq--
	}
}

// OpenInPlace authenticates and decrypts frame in place, returning the record
// kind and body slice aliasing frame. Callers serialize reads on one SubstreamCipher.
func (c *SubstreamCipher) OpenInPlace(frame []byte) (byte, []byte, error) {
	if len(frame) < 1+SubstreamTagSize || len(frame) > MaxPlaintext+SubstreamTagSize {
		return 0, nil, errors.New("invalid substream ciphertext size")
	}
	if time.Since(c.session.created) >= MaxSessionAge {
		return 0, nil, ErrRekey
	}
	c.recvSeq++
	seq := c.recvSeq
	binary.BigEndian.PutUint64(c.recvAD[len(c.recvAD)-8:], seq)
	plain, err := c.recv.Decrypt(frame[:0], seq, c.recvAD, frame)
	if err != nil {
		return 0, nil, err
	}
	return plain[0], plain[1:], nil
}
