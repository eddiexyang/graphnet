package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"golang.org/x/crypto/chacha20"
)

// Stream adapts TCP, TLS and other net.Conn streams to complete messages. One
// reader and one writer may operate concurrently. Writes cannot interleave.
// An I/O error closes the stream because a partial frame cannot be resumed safely.
type Stream struct {
	conn         net.Conn
	sendMu       sync.Mutex
	readMu       sync.Mutex
	reader       *bufio.Reader
	writeBuffer  []byte
	prefixes     [128 * 4]byte
	gather       [256][]byte
	writeBuffers func(net.Buffers) (int64, error)

	keyMu          sync.Mutex
	sendHPSet      bool
	sendHP         [32]byte
	recvHPSet      bool
	recvHP         [32]byte
	sendCipher     *chacha20.Cipher
	recvCipher     *chacha20.Cipher
	hasPendingSize bool
	pendingSize    uint32
}

func NewStream(conn net.Conn) *Stream {
	s := &Stream{conn: conn, reader: bufio.NewReaderSize(conn, 64*1024)}
	if tcp, ok := conn.(*net.TCPConn); ok {
		s.writeBuffers = func(parts net.Buffers) (int64, error) { return parts.WriteTo(tcp) }
	} else if writer, ok := conn.(interface {
		WriteBuffers(net.Buffers) (int64, error)
	}); ok {
		s.writeBuffers = writer.WriteBuffers
	}
	return s
}

func (s *Stream) SetLocalPublicKey(pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	hp := HeaderProtectionKey(pub)
	s.keyMu.Lock()
	s.recvHP = hp
	s.recvHPSet = true
	s.keyMu.Unlock()
}

func (s *Stream) SetPeerPublicKey(pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	hp := HeaderProtectionKey(pub)
	s.keyMu.Lock()
	s.sendHP = hp
	s.sendHPSet = true
	s.keyMu.Unlock()
}

func (s *Stream) loadSendHP() ([32]byte, bool) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.sendHP, s.sendHPSet
}

func (s *Stream) loadRecvHP() ([32]byte, bool) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.recvHP, s.recvHPSet
}

func (s *Stream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }
func (s *Stream) Close() error         { return s.conn.Close() }

func (s *Stream) UseKernelWriteBacklog() error {
	if wrapper, ok := s.conn.(interface{ UseKernelWriteBacklog() error }); ok {
		return wrapper.UseKernelWriteBacklog()
	}
	return UseKernelTCPBacklog(s.conn)
}

func (s *Stream) ReceiveWindow() (int, bool) {
	if wrapper, ok := s.conn.(interface{ ReceiveWindow() (int, bool) }); ok {
		return wrapper.ReceiveWindow()
	}
	return TCPReceiveWindow(s.conn)
}

func (s *Stream) Send(ctx context.Context, data []byte) error {
	return s.SendBatch(ctx, [][]byte{data})
}

func (s *Stream) ensureSendCipherLocked(hpKey [32]byte) ([]byte, error) {
	if s.sendCipher != nil {
		return nil, nil
	}
	salt, err := drawStreamSalt()
	if err != nil {
		return nil, err
	}
	s.sendCipher = newHPCipher(hpKey, salt[:])
	return salt[:], nil
}

// maskFrameInPlace masks the 4-byte big-endian length prefix, the 1-byte kind,
// and (for data frames with a 4-byte sequence counter) the 4-byte counter.
func (s *Stream) maskFrameInPlace(frame []byte) {
	n := 5
	if len(frame) >= 9 && frame[4] == dataFrameKind {
		n = 9
	}
	s.sendCipher.XORKeyStream(frame[:n], frame[:n])
}

func (s *Stream) SendFramedBatch(ctx context.Context, frames []byte) (err error) {
	count := 0
	for offset := 0; offset < len(frames); {
		if len(frames)-offset < 4 {
			return errors.New("truncated transport frame prefix")
		}
		size := int(binary.BigEndian.Uint32(frames[offset:]))
		if size == 0 || size > MaxMessage || size > len(frames)-offset-4 {
			return errors.New("invalid transport frame size")
		}
		count++
		if count > 128 {
			return errors.New("invalid transport batch size")
		}
		offset += 4 + size
	}
	if count == 0 {
		return errors.New("empty transport frame batch")
	}
	hpKey, hpSet := s.loadSendHP()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	cleanup, err := deadline(ctx, s.conn.SetWriteDeadline)
	if err != nil {
		return err
	}
	defer cleanup()
	if !hpSet {
		err = ctxError(ctx, writeFull(s.conn, frames))
		if err != nil {
			s.conn.Close()
		}
		return err
	}
	salt, err := s.ensureSendCipherLocked(hpKey)
	if err != nil {
		s.conn.Close()
		return err
	}
	total := len(salt) + len(frames)
	if cap(s.writeBuffer) < total {
		s.writeBuffer = make([]byte, total)
	}
	out := s.writeBuffer[:total]
	copy(out, salt)
	body := out[len(salt):]
	copy(body, frames)
	for offset := 0; offset < len(body); {
		size := int(binary.BigEndian.Uint32(body[offset:]))
		s.maskFrameInPlace(body[offset : offset+4+size])
		offset += 4 + size
	}
	err = ctxError(ctx, writeFull(s.conn, out))
	if err != nil {
		s.conn.Close()
	}
	return err
}

func (s *Stream) SendFramedParts(ctx context.Context, parts [][]byte, frames int) (err error) {
	if frames == 0 || frames > 128 || len(parts) == 0 {
		return errors.New("invalid transport batch size")
	}
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	hpKey, hpSet := s.loadSendHP()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	cleanup, err := deadline(ctx, s.conn.SetWriteDeadline)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() {
		if err != nil {
			s.conn.Close()
		}
	}()
	if !hpSet && s.writeBuffers != nil {
		n, writeErr := s.writeBuffers(net.Buffers(parts))
		if writeErr == nil && n != int64(size) {
			writeErr = io.ErrShortWrite
		}
		return ctxError(ctx, writeErr)
	}
	var salt []byte
	if hpSet {
		salt, err = s.ensureSendCipherLocked(hpKey)
		if err != nil {
			return err
		}
	}
	total := len(salt) + size
	if cap(s.writeBuffer) < total {
		s.writeBuffer = make([]byte, total)
	}
	out := s.writeBuffer[:0]
	out = append(out, salt...)
	for _, part := range parts {
		out = append(out, part...)
	}
	if hpSet {
		body := out[len(salt):]
		for offset := 0; offset < len(body); {
			if len(body)-offset < 4 {
				return errors.New("truncated transport frame prefix")
			}
			fSize := int(binary.BigEndian.Uint32(body[offset:]))
			if fSize == 0 || fSize > MaxMessage || fSize > len(body)-offset-4 {
				return errors.New("invalid transport frame size")
			}
			s.maskFrameInPlace(body[offset : offset+4+fSize])
			offset += 4 + fSize
		}
	}
	return ctxError(ctx, writeFull(s.conn, out))
}

func (s *Stream) SendBatch(ctx context.Context, messages [][]byte) (err error) {
	if len(messages) == 0 || len(messages) > 128 {
		return errors.New("invalid transport batch size")
	}
	size := 0
	for _, data := range messages {
		if len(data) == 0 || len(data) > MaxMessage {
			return errors.New("invalid transport message size")
		}
		size += 4 + len(data)
	}
	hpKey, hpSet := s.loadSendHP()
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	cleanup, err := deadline(ctx, s.conn.SetWriteDeadline)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() {
		if err != nil {
			s.conn.Close()
		}
	}()
	if !hpSet && s.writeBuffers != nil {
		parts := s.gather[:2*len(messages)]
		for i, data := range messages {
			prefix := s.prefixes[i*4 : i*4+4]
			binary.BigEndian.PutUint32(prefix, uint32(len(data)))
			parts[2*i], parts[2*i+1] = prefix, data
		}
		vectors := net.Buffers(parts)
		n, writeErr := s.writeBuffers(vectors)
		clear(s.gather[:2*len(messages)])
		if writeErr == nil && n != int64(size) {
			writeErr = io.ErrShortWrite
		}
		return ctxError(ctx, writeErr)
	}
	var salt []byte
	if hpSet {
		salt, err = s.ensureSendCipherLocked(hpKey)
		if err != nil {
			return err
		}
	}
	total := len(salt) + size
	if cap(s.writeBuffer) < total {
		s.writeBuffer = make([]byte, total)
	}
	frame := s.writeBuffer[:total]
	copy(frame, salt)
	offset := len(salt)
	for _, data := range messages {
		binary.BigEndian.PutUint32(frame[offset:], uint32(len(data)))
		copy(frame[offset+4:], data)
		if hpSet {
			s.maskFrameInPlace(frame[offset : offset+4+len(data)])
		}
		offset += 4 + len(data)
	}
	return ctxError(ctx, writeFull(s.conn, frame))
}

func (s *Stream) Receive(ctx context.Context) ([]byte, error) {
	messages, err := s.receive(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer packetbuf.ReleaseAll(messages)
	return append([]byte(nil), messages[0].Data...), nil
}

func (s *Stream) ReceiveBatch(ctx context.Context) ([][]byte, error) {
	messages, err := s.ReceiveOwnedBatch(ctx)
	if err != nil {
		return nil, err
	}
	defer packetbuf.ReleaseAll(messages)
	out := make([][]byte, len(messages))
	for i, b := range messages {
		out[i] = append([]byte(nil), b.Data...)
	}
	return out, nil
}

func (s *Stream) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	return s.receive(ctx, 32)
}

func (s *Stream) receive(ctx context.Context, limit int) (out []*packetbuf.Buffer, err error) {
	hpKey, hpSet := s.loadRecvHP()
	s.readMu.Lock()
	defer s.readMu.Unlock()
	cleanup, err := deadline(ctx, s.conn.SetReadDeadline)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	defer func() {
		if err != nil {
			s.conn.Close()
		}
	}()
	if hpSet && s.recvCipher == nil {
		var salt [hpSaltSize]byte
		if _, err := io.ReadFull(s.reader, salt[:]); err != nil {
			return nil, ctxError(ctx, err)
		}
		s.recvCipher = newHPCipher(hpKey, salt[:])
	}
	out = make([]*packetbuf.Buffer, 0, limit)
	owned := out
	defer func() {
		if err != nil {
			packetbuf.ReleaseAll(owned)
		}
	}()
	for len(out) < limit {
		if !s.hasPendingSize {
			if len(out) > 0 && s.reader.Buffered() < 4 {
				break
			}
			var prefix [4]byte
			if _, err := io.ReadFull(s.reader, prefix[:]); err != nil {
				return nil, ctxError(ctx, err)
			}
			if s.recvCipher != nil {
				s.recvCipher.XORKeyStream(prefix[:], prefix[:])
			}
			size := binary.BigEndian.Uint32(prefix[:])
			if size == 0 || size > MaxMessage {
				return nil, fmt.Errorf("invalid transport frame size %d", size)
			}
			s.pendingSize = size
			s.hasPendingSize = true
		}
		if len(out) > 0 && s.reader.Buffered() < int(s.pendingSize) {
			break
		}
		size := int(s.pendingSize)
		s.hasPendingSize = false
		data := packetbuf.Get(size)
		out = append(out, data)
		owned = out
		if _, err := io.ReadFull(s.reader, data.Data); err != nil {
			return nil, ctxError(ctx, err)
		}
		if s.recvCipher != nil {
			s.recvCipher.XORKeyStream(data.Data[:1], data.Data[:1])
			if data.Data[0] == dataFrameKind && len(data.Data) >= 5 {
				s.recvCipher.XORKeyStream(data.Data[1:5], data.Data[1:5])
			}
		}
	}
	return out, nil
}

func deadline(ctx context.Context, set func(time.Time) error) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit, _ := ctx.Deadline()
	if err := set(limit); err != nil {
		return nil, err
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { set(time.Now()); close(finished) })
	return func() {
		if !stop() {
			<-finished
		}
		set(time.Time{})
	}, nil
}

func ctxError(ctx context.Context, err error) error {
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return cause
		}
		var timeout net.Error
		if limit, ok := ctx.Deadline(); ok && !time.Now().Before(limit) && errors.As(err, &timeout) && timeout.Timeout() {
			return context.DeadlineExceeded
		}
	}
	return err
}

func writeFull(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if n < 0 || n > len(buf) {
			return io.ErrShortWrite
		}
		buf = buf[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
