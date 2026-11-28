package peer

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/secure"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// Substream carries length-framed, AEAD-authenticated records on one ordered
// QUIC stream derived from an authenticated Channel's Noise session.
type Substream struct {
	raw      *transport.QUICSubstream
	cipher   *secure.SubstreamCipher
	reader   *bufio.Reader
	sendMu   sync.Mutex
	readMu   sync.Mutex
	sendBuf  []byte
	plainBuf []byte
}

func newSubstream(raw *transport.QUICSubstream, session *secure.Session) (*Substream, error) {
	cipher, err := session.NewSubstreamCipher(raw.StreamID())
	if err != nil {
		raw.Close()
		return nil, err
	}
	// Buffer at least one full maximum ciphertext frame so Peek never splits a
	// record across a read deadline expiration.
	bufSize := max(128*1024, 4+secure.MaxPlaintext+secure.SubstreamTagSize+1024)
	return &Substream{
		raw:    raw,
		cipher: cipher,
		reader: bufio.NewReaderSize(raw, bufSize),
	}, nil
}

func (s *Substream) StreamID() uint64 { return s.raw.StreamID() }

func (s *Substream) SetPriority(urgency int8, incremental bool) {
	s.raw.SetPriority(urgency, incremental)
}

func (s *Substream) SetReadDeadline(t time.Time) error  { return s.raw.SetReadDeadline(t) }
func (s *Substream) SetWriteDeadline(t time.Time) error { return s.raw.SetWriteDeadline(t) }
func (s *Substream) CloseWrite() error                  { return s.raw.CloseWrite() }
func (s *Substream) Cancel(code uint64)                 { s.raw.Cancel(code) }
func (s *Substream) Close() error                       { return s.raw.Close() }

// SendRecord encrypts and writes one record, reporting whether any byte of the
// framed record was written to the underlying stream before an error occurred.
func (s *Substream) SendRecord(kind byte, body []byte) (bool, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	out, err := s.cipher.SealRecord(s.sendBuf[:0], kind, body, &s.plainBuf)
	if err != nil {
		return false, err
	}
	s.sendBuf = out
	n, err := s.raw.Write(out)
	if err != nil && n == 0 {
		s.cipher.UndoSeal()
		return false, err
	}
	return n > 0, err
}

func (s *Substream) SendRecordBatch(kind byte, bodies [][]byte) error {
	if len(bodies) == 0 {
		return nil
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	out := s.sendBuf[:0]
	var err error
	for _, body := range bodies {
		out, err = s.cipher.SealRecord(out, kind, body, &s.plainBuf)
		if err != nil {
			return err
		}
	}
	s.sendBuf = out
	_, err = s.raw.Write(out)
	return err
}

func (s *Substream) ReceiveOwnedRecord() (byte, []byte, *packetbuf.Buffer, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	prefix, err := s.reader.Peek(4)
	if err != nil {
		return 0, nil, nil, err
	}
	size := int(binary.BigEndian.Uint32(prefix))
	if size < 1+secure.SubstreamTagSize || size > secure.MaxPlaintext+secure.SubstreamTagSize {
		return 0, nil, nil, errors.New("invalid substream frame size")
	}
	framed, err := s.reader.Peek(4 + size)
	if err != nil {
		return 0, nil, nil, err
	}
	buf := packetbuf.Get(size)
	copy(buf.Data, framed[4:4+size])
	_, _ = s.reader.Discard(4 + size)
	kind, body, err := s.cipher.OpenInPlace(buf.Data)
	if err != nil {
		buf.Release()
		return 0, nil, nil, err
	}
	buf.Data = buf.Data[:1+len(body)]
	return kind, body, buf, nil
}

// SubstreamErrorCode extracts the peer's QUIC stream reset/stop error code.
func SubstreamErrorCode(err error) (uint64, bool) {
	return transport.StreamErrorCode(err)
}

// SupportsSubstreams reports whether the underlying transport supports native
// multiplexed substreams.
func (c *Channel) SupportsSubstreams() bool {
	_, ok := c.conn.(*transport.QUIC)
	return ok
}

// OpenSubstream opens an authenticated, independently encrypted substream.
func (c *Channel) OpenSubstream(ctx context.Context, urgency int8, incremental bool) (*Substream, error) {
	q, ok := c.conn.(*transport.QUIC)
	if !ok {
		return nil, errors.New("transport does not support substreams")
	}
	raw, err := q.OpenSubstream(ctx, urgency, incremental)
	if err != nil {
		return nil, err
	}
	return newSubstream(raw, c.session)
}

// AcceptSubstream accepts a peer-opened authenticated substream.
func (c *Channel) AcceptSubstream(ctx context.Context) (*Substream, error) {
	q, ok := c.conn.(*transport.QUIC)
	if !ok {
		return nil, errors.New("transport does not support substreams")
	}
	raw, err := q.AcceptSubstream(ctx)
	if err != nil {
		return nil, err
	}
	return newSubstream(raw, c.session)
}
