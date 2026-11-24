// Package peer authenticates a configured graph edge over a message transport.
package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/secure"
	"github.com/eddiexyang/graphnet/internal/transport"
)

// Message kinds are at least 0x41, so that no datagram transport mistakes
// them for STUN.
const (
	helloKind          = 0x41
	replyKind          = 0x42
	dataKind           = 0x45
	handshakeTimeout   = 10 * time.Second
	retransmitInterval = 250 * time.Millisecond
)

// Channel carries authenticated plaintext messages after its handshake. It owns
// the transport connection. A single Receive loop must remain active to service
// retransmitted UDP handshake messages as well as application traffic.
type Channel struct {
	conn           transport.Conn
	session        *secure.Session
	sendMu         sync.Mutex
	sendBuffer     []byte
	opened         [128][]byte // a received batch's messages while they open
	unreliable     bool
	repeatRequest  []byte
	repeatResponse []byte
	ignore         [][]byte
}

func (c *Channel) ID() string         { return c.session.ID() }
func (c *Channel) NeedsRekey() bool   { return c.session.NeedsRekey() }
func (c *Channel) Created() time.Time { return c.session.Created() }
func (c *Channel) Close() error       { return c.conn.Close() }

// UseKernelWriteBacklog removes the packet carrier's unsent-byte bound when
// byte streams share this connection.
func (c *Channel) UseKernelWriteBacklog() error {
	if native, ok := c.conn.(interface{ UseKernelWriteBacklog() error }); ok {
		return native.UseKernelWriteBacklog()
	}
	return nil
}

// ReceiveWindow reports the kernel's receive buffer of the connection, when
// the transport is a kernel TCP socket.
func (c *Channel) ReceiveWindow() (int, bool) {
	if native, ok := c.conn.(interface{ ReceiveWindow() (int, bool) }); ok {
		return native.ReceiveWindow()
	}
	return 0, false
}
func (c *Channel) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Channel) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Resolve authorizes the exact incoming Network/Edge/Node tuple decrypted from
// Message 1 and returns its configured identities and cipher suite.
type Resolve func(secure.ClientHello) (secure.Config, error)

func Dial(parent context.Context, conn transport.Conn, config secure.Config) (channel *Channel, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(parent, handshakeTimeout)
	defer cancel()
	config.Initiator = true
	handshake, err := secure.NewHandshake(config)
	if err != nil {
		return nil, err
	}
	first, _, err := handshake.Write()
	if err != nil {
		return nil, err
	}
	request := append([]byte{helloKind}, first...)
	unreliable := isDatagram(conn)
	reply, err := exchange(ctx, conn, unreliable, request, replyKind, nil)
	if err != nil {
		return nil, err
	}
	session, err := handshake.Read(reply[1:])
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, errors.New("incomplete peer handshake")
	}
	markAuthenticated(conn)
	return &Channel{conn: conn, session: session, unreliable: unreliable, ignore: [][]byte{reply}}, nil
}

func Accept(parent context.Context, conn transport.Conn, kind model.Transport, identity ed25519.PrivateKey, replay *secure.ReplayFilter, resolve Resolve) (channel *Channel, err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(parent, handshakeTimeout)
	defer cancel()
	first, err := conn.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if len(first) <= 1 || len(first) > secure.MaxHandshake+1 || first[0] != helloKind {
		return nil, errors.New("invalid peer handshake initiation")
	}
	replyBody, session, err := secure.RespondHandshake(identity, first[1:], replay, func(hello secure.ClientHello) (secure.Config, error) {
		if hello.Transport != kind {
			return secure.Config{}, errors.New("hello transport does not match listener")
		}
		return resolve(hello)
	})
	if err != nil {
		return nil, err
	}
	reply := append([]byte{replyKind}, replyBody...)
	if err := conn.Send(ctx, reply); err != nil {
		return nil, err
	}
	unreliable := isDatagram(conn)
	markAuthenticated(conn)
	return &Channel{conn: conn, session: session, unreliable: unreliable, repeatRequest: first, repeatResponse: reply, ignore: [][]byte{first}}, nil
}

func exchange(ctx context.Context, conn transport.Conn, unreliable bool, out []byte, want byte, duplicate []byte) ([]byte, error) {
	if err := conn.Send(ctx, out); err != nil {
		return nil, err
	}
	for {
		readCtx := ctx
		cancel := func() {}
		if unreliable {
			readCtx, cancel = context.WithTimeout(ctx, retransmitInterval)
		}
		raw, err := conn.Receive(readCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if unreliable && errors.Is(err, context.DeadlineExceeded) {
				if err := conn.Send(ctx, out); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		if len(raw) > 1 && len(raw) <= secure.MaxHandshake+1 && raw[0] == want {
			return raw, nil
		}
		if unreliable && bytes.Equal(raw, duplicate) {
			if err := conn.Send(ctx, out); err != nil {
				return nil, err
			}
			continue
		}
		if unreliable {
			continue
		}
		return nil, errors.New("unexpected peer handshake message")
	}
}
func isDatagram(conn transport.Conn) bool {
	d, ok := conn.(interface{ Unreliable() bool })
	return ok && d.Unreliable()
}
func markAuthenticated(conn transport.Conn) {
	if d, ok := conn.(interface{ Authenticated() }); ok {
		d.Authenticated()
	}
}
func markAlive(conn transport.Conn) {
	if d, ok := conn.(interface{ Alive() }); ok {
		d.Alive()
	}
}

func (c *Channel) Send(ctx context.Context, payload []byte) error {
	return c.SendBatch(ctx, [][]byte{payload})
}

// SendBatch encrypts each message with its own nonce, retaining compatibility
// with peers that read one message at a time. Transports without batching fall
// back to individual sends under the same bounded operation context.
func (c *Channel) SendBatch(ctx context.Context, payloads [][]byte) error {
	if len(payloads) == 0 || len(payloads) > 128 {
		return errors.New("invalid peer batch size")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	framed, canFrame := c.conn.(interface {
		SendFramedBatch(context.Context, []byte) error
	})
	headroom := 0
	if canFrame {
		headroom = 4 // Existing stream transport length prefix.
	}
	needed := 0
	for _, payload := range payloads {
		if len(payload) == 0 || len(payload) > secure.MaxPlaintext {
			return errors.New("invalid peer message size")
		}
		needed += headroom + 1 + secure.Overhead + len(payload)
	}
	if cap(c.sendBuffer) < needed {
		c.sendBuffer = make([]byte, needed)
	}
	c.sendBuffer = c.sendBuffer[:needed]
	var messages [128][]byte
	offset := 0
	for i, payload := range payloads {
		head := 1 + secure.Overhead + len(payload)
		end := offset + headroom + head
		if headroom != 0 {
			binary.BigEndian.PutUint32(c.sendBuffer[offset:], uint32(head))
			offset += headroom
		}
		c.sendBuffer[offset] = dataKind
		messages[i] = c.sendBuffer[offset : offset+1 : end]
		offset = end
	}
	c.sendBuffer = c.sendBuffer[:offset]
	if err := c.session.SealBatchAppend(messages[:len(payloads)], payloads); err != nil {
		return err
	}
	if headroom != 0 {
		// Prefixes and independently authenticated records already occupy
		// one contiguous allocation.
		return framed.SendFramedBatch(ctx, c.sendBuffer)
	}
	if batch, ok := c.conn.(interface {
		SendBatch(context.Context, [][]byte) error
	}); ok {
		return batch.SendBatch(ctx, messages[:len(payloads)])
	}
	for _, message := range messages[:len(payloads)] {
		if err := c.conn.Send(ctx, message); err != nil {
			return err
		}
	}
	return nil
}
func (c *Channel) Receive(ctx context.Context) ([]byte, error) {
	for {
		raw, err := c.conn.Receive(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := c.decode(ctx, raw)
		if err != nil || plain != nil {
			return plain, err
		}
	}
}
func (c *Channel) ReceiveBatch(ctx context.Context) ([][]byte, error) {
	batch, ok := c.conn.(interface {
		ReceiveBatch(context.Context) ([][]byte, error)
	})
	if !ok {
		raw, err := c.Receive(ctx)
		if err != nil {
			return nil, err
		}
		return [][]byte{raw}, nil
	}
	return c.decodeBatches(ctx, batch.ReceiveBatch)
}

func (c *Channel) decodeBatches(ctx context.Context, receive func(context.Context) ([][]byte, error)) ([][]byte, error) {
	for {
		messages, err := receive(ctx)
		if err != nil {
			return nil, err
		}
		allEncrypted := len(messages) > 1 && len(messages) <= len(c.opened)
		for _, raw := range messages {
			if !encrypted(raw) {
				allEncrypted = false
				break
			}
		}
		if allEncrypted {
			raws := c.opened[:len(messages)]
			copy(raws, messages)
			for i, raw := range raws {
				messages[i] = raw[1:]
			}
			errs := c.session.OpenBatchInPlace(messages)
			count := 0
			for i, err := range errs {
				if err != nil {
					if errors.Is(err, secure.ErrReplay) || c.unreliable && !errors.Is(err, secure.ErrRekey) {
						continue
					}
					clear(raws)
					return nil, err
				}
				messages[count] = messages[i]
				count++
			}
			clear(raws)
			clear(messages[count:])
			if count > 0 {
				markAlive(c.conn)
				return messages[:count], nil
			}
			continue
		}
		count := 0
		for _, raw := range messages {
			plain, err := c.decode(ctx, raw)
			if err != nil {
				return nil, err
			}
			if plain != nil {
				messages[count] = plain
				count++
			}
		}
		clear(messages[count:])
		if count > 0 {
			return messages[:count], nil
		}
	}
}

// encrypted reports a data message.
func encrypted(raw []byte) bool { return len(raw) > 1 && raw[0] == dataKind }

func (c *Channel) decode(ctx context.Context, raw []byte) ([]byte, error) {
	if encrypted(raw) {
		plaintext, err := c.session.OpenInPlace(raw[1:])
		if err != nil {
			if errors.Is(err, secure.ErrReplay) || c.unreliable && !errors.Is(err, secure.ErrRekey) {
				return nil, nil
			}
			return nil, err
		}
		markAlive(c.conn)
		return plaintext, nil
	}
	if c.unreliable {
		if bytes.Equal(raw, c.repeatRequest) {
			if err := c.conn.Send(ctx, c.repeatResponse); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	for _, message := range c.ignore {
		if bytes.Equal(raw, message) {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unexpected peer channel message")
}

// ReceiveOwnedBatch carries storage ownership through authentication and into
// forwarding. Rejected/control frames are released here; accepted buffers remain
// owned by the caller until delivery (or queue drop) completes.
func (c *Channel) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	for {
		var buffers []*packetbuf.Buffer
		var err error
		if receiver, ok := c.conn.(interface {
			ReceiveOwnedBatch(context.Context) ([]*packetbuf.Buffer, error)
		}); ok {
			buffers, err = receiver.ReceiveOwnedBatch(ctx)
		} else {
			var raw []byte
			raw, err = c.conn.Receive(ctx)
			if err == nil {
				buffers = []*packetbuf.Buffer{packetbuf.Wrap(raw)}
			}
		}
		if err != nil {
			packetbuf.ReleaseAll(buffers)
			return nil, err
		}
		allEncrypted := len(buffers) > 1
		for _, b := range buffers {
			if !encrypted(b.Data) {
				allEncrypted = false
				break
			}
		}
		if allEncrypted {
			frames := make([][]byte, len(buffers))
			for i, b := range buffers {
				frames[i] = b.Data[1:]
			}
			errs := c.session.OpenBatchInPlace(frames)
			for i, decodeErr := range errs {
				buffers[i].Data = frames[i]
				if decodeErr != nil && !errors.Is(decodeErr, secure.ErrReplay) && !(c.unreliable && !errors.Is(decodeErr, secure.ErrRekey)) {
					err = decodeErr
				}
			}
		} else {
			for _, b := range buffers {
				b.Data, err = c.decode(ctx, b.Data)
				if err != nil {
					break
				}
			}
		}
		if err != nil {
			packetbuf.ReleaseAll(buffers)
			return nil, err
		}
		count := 0
		for _, b := range buffers {
			if b.Data == nil {
				b.Release()
				continue
			}
			buffers[count] = b
			count++
		}
		clear(buffers[count:])
		if count > 0 {
			markAlive(c.conn)
			return buffers[:count], nil
		}
	}
}
