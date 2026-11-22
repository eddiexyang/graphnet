package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

const (
	wsGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsBufSize    = 64 * 1024
	wsOpCont     = 0x0
	wsOpBinary   = 0x2
	wsOpClose    = 0x8
	wsOpPing     = 0x9
	wsOpPong     = 0xa
	wsMaxControl = 125
)

// WebSocketAcceptKey computes the RFC 6455 Sec-WebSocket-Accept header value.
func WebSocketAcceptKey(clientKey string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(strings.TrimSpace(clientKey)))
	_, _ = h.Write([]byte(wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsFrameConn implements a zero-allocation steady-state RFC 6455 binary
// WebSocket byte stream directly over a net.Conn (TCP or TLS) with 64 KiB
// buffered I/O and word-wide XOR masking.
type wsFrameConn struct {
	conn       net.Conn
	br         *bufio.Reader
	bw         *bufio.Writer
	clientMask bool

	readMu     sync.Mutex
	rem        int64
	readMasked bool
	readKey    [4]byte
	readPos    int
	inBinary   bool

	writeMu  sync.Mutex
	maskBuf  []byte
	randPool [4096]byte
	randPos  int
	closed   bool
}

func newWSFrameConn(conn net.Conn, br *bufio.Reader, clientMask bool) *wsFrameConn {
	if br == nil || br.Size() < wsBufSize {
		br = bufio.NewReaderSize(conn, wsBufSize)
	}
	return &wsFrameConn{
		conn:       conn,
		br:         br,
		bw:         bufio.NewWriterSize(conn, wsBufSize),
		clientMask: clientMask,
		randPos:    len([4096]byte{}),
	}
}

func (c *wsFrameConn) nextMaskKey() ([4]byte, error) {
	if c.randPos+4 > len(c.randPool) {
		if _, err := io.ReadFull(rand.Reader, c.randPool[:]); err != nil {
			return [4]byte{}, err
		}
		c.randPos = 0
	}
	var key [4]byte
	copy(key[:], c.randPool[c.randPos:c.randPos+4])
	c.randPos += 4
	return key, nil
}

// maskBytes XORs src into dst starting at mask offset pos, returning the updated pos.
// dst and src may alias (in-place unmasking) or be disjoint (client masking).
func maskBytes(dst, src []byte, key [4]byte, pos int) int {
	n := len(src)
	i := 0
	for i < n && pos != 0 {
		dst[i] = src[i] ^ key[pos]
		pos = (pos + 1) & 3
		i++
	}
	if n-i >= 8 {
		k32 := binary.LittleEndian.Uint32(key[:])
		k64 := uint64(k32) | (uint64(k32) << 32)
		for i+8 <= n {
			v := binary.LittleEndian.Uint64(src[i:]) ^ k64
			binary.LittleEndian.PutUint64(dst[i:], v)
			i += 8
		}
	}
	for i < n {
		dst[i] = src[i] ^ key[pos]
		pos = (pos + 1) & 3
		i++
	}
	return pos
}

func (c *wsFrameConn) writeFrameLocked(opcode byte, payload []byte) error {
	if c.closed {
		return net.ErrClosed
	}
	var hdr [14]byte
	hdr[0] = 0x80 | opcode
	hlen := 2
	n := len(payload)
	switch {
	case n <= 125:
		hdr[1] = byte(n)
	case n <= 65535:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	if c.clientMask {
		key, err := c.nextMaskKey()
		if err != nil {
			return err
		}
		hdr[1] |= 0x80
		copy(hdr[hlen:hlen+4], key[:])
		hlen += 4
		if _, err := c.bw.Write(hdr[:hlen]); err != nil {
			return err
		}
		if n > 0 {
			if cap(c.maskBuf) < n {
				c.maskBuf = make([]byte, n)
			}
			out := c.maskBuf[:n]
			maskBytes(out, payload, key, 0)
			if _, err := c.bw.Write(out); err != nil {
				return err
			}
		}
		return c.bw.Flush()
	}
	if _, err := c.bw.Write(hdr[:hlen]); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func (c *wsFrameConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.writeFrameLocked(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsFrameConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.rem == 0 {
		var h2 [2]byte
		if _, err := io.ReadFull(c.br, h2[:]); err != nil {
			return 0, err
		}
		fin := h2[0]&0x80 != 0
		rsv := h2[0] & 0x70
		if rsv != 0 {
			return 0, errors.New("websocket: non-zero RSV bits")
		}
		opcode := h2[0] & 0x0f
		masked := h2[1]&0x80 != 0
		// RFC 6455: server requires masked client frames; client requires unmasked server frames.
		if masked == c.clientMask {
			return 0, errors.New("websocket: invalid mask bit")
		}
		plen := int64(h2[1] & 0x7f)
		switch plen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, err
			}
			plen = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return 0, err
			}
			v := binary.BigEndian.Uint64(ext[:])
			if v&(1<<63) != 0 || v > 64<<20 {
				return 0, errors.New("websocket: frame too large")
			}
			plen = int64(v)
		}
		var key [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, key[:]); err != nil {
				return 0, err
			}
		}
		// Control frames (opcode >= 8)
		if opcode >= 0x8 {
			if !fin || plen > wsMaxControl {
				return 0, errors.New("websocket: invalid control frame")
			}
			var ctrl [wsMaxControl]byte
			if plen > 0 {
				if _, err := io.ReadFull(c.br, ctrl[:plen]); err != nil {
					return 0, err
				}
				if masked {
					maskBytes(ctrl[:plen], ctrl[:plen], key, 0)
				}
			}
			switch opcode {
			case wsOpClose:
				return 0, io.EOF
			case wsOpPing:
				c.writeMu.Lock()
				_ = c.writeFrameLocked(wsOpPong, ctrl[:plen])
				c.writeMu.Unlock()
			case wsOpPong:
			default:
				return 0, fmt.Errorf("websocket: unsupported control opcode %d", opcode)
			}
			continue
		}
		switch opcode {
		case wsOpBinary:
			if c.inBinary {
				return 0, errors.New("websocket: interleaved data frame")
			}
			c.inBinary = !fin
		case wsOpCont:
			if !c.inBinary {
				return 0, errors.New("websocket: unexpected continuation frame")
			}
			if fin {
				c.inBinary = false
			}
		default:
			return 0, fmt.Errorf("websocket: expected binary frame, got opcode %d", opcode)
		}
		c.rem = plen
		c.readMasked = masked
		c.readKey = key
		c.readPos = 0
	}
	want := len(p)
	if int64(want) > c.rem {
		want = int(c.rem)
	}
	n, err := c.br.Read(p[:want])
	if n > 0 {
		if c.readMasked {
			c.readPos = maskBytes(p[:n], p[:n], c.readKey, c.readPos)
		}
		c.rem -= int64(n)
	}
	return n, err
}

func (c *wsFrameConn) Close() error {
	c.writeMu.Lock()
	c.closed = true
	c.writeMu.Unlock()
	return c.conn.Close()
}
func (c *wsFrameConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *wsFrameConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *wsFrameConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *wsFrameConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *wsFrameConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// WebSocket carries GraphNet length-framed encrypted messages as a byte stream
// inside RFC 6455 binary WebSocket frames with zero steady-state allocations.
type WebSocket struct {
	frameConn     *wsFrameConn
	socket        net.Conn
	stream        *Stream
	local, remote net.Addr
	path          string
	closeOnce     sync.Once
}

func NewWebSocket(conn net.Conn, br *bufio.Reader, socket net.Conn, local, remote net.Addr, path string, clientMask bool) *WebSocket {
	fc := newWSFrameConn(conn, br, clientMask)
	return &WebSocket{
		frameConn: fc,
		socket:    socket,
		stream:    NewStream(fc),
		local:     local,
		remote:    remote,
		path:      path,
	}
}

func (w *WebSocket) LocalAddr() net.Addr  { return w.local }
func (w *WebSocket) RemoteAddr() net.Addr { return w.remote }
func (w *WebSocket) EndpointPath() string { return w.path }

func (w *WebSocket) Close() error {
	var err error
	w.closeOnce.Do(func() {
		err = w.frameConn.Close()
	})
	return err
}

func (w *WebSocket) UseKernelWriteBacklog() error {
	if w.socket == nil {
		return nil
	}
	if wrapper, ok := w.socket.(interface{ UseKernelWriteBacklog() error }); ok {
		return wrapper.UseKernelWriteBacklog()
	}
	return UseKernelTCPBacklog(w.socket)
}

// ReceiveWindow returns false for WebSocket links: behind a CDN or reverse proxy
// the local TCP socket terminates at the proxy hop (low RTT, small kernel buffer)
// rather than the remote peer, so mux uses its configured end-to-end window instead.
func (w *WebSocket) ReceiveWindow() (int, bool) {
	return 0, false
}

func (w *WebSocket) Send(ctx context.Context, raw []byte) error {
	return w.stream.Send(ctx, raw)
}

func (w *WebSocket) SendBatch(ctx context.Context, packets [][]byte) error {
	return w.stream.SendBatch(ctx, packets)
}

func (w *WebSocket) SendFramedBatch(ctx context.Context, frames []byte) error {
	return w.stream.SendFramedBatch(ctx, frames)
}

func (w *WebSocket) SendFramedParts(ctx context.Context, parts [][]byte, frames int) error {
	return w.stream.SendFramedParts(ctx, parts, frames)
}

func (w *WebSocket) Receive(ctx context.Context) ([]byte, error) {
	return w.stream.Receive(ctx)
}

func (w *WebSocket) ReceiveBatch(ctx context.Context) ([][]byte, error) {
	return w.stream.ReceiveBatch(ctx)
}

func (w *WebSocket) ReceiveOwnedBatch(ctx context.Context) ([]*packetbuf.Buffer, error) {
	return w.stream.ReceiveOwnedBatch(ctx)
}

func WebSocketProtocol(kind model.Transport) string { return "graphnet." + string(kind) + ".v1" }

func WebSocketPath(u *url.URL) string {
	if u == nil || u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

// DialWebSocket disables redirects and environment HTTP proxies, and fixes the
// configured IPv4/IPv6 candidate family at the actual socket dial. RootCAs nil
// uses system roots for public TLS proxies/CDNs; direct Agents use the identity pin.
func DialWebSocket(ctx context.Context, endpoint model.Endpoint, family int, identity ed25519.PublicKey, roots *x509.CertPool) (*WebSocket, error) {
	return DialWebSocketAt(ctx, endpoint, family, identity, roots, netip.Addr{})
}

func headerContainsToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// DialWebSocketAt performs a direct RFC 6455 HTTP/1.1 Upgrade over TCP or TLS 1.3 (X25519)
// and hands the raw socket directly to wsFrameConn (64 KiB buffered, zero-alloc masking).
func DialWebSocketAt(ctx context.Context, endpoint model.Endpoint, family int, identity ed25519.PublicKey, roots *x509.CertPool, target netip.Addr) (*WebSocket, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	if (endpoint.Transport != model.WS && endpoint.Transport != model.WSS) || (family != 4 && family != 6) {
		return nil, errors.New("invalid WebSocket candidate")
	}
	parsed, _ := url.Parse(endpoint.URL)
	dialAddress, err := EndpointDialAddress(endpoint, family, target)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	socket, err := DialTCP(ctx, dialer, "tcp"+strconv.Itoa(family), dialAddress)
	if err != nil {
		return nil, err
	}
	var conn net.Conn = socket
	if endpoint.Transport == model.WSS {
		tlsCfg := PeerClientTLS(parsed.Hostname(), identity, roots)
		tlsCfg.NextProtos = []string{"http/1.1"}
		tlsConn := tls.Client(socket, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			socket.Close()
			return nil, err
		}
		conn = tlsConn
	}

	cleanup, err := deadline(ctx, conn.SetDeadline)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var keyRaw [16]byte
	if _, err := io.ReadFull(rand.Reader, keyRaw[:]); err != nil {
		cleanup()
		conn.Close()
		return nil, err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyRaw[:])
	protocol := WebSocketProtocol(endpoint.Transport)
	path := WebSocketPath(parsed)

	reqText := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
		path, parsed.Host, wsKey, protocol,
	)
	if err := writeFull(conn, []byte(reqText)); err != nil {
		cleanup()
		conn.Close()
		return nil, ctxError(ctx, err)
	}

	br := bufio.NewReaderSize(conn, wsBufSize)
	req := &http.Request{Method: http.MethodGet, URL: parsed}
	resp, err := http.ReadResponse(br, req)
	cleanup()
	if err != nil {
		conn.Close()
		return nil, ctxError(ctx, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		if resp.Body != nil {
			resp.Body.Close()
		}
		conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: status %d", resp.StatusCode)
	}
	if !headerContainsToken(resp.Header, "Upgrade", "websocket") ||
		!headerContainsToken(resp.Header, "Connection", "upgrade") ||
		resp.Header.Get("Sec-WebSocket-Accept") != WebSocketAcceptKey(wsKey) ||
		resp.Header.Get("Sec-WebSocket-Protocol") != protocol {
		conn.Close()
		return nil, errors.New("invalid WebSocket upgrade response")
	}
	return NewWebSocket(conn, br, socket, socket.LocalAddr(), socket.RemoteAddr(), path, true), nil
}
