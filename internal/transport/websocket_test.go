package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

// TestWebSocketFramingBatchAndTLS13X25519 verifies our zero-alloc RFC 6455 client
// interoperates with a standard third-party RFC 6455 server (coder/websocket)
// over both WS and WSS (TLS 1.3 + X25519) with batched binary frames.
func TestWebSocketFramingBatchAndTLS13X25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	serverTLS, err := PeerServerTLS(priv)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.NextProtos = []string{"http/1.1"}

	for _, kind := range []model.Transport{model.WS, model.WSS} {
		t.Run(string(kind), func(t *testing.T) {
			accepted := make(chan *Stream, 1)
			var negotiatedTLS tls.ConnectionState
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Sec-WebSocket-Protocol") != "" {
					t.Errorf("client sent unexpected subprotocol %q", r.Header.Get("Sec-WebSocket-Protocol"))
				}
				if r.TLS != nil {
					negotiatedTLS = *r.TLS
				}
				c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
					CompressionMode: websocket.CompressionDisabled,
				})
				if err != nil {
					return
				}
				c.SetReadLimit(4 << 20)
				accepted <- NewStream(websocket.NetConn(context.Background(), c, websocket.MessageBinary))
			})
			rawLN, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ln := rawLN
			if kind == model.WSS {
				ln = tls.NewListener(rawLN, serverTLS)
			}
			srv := &http.Server{Handler: handler}
			go srv.Serve(ln)
			t.Cleanup(func() { srv.Close() })

			ep := model.Endpoint{
				ID:        model.ID("00000000000000000000000000000001"),
				Transport: kind,
				Source:    model.Manual,
				URL:       string(kind) + "://" + rawLN.Addr().String() + "/peer",
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			clientWS, err := DialWebSocket(ctx, ep, 4, pub, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clientWS.Close()
			if clientWS.EndpointPath() != "/peer" {
				t.Fatalf("path = %q, want /peer", clientWS.EndpointPath())
			}
			serverStream := <-accepted
			defer serverStream.Close()

			if kind == model.WSS {
				if negotiatedTLS.Version != tls.VersionTLS13 {
					t.Fatalf("TLS version = %x, want TLS 1.3", negotiatedTLS.Version)
				}
				if negotiatedTLS.CurveID != tls.X25519 {
					t.Fatalf("TLS curve = %v, want X25519", negotiatedTLS.CurveID)
				}
			}

			// Verify bidirectional SendFramedBatch + ReceiveOwnedBatch interop with coder/websocket.
			m1 := bytes.Repeat([]byte("a"), 1200)
			m2 := bytes.Repeat([]byte("b"), 4096)
			var frames []byte
			frames = binary.BigEndian.AppendUint32(frames, uint32(len(m1)))
			frames = append(frames, m1...)
			frames = binary.BigEndian.AppendUint32(frames, uint32(len(m2)))
			frames = append(frames, m2...)

			if err := clientWS.SendFramedBatch(ctx, frames); err != nil {
				t.Fatal(err)
			}
			var got [][]byte
			for len(got) < 2 {
				batch, err := serverStream.ReceiveOwnedBatch(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, b := range batch {
					got = append(got, bytes.Clone(b.Data))
				}
				packetbuf.ReleaseAll(batch)
			}
			if !bytes.Equal(got[0], m1) || !bytes.Equal(got[1], m2) {
				t.Fatal("client->server batched WebSocket payload mismatch")
			}

			if err := serverStream.SendFramedBatch(ctx, frames); err != nil {
				t.Fatal(err)
			}
			got = got[:0]
			for len(got) < 2 {
				batch, err := clientWS.ReceiveOwnedBatch(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, b := range batch {
					got = append(got, bytes.Clone(b.Data))
				}
				packetbuf.ReleaseAll(batch)
			}
			if !bytes.Equal(got[0], m1) || !bytes.Equal(got[1], m2) {
				t.Fatal("server->client batched WebSocket payload mismatch")
			}
		})
	}
}
