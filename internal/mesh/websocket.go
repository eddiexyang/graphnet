package mesh

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/transport"
)

type wsRawConnKey struct{}
type wsTLSStateKey struct{}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func (m *Mesh) acceptWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Origin") != "" {
		http.Error(w, "peer WebSocket upgrade required", http.StatusBadRequest)
		return
	}
	if !headerHasToken(r.Header, "Upgrade", "websocket") ||
		!headerHasToken(r.Header, "Connection", "upgrade") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "invalid WebSocket upgrade headers", http.StatusBadRequest)
		return
	}
	clientKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if clientKey == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	path := transport.WebSocketPath(r.URL)
	tlsState := r.TLS
	if tlsState == nil {
		tlsState, _ = r.Context().Value(wsTLSStateKey{}).(*tls.ConnectionState)
	}
	var kind model.Transport
	if tlsState != nil {
		if m.requireOriginMTLS && len(tlsState.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		if !m.allowsEndpoint(model.WSS, path) {
			http.NotFound(w, r)
			return
		}
		kind = model.WSS
	} else if m.requireOriginMTLS {
		if !m.allowsEndpoint(model.WS, path) {
			http.Error(w, "origin mTLS required", http.StatusForbidden)
			return
		}
		kind = model.WS
	} else if !m.allowsEndpoint(model.WS, path) && !m.allowsEndpoint(model.WSS, path) {
		http.NotFound(w, r)
		return
	}
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		return
	}
	rc := http.NewResponseController(w)
	if rc.SetReadDeadline(time.Time{}) != nil || rc.SetWriteDeadline(time.Time{}) != nil {
		return
	}
	conn, brw, err := rc.Hijack()
	if err != nil {
		return
	}
	accept := transport.WebSocketAcceptKey(clientKey)
	resp := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	)
	if _, err := brw.WriteString(resp); err != nil || brw.Flush() != nil {
		conn.Close()
		return
	}
	rawSock, _ := r.Context().Value(wsRawConnKey{}).(net.Conn)
	// WSS may terminate at a CDN or reverse proxy (optionally with mTLS origin
	// pull). No subprotocol is negotiated; the encrypted Noise IK Message 1
	// specifies WS vs WSS and binds it to the configured endpoint policy.
	m.accept(transport.NewWebSocket(conn, brw.Reader, rawSock, local, remote, path, false), kind)
}
