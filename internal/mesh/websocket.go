package mesh

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/transport"
)

type wsRawConnKey struct{}

func requestedWebSocketKind(header string) (model.Transport, bool) {
	for _, part := range strings.Split(header, ",") {
		switch strings.TrimSpace(part) {
		case transport.WebSocketProtocol(model.WS):
			return model.WS, true
		case transport.WebSocketProtocol(model.WSS):
			return model.WSS, true
		}
	}
	return "", false
}

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
	kind, ok := requestedWebSocketKind(r.Header.Get("Sec-WebSocket-Protocol"))
	if !ok {
		http.Error(w, "unsupported peer subprotocol", http.StatusBadRequest)
		return
	}
	path := transport.WebSocketPath(r.URL)
	if !m.allowsEndpoint(kind, path) {
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
	proto := transport.WebSocketProtocol(kind)
	accept := transport.WebSocketAcceptKey(clientKey)
	resp := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
		accept, proto,
	)
	if _, err := brw.WriteString(resp); err != nil || brw.Flush() != nil {
		conn.Close()
		return
	}
	rawSock, _ := r.Context().Value(wsRawConnKey{}).(net.Conn)
	// WSS may terminate at a CDN or reverse proxy (optionally with mTLS origin
	// pull). The outer hop is never trusted as an Agent identity; the inner
	// Noise handshake still verifies graph membership.
	m.accept(transport.NewWebSocket(conn, brw.Reader, rawSock, local, remote, path, false), kind)
}
