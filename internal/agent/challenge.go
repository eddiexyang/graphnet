package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/eddiexyang/graphnet/internal/model"
)

// challengeSigner authenticates an Agent registered by public key inside the
// controller TLS session, where no client certificate was issued.
type challengeSigner struct {
	base http.RoundTripper
	id   model.ID
	key  ed25519.PrivateKey
	// byKey identifies the Agent by public key, before it knows its ID.
	byKey bool
}

func (s *challengeSigner) RoundTrip(req *http.Request) (*http.Response, error) {
	challenge, err := s.challenge(req)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	signed := req.Clone(req.Context())
	wsKey := strings.TrimSpace(signed.Header.Get("Sec-WebSocket-Key"))
	message := model.AgentChallengeMessage(s.id, challenge, signed.Method, signed.URL.Path, wsKey)
	if s.byKey {
		public := s.key.Public().(ed25519.PublicKey)
		signed.Header.Set(model.AgentKeyHeader, model.EncodeAgentKey(public))
		message = model.AgentKeyChallengeMessage(public, challenge, signed.Method, signed.URL.Path, wsKey)
	} else {
		signed.Header.Set(model.AgentIDHeader, string(s.id))
	}
	signed.Header.Set(model.AgentChallengeHeader, challenge)
	signed.Header.Set(model.AgentSignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, message)))
	return s.base.RoundTrip(signed)
}

func (s *challengeSigner) challenge(orig *http.Request) (string, error) {
	u := *orig.URL
	u.Path, u.RawPath, u.RawQuery = model.AgentChallengePath, "", ""
	req, err := http.NewRequestWithContext(orig.Context(), "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := s.base.RoundTrip(req)
	if err != nil {
		return "", fmt.Errorf("agent challenge: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("agent challenge: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return "", fmt.Errorf("agent challenge: %w", err)
	}
	if body.Challenge == "" {
		return "", errors.New("agent challenge: empty challenge")
	}
	return body.Challenge, nil
}
