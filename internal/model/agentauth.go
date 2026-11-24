package model

import (
	"crypto/ed25519"
	"encoding/base64"
)

// Agents registered by public key (without a client certificate) sign a
// single-use controller challenge inside the controller TLS session, carried
// in these headers.
const (
	AgentIDHeader        = "X-GraphNet-Agent"
	AgentChallengeHeader = "X-GraphNet-Challenge"
	AgentSignatureHeader = "X-GraphNet-Signature"
	AgentChallengePath   = "/api/v1/agent/challenge"
	// AgentKeyHeader identifies the Agent by its public key instead of its ID.
	// An Agent registered by public key uses it once, to learn its ID.
	AgentKeyHeader = "X-GraphNet-Agent-Key"
	// AgentRegistrationPath returns the Agent ID, CA and controller directory
	// to an authenticated Agent.
	AgentRegistrationPath = "/api/v1/agent/registration"
	// AgentRenewPath issues a new client certificate to an authenticated
	// Agent for a certificate request signed by its registered key.
	AgentRenewPath = "/api/v1/agent/renew"
)

// AgentChallengeMessage is the exact byte string an Agent signs. Binding the
// HTTP method, path and WebSocket upgrade key prevents cross-route replay.
func AgentChallengeMessage(id ID, challenge, method, path, webSocketKey string) []byte {
	return []byte("graphnet agent challenge v2\n" + string(id) + "\n" + challenge + "\n" + method + "\n" + path + "\n" + webSocketKey)
}

// AgentKeyChallengeMessage is signed when the Agent identifies by public key.
// Its distinct prefix keeps it from being replayed as an ID challenge.
func AgentKeyChallengeMessage(key ed25519.PublicKey, challenge, method, path, webSocketKey string) []byte {
	return []byte("graphnet agent key challenge v2\n" + EncodeAgentKey(key) + "\n" + challenge + "\n" + method + "\n" + path + "\n" + webSocketKey)
}

// EncodeAgentKey is the header and API text form of an Agent public key.
func EncodeAgentKey(key ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// ParseAgentKey accepts the header form and standard base64, as pasted from
// other tools.
func ParseAgentKey(text string) (ed25519.PublicKey, bool) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if raw, err := encoding.DecodeString(text); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), true
		}
	}
	return nil, false
}

// EncodeAgentPrivateKey is the configuration text form of an Agent private
// key: its Ed25519 seed, encoded as EncodeAgentKey encodes the public key.
func EncodeAgentPrivateKey(key ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(key.Seed())
}

// ParseAgentPrivateKey accepts EncodeAgentPrivateKey's form and standard
// base64 of the seed.
func ParseAgentPrivateKey(text string) (ed25519.PrivateKey, bool) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if raw, err := encoding.DecodeString(text); err == nil && len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), true
		}
	}
	return nil, false
}
