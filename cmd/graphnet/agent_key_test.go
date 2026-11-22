package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
)

func TestAgentKeyFromEnvironment(t *testing.T) {
	t.Setenv(agentPrivateKeyEnv, "")
	if _, _, err := openAgentCache(""); err == nil {
		t.Fatal("empty key accepted")
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(agentPrivateKeyEnv, model.EncodeAgentPrivateKey(key)+"\n")
	cache, explicit, err := openAgentCache("")
	if err != nil || !explicit {
		t.Fatalf("open with key: explicit=%v, %v", explicit, err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.PrivateKey(), key) {
		t.Fatal("configured key is not the identity")
	}

	t.Setenv(agentPrivateKeyEnv, "not-a-key")
	if _, _, err := openAgentCache(""); err == nil {
		t.Fatal("malformed key accepted")
	}
}
