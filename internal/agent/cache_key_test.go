package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
)

func TestMemoryCacheIdentityAndRegistration(t *testing.T) {
	_, first, _ := ed25519.GenerateKey(rand.Reader)
	cache, err := NewMemoryCache(first)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.PrivateKey(), first) {
		t.Fatal("cache does not use the configured key")
	}
	reg := Registration{CA: []byte("ca"), AgentID: model.NewID(), Server: "https://127.0.0.1:8443"}
	if err := cache.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	if got, err := cache.Registration(); err != nil || got == nil || got.AgentID != reg.AgentID {
		t.Fatalf("registration = %+v, %v", got, err)
	}
	// A fresh startup starts with no cached registration.
	fresh, err := NewMemoryCache(first)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fresh.Registration(); err != nil || got != nil {
		t.Fatalf("fresh startup should have no cached registration, got %+v, %v", got, err)
	}
}

func TestAgentPrivateKeyText(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	got, ok := model.ParseAgentPrivateKey(model.EncodeAgentPrivateKey(key))
	if !ok || !bytes.Equal(got, key) {
		t.Fatal("private key does not survive its text form")
	}
	if _, ok := model.ParseAgentPrivateKey("not-a-key"); ok {
		t.Fatal("malformed private key accepted")
	}
}
