package secure

import (
	"bytes"
	"testing"
)

// Forged and truncated ciphertext never opens and never panics.
func FuzzOpen(f *testing.F) {
	a, b := configs(f)
	sender, receiver := establish(f, a, b)
	sealed, _ := sender.Seal([]byte("message"))
	f.Add(sealed)
	f.Add(make([]byte, Overhead+1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if bytes.Equal(raw, sealed) {
			return
		}
		if _, err := receiver.Open(bytes.Clone(raw)); err == nil {
			t.Fatal("forged message opened")
		}
		receiver.OpenBatchInPlace([][]byte{bytes.Clone(raw)})
	})
}
