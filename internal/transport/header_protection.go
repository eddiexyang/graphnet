package transport

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20"
)

const (
	hpSaltSize       = 16
	udpMaskHeaderLen = 5 // 1-byte kind + 4-byte sequence counter (or handshake prefix)
	udpSampleLen     = 16
	udpMinMaskedLen  = udpMaskHeaderLen + udpSampleLen + udpTokenSize
	dataFrameKind    = 0x45
)

// HeaderProtectionKey derives a receiver's ChaCha20 header-protection key from
// its Ed25519 public key.
func HeaderProtectionKey(pub ed25519.PublicKey) [32]byte {
	var out [32]byte
	raw, err := hkdf.Key(sha256.New, pub, nil, "GraphNet HP v1", 32)
	if err != nil {
		panic(err)
	}
	copy(out[:], raw)
	return out
}

func newHPCipher(hpKey [32]byte, sample []byte) *chacha20.Cipher {
	c, err := chacha20.NewUnauthenticatedCipher(hpKey[:], sample[4:16])
	if err != nil {
		panic(err)
	}
	c.SetCounter(binary.LittleEndian.Uint32(sample[0:4]))
	return c
}

func udpHeaderMask(hpKey [32]byte, sample []byte) [udpMaskHeaderLen + udpTokenSize]byte {
	var mask [udpMaskHeaderLen + udpTokenSize]byte
	c := newHPCipher(hpKey, sample)
	c.XORKeyStream(mask[:], mask[:])
	return mask
}

// maskUDPParts computes the masked 5-byte header and 4-byte trailing token for
// an outgoing UDP datagram without mutating caller-owned slices.
func maskUDPParts(hpKey [32]byte, payload, tail []byte, token [udpTokenSize]byte) (hdr [udpMaskHeaderLen]byte, maskedTok [udpTokenSize]byte, ok bool) {
	total := len(payload) + len(tail)
	if total < udpMaskHeaderLen+udpSampleLen || len(payload) < udpMaskHeaderLen {
		return hdr, maskedTok, false
	}
	var sample [udpSampleLen]byte
	if len(tail) >= udpSampleLen {
		copy(sample[:], tail[len(tail)-udpSampleLen:])
	} else {
		needFromPayload := udpSampleLen - len(tail)
		copy(sample[:needFromPayload], payload[len(payload)-needFromPayload:])
		copy(sample[needFromPayload:], tail)
	}
	mask := udpHeaderMask(hpKey, sample[:])
	for i := range udpMaskHeaderLen {
		hdr[i] = payload[i] ^ mask[i]
	}
	for i := range udpTokenSize {
		maskedTok[i] = token[i] ^ mask[udpMaskHeaderLen+i]
	}
	return hdr, maskedTok, true
}

func unmaskUDPDatagram(hpKey [32]byte, raw []byte) (hdr [udpMaskHeaderLen]byte, token [udpTokenSize]byte, ok bool) {
	n := len(raw)
	if n < udpMinMaskedLen {
		return hdr, token, false
	}
	sample := raw[n-udpTokenSize-udpSampleLen : n-udpTokenSize]
	mask := udpHeaderMask(hpKey, sample)
	for i := range udpMaskHeaderLen {
		hdr[i] = raw[i] ^ mask[i]
	}
	for i := range udpTokenSize {
		token[i] = raw[n-udpTokenSize+i] ^ mask[udpMaskHeaderLen+i]
	}
	return hdr, token, true
}

func drawStreamSalt() (salt [hpSaltSize]byte, err error) {
	for {
		if _, err := rand.Read(salt[:]); err != nil {
			return salt, err
		}
		if salt[0] != 0x16 && salt[0] != 'G' {
			return salt, nil
		}
	}
}
