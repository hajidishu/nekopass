// Package tunnelcrypto implements nekopass random encryption v1 independently
// from the public Noise NNpsk0 specification. Standard-library primitives do
// the cryptography; this package owns the envelope, framing and lifecycle.
package tunnelcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20Poly1305 = "chacha20-poly1305"
	AES256GCM        = "aes-256-gcm"
	MaxRecord        = 32 << 10
)

var ErrAuthentication = errors.New("random encryption authentication failed")

func ValidCipher(name string) bool { return name == ChaCha20Poly1305 || name == AES256GCM }
func GenerateKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func DecodeKey(s string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := encoding.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("encryption key must encode 32 random bytes in Base64")
}
func linkKey(token string) ([]byte, error) {
	b, err := hex.DecodeString(token)
	if err != nil || len(b) != 32 {
		return nil, ErrAuthentication
	}
	return derive(b, "nekopass/random/v1/link", 32), nil
}
func derive(key []byte, label string, n int) []byte {
	b, err := hkdf.Key(sha256.New, key, nil, label, n)
	if err != nil {
		panic(err)
	}
	return b
}
func newAEAD(name string, key []byte) (cipher.AEAD, error) {
	switch name {
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, errors.New("unsupported random encryption cipher")
	}
}
