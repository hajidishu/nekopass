package tunnelcrypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// NNpsk0: -> psk,e ; <- e,ee. PSK-mode e tokens mix both hash and key.
// Handshake payloads use Noise's transcript as associated data. No early data
// or session tickets are supported. The wire envelope encrypts public keys too.
type noiseState struct {
	h, ck   [32]byte
	aead    cipher.AEAD
	name    string
	counter uint64
}

func digest(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func noiseKDF(ck [32]byte, input []byte, count int) [][32]byte {
	m := hmac.New(sha256.New, ck[:])
	m.Write(input)
	secret := m.Sum(nil)
	result := make([][32]byte, count)
	var previous []byte
	for i := range result {
		m = hmac.New(sha256.New, secret)
		m.Write(previous)
		m.Write([]byte{byte(i + 1)})
		copy(result[i][:], m.Sum(nil))
		previous = result[i][:]
	}
	return result
}
func newNoise(name string, prologue, psk []byte) *noiseState {
	cipherName := "ChaChaPoly"
	if name == AES256GCM {
		cipherName = "AESGCM"
	}
	protocol := []byte("Noise_NNpsk0_25519_" + cipherName + "_SHA256")
	n := &noiseState{name: name}
	if len(protocol) > 32 {
		n.h = sha256.Sum256(protocol)
	} else {
		copy(n.h[:], protocol)
	}
	n.ck = n.h
	n.mixHash(prologue)
	keys := noiseKDF(n.ck, psk, 3)
	n.ck = keys[0]
	n.mixHash(keys[1][:])
	n.aead, _ = newAEAD(name, keys[2][:])
	return n
}
func (n *noiseState) mixHash(b []byte) { n.h = digest(n.h[:], b) }
func (n *noiseState) mixKey(b []byte) {
	keys := noiseKDF(n.ck, b, 2)
	n.ck = keys[0]
	n.aead, _ = newAEAD(n.name, keys[1][:])
	n.counter = 0
}
func (n *noiseState) ephemeral(pub []byte) { n.mixHash(pub); n.mixKey(pub) }
func (n *noiseState) seal(payload []byte) []byte {
	nonce := nonce(n.name, n.counter)
	out := n.aead.Seal(nil, nonce[:], payload, n.h[:])
	n.counter++
	n.mixHash(out)
	return out
}
func (n *noiseState) open(b []byte) ([]byte, error) {
	nonce := nonce(n.name, n.counter)
	out, err := n.aead.Open(nil, nonce[:], b, n.h[:])
	if err != nil {
		return nil, ErrAuthentication
	}
	n.counter++
	n.mixHash(b)
	return out, nil
}
func (n *noiseState) exchange(private *ecdh.PrivateKey, public []byte) error {
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return ErrAuthentication
	}
	secret, err := private.ECDH(pub)
	if err != nil {
		return ErrAuthentication
	}
	n.mixKey(secret)
	return nil
}
func (n *noiseState) split() (send, receive []byte) {
	keys := noiseKDF(n.ck, nil, 2)
	return keys[0][:], keys[1][:]
}
func nonce(name string, seq uint64) [12]byte {
	var n [12]byte
	if name == AES256GCM {
		binary.BigEndian.PutUint64(n[4:], seq)
	} else {
		binary.LittleEndian.PutUint64(n[4:], seq)
	}
	return n
}
