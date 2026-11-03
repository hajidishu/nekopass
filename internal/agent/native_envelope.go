package agent

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/nekopass/nekopass/internal/tunnelcrypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const nativeEnvelopeOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

// The node-level envelope hides routing metadata; the independent per-link MAC
// underneath still authorizes each ingress. Nonces and direction are bound to
// AEAD authentication, and invalid packets never advance session replay state.
type nativeEnvelope struct{ aead cipher.AEAD }

func newNativeEnvelope(key string) (*nativeEnvelope, error) {
	b, err := tunnelcrypto.DecodeKey(key)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, b)
	m.Write([]byte("nekopass/native-udp/v3/envelope"))
	a, err := chacha20poly1305.NewX(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	return &nativeEnvelope{aead: a}, nil
}

func nativeEnvelopeAAD(ingressToExit bool) []byte {
	if ingressToExit {
		return []byte{3, 1}
	}
	return []byte{3, 0}
}

func (e *nativeEnvelope) seal(wire []byte, ingressToExit bool) ([]byte, error) {
	if len(wire) < nativeHeader+nativeMAC || len(wire)+nativeEnvelopeOverhead > 1200 {
		return nil, errors.New("invalid encrypted native packet size")
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce[:], nonce[:], wire, nativeEnvelopeAAD(ingressToExit)), nil
}

func (e *nativeEnvelope) open(wire []byte, ingressToExit bool) ([]byte, error) {
	if len(wire) < nativeHeader+nativeMAC+nativeEnvelopeOverhead || len(wire) > 1200 {
		return nil, errors.New("invalid encrypted native packet size")
	}
	return e.aead.Open(nil, wire[:chacha20poly1305.NonceSizeX], wire[chacha20poly1305.NonceSizeX:], nativeEnvelopeAAD(ingressToExit))
}
