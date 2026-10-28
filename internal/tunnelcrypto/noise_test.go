package tunnelcrypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Public test data only (not implementation code), from
// https://github.com/centromere/cacophony/blob/master/vectors/cacophony.txt
func TestNoisePublishedVectors(t *testing.T) {
	var vectors []struct {
		Name      string   `json:"protocol_name"`
		Prologue  string   `json:"init_prologue"`
		PSKs      []string `json:"init_psks"`
		Initiator string   `json:"init_ephemeral"`
		Responder string   `json:"resp_ephemeral"`
		Hash      string   `json:"handshake_hash"`
		Messages  []struct{ Payload, Ciphertext string }
	}
	b, err := os.ReadFile("testdata/noise-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if len(vectors) != 2 {
		t.Fatal("missing cipher vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			name := ChaCha20Poly1305
			if strings.Contains(v.Name, "AESGCM") {
				name = AES256GCM
			}
			i := newNoise(name, decode(v.Prologue), decode(v.PSKs[0]))
			r := newNoise(name, decode(v.Prologue), decode(v.PSKs[0]))
			ie, _ := ecdh.X25519().NewPrivateKey(decode(v.Initiator))
			re, _ := ecdh.X25519().NewPrivateKey(decode(v.Responder))
			ip, rp := ie.PublicKey().Bytes(), re.PublicKey().Bytes()
			i.ephemeral(ip)
			first := append(ip, i.seal(decode(v.Messages[0].Payload))...)
			if !bytes.Equal(first, decode(v.Messages[0].Ciphertext)) {
				t.Fatal("initiator flight differs from public vector")
			}
			r.ephemeral(first[:32])
			if _, err = r.open(first[32:]); err != nil {
				t.Fatal(err)
			}
			r.ephemeral(rp)
			if err = r.exchange(re, ip); err != nil {
				t.Fatal(err)
			}
			second := append(rp, r.seal(decode(v.Messages[1].Payload))...)
			if !bytes.Equal(second, decode(v.Messages[1].Ciphertext)) {
				t.Fatal("responder flight differs from public vector")
			}
			i.ephemeral(rp)
			if err = i.exchange(ie, rp); err != nil {
				t.Fatal(err)
			}
			if _, err = i.open(second[32:]); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(i.h[:], decode(v.Hash)) || i.h != r.h {
				t.Fatal("transcript mismatch")
			}
			send, receive := i.split()
			rsend, rreceive := r.split()
			if !bytes.Equal(send, rsend) || !bytes.Equal(receive, rreceive) {
				t.Fatal("split mismatch")
			}
			for j, m := range v.Messages[2:] {
				key := send
				if j%2 == 1 {
					key = receive
				}
				aead, _ := newAEAD(name, key)
				n := nonce(name, uint64(j/2))
				ciphertext := aead.Seal(nil, n[:], decode(m.Payload), nil)
				if !bytes.Equal(ciphertext, decode(m.Ciphertext)) {
					t.Fatalf("split key / nonce mismatch %d", j)
				}
			}
		})
	}
}
