package tunnelcrypto

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func datagramPair(t testing.TB, name string) (*DatagramSession, *DatagramSession) {
	t.Helper()
	client, server := configs(t, name)
	client.Transport = "raw_udp"
	server.Transport = "raw_udp"
	h, err := NewDatagramHandshake(client)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewDatagramServer(server)
	if err != nil {
		t.Fatal(err)
	}
	req, challenge, err := gate.Check(h.Initial(), "source:123")
	if err != nil || req != nil || len(challenge) > len(h.Initial()) {
		t.Fatal("source challenge", err)
	}
	retry, session, err := h.Handle(challenge)
	if err != nil || session != nil {
		t.Fatal(err)
	}
	if req, challenge, err = gate.Check(retry, "different:123"); err != nil || req != nil || challenge == nil {
		t.Fatal("cookie not bound to source")
	}
	req, challenge, err = gate.Check(retry, "source:123")
	if err != nil || req == nil || challenge != nil {
		t.Fatal(err)
	}
	reply, b, err := req.Respond()
	if err != nil || len(reply) > len(retry) {
		t.Fatal("amplifying handshake", err)
	}
	_, a, err := h.Handle(reply)
	if err != nil || a == nil || a.ID() != b.ID() {
		t.Fatal("key agreement", err)
	}
	return a, b
}
func TestDatagramCiphersReorderingAndReplay(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			a, b := datagramPair(t, name)
			var wires [][]byte
			for i := range 20 {
				wire, err := a.Seal(bytes.Repeat([]byte{byte(i)}, i*40))
				if err != nil {
					t.Fatal(err)
				}
				wires = append(wires, wire)
			}
			for i := len(wires) - 1; i >= 0; i-- {
				packet, err := b.Parse(wires[i])
				if err != nil {
					t.Fatal(err)
				}
				plain, err := b.Open(packet)
				if err != nil || !bytes.Equal(plain, bytes.Repeat([]byte{byte(i)}, i*40)) {
					t.Fatal("out of order", i, err)
				}
				if _, err = b.Open(packet); err != ErrReplay {
					t.Fatal("replayed packet", err)
				}
			}
			wire, _ := b.Seal([]byte("return"))
			packet, err := a.Parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			if plain, err := a.Open(packet); err != nil || string(plain) != "return" {
				t.Fatal("reverse direction", err)
			}
		})
	}
}
func TestDatagramAuthenticationAndRekey(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			a, b := datagramPair(t, name)
			wire, _ := a.Seal([]byte("authenticated"))
			if _, err := a.Parse(wire); err == nil {
				t.Fatal("reflection accepted")
			}
			for i := range wire {
				modified := bytes.Clone(wire)
				modified[i] ^= 1
				packet, err := b.Parse(modified)
				if err == nil {
					if _, err = b.Open(packet); err == nil {
						t.Fatalf("tamper accepted at %d", i)
					}
				}
			}
			// A valid routing header with a forged body must not poison counters.
			forged := bytes.Clone(wire)
			var route [24]byte
			copy(route[:16], a.id[:])
			binary.BigEndian.PutUint64(route[16:], 1<<40)
			copy(forged[24:64], a.header.aead.Seal(nil, forged[:24], route[:], []byte{1}))
			packet, err := b.Parse(forged)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.Open(packet); err == nil {
				t.Fatal("forged future sequence accepted")
			}
			packet, _ = b.Parse(wire)
			if _, err = b.Open(packet); err != nil {
				t.Fatal("forgery poisoned replay state", err)
			}
			a.sequence = (1 << 16) - 2
			old, _ := a.Seal([]byte("old epoch"))
			fresh, _ := a.Seal([]byte("new epoch"))
			for _, packetWire := range [][]byte{fresh, old} {
				packet, err = b.Parse(packetWire)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = b.Open(packet); err != nil {
					t.Fatal("rekey / reordered old epoch", err)
				}
			}
			if _, err = a.Seal(make([]byte, MaxDatagramPayload+1)); err == nil {
				t.Fatal("oversize packet accepted")
			}
		})
	}
}
func TestDatagramHandshakeRejectsInvalidCredentials(t *testing.T) {
	for _, field := range []string{"key", "link", "ingress", "exit", "cipher"} {
		t.Run(field, func(t *testing.T) {
			c, s := configs(t, ChaCha20Poly1305)
			c.Transport = "raw_udp"
			s.Transport = "raw_udp"
			gate, _ := NewDatagramServer(s)
			switch field {
			case "key":
				c.Key, _ = GenerateKey()
			case "link":
				c.LinkKey = "0000000000000000000000000000000000000000000000000000000000000000"
			case "ingress":
				c.IngressID++
			case "exit":
				c.ExitID++
			case "cipher":
				c.Cipher = AES256GCM
			}
			h, err := NewDatagramHandshake(c)
			if err != nil {
				t.Fatal(err)
			}
			if req, reply, err := gate.Check(h.Initial(), "source:1"); err == nil || req != nil || reply != nil {
				t.Fatal("unauthenticated UDP client received response")
			}
		})
	}
}

func TestDatagramOpaqueCookieAndSingleCompletion(t *testing.T) {
	c, s := configs(t, AES256GCM)
	c.Transport = "raw_udp"
	s.Transport = "raw_udp"
	h, _ := NewDatagramHandshake(c)
	gate, _ := NewDatagramServer(s)
	_, challenge, err := gate.Check(h.Initial(), "source:1")
	if err != nil {
		t.Fatal(err)
	}
	retry, _, err := h.Handle(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cookie := retry[DatagramInitialSize:]
	if len(cookie) != 40 || binary.BigEndian.Uint64(cookie[:8]) == uint64(time.Now().Unix()/60) {
		t.Fatal("cookie exposes time bucket")
	}
	r, _, err := gate.Check(retry, "source:1")
	if err != nil || r == nil {
		t.Fatal(err)
	}
	reply, _, err := r.Respond()
	if err != nil {
		t.Fatal(err)
	}
	for i := range reply {
		bad := bytes.Clone(reply)
		bad[i] ^= 1
		if _, session, err := h.Handle(bad); err == nil || session != nil {
			t.Fatal("tampered response accepted", i)
		}
	}
	if _, session, err := h.Handle(reply); err != nil || session == nil {
		t.Fatal("invalid responses corrupted handshake", err)
	}
	if _, _, err := h.Handle(reply); err == nil {
		t.Fatal("repeated completion could reset packet nonces")
	}
}
func BenchmarkDatagrams(b *testing.B) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		b.Run(name, func(b *testing.B) {
			a, c := datagramPair(b, name)
			body := make([]byte, 1100)
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				wire, err := a.Seal(body)
				if err != nil {
					b.Fatal(err)
				}
				p, err := c.Parse(wire)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = c.Open(p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func FuzzDatagramHeader(f *testing.F) {
	key, _ := GenerateKey()
	header, _ := newDatagramHeader(key)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, 1200))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > DatagramMTU+1 {
			t.Skip()
		}
		header.parse(wire, true)
	})
}
