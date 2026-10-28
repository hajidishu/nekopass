package tunnelcrypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type captureConn struct {
	net.Conn
	writes bytes.Buffer
	short  bool
}

func (c *captureConn) Write(p []byte) (int, error) {
	if c.short && len(p) > 7 {
		p = p[:7]
	}
	n, err := c.Conn.Write(p)
	c.writes.Write(p[:n])
	return n, err
}
func TestHandshakeReplayAndTampering(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			cfg, scfg := configs(t, name)
			server, _ := NewServer(scfg)
			a, b := net.Pipe()
			clientWire, serverWire := &captureConn{Conn: a, short: true}, &captureConn{Conn: b, short: true}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := server.Accept(ctx, serverWire); done <- err }()
			c, err := Dial(ctx, clientWire, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			first, reply := bytes.Clone(clientWire.writes.Bytes()), bytes.Clone(serverWire.writes.Bytes())
			c.Close()
			b.Close()
			if len(first) != clientWireSize || len(reply) != serverWireSize {
				t.Fatal("flight framing", len(first), len(reply))
			}
			// Replaying an authenticated first flight must neither get a reply nor
			// trigger another Diffie-Hellman operation in the recent replay window.
			raw := &memoryConn{}
			raw.Write(first)
			if _, err = server.Accept(ctx, raw); err == nil {
				t.Fatal("replayed handshake accepted")
			}
			if raw.Len() != 0 {
				t.Fatal("reply emitted to replay")
			}
			for j := range first {
				bad := bytes.Clone(first)
				bad[j] ^= 1
				raw := &memoryConn{}
				raw.Write(bad)
				if _, err = server.Accept(ctx, raw); err == nil {
					t.Fatalf("tampered first flight accepted at %d", j)
				}
				if raw.Len() != 0 {
					t.Fatal("response emitted to invalid client")
				}
			}
			// A response from another session cannot be transplanted, even when
			// the exit key, cipher, ingress and link credential are identical.
			x, y := net.Pipe()
			defer x.Close()
			defer y.Close()
			go func() { io.ReadFull(y, make([]byte, clientWireSize)); writeFull(y, reply); y.Close() }()
			if peer, err := Dial(ctx, x, cfg); err == nil {
				peer.Close()
				t.Fatal("cross-session response accepted")
			}
		})
	}
}
func TestReplayWindowBounded(t *testing.T) {
	_, cfg := configs(t, ChaCha20Poly1305)
	s, _ := NewServer(cfg)
	for j := 0; j < replayLimit; j++ {
		var salt [24]byte
		binary.BigEndian.PutUint64(salt[:8], uint64(j))
		if !s.take(salt) {
			t.Fatal("premature replay bound")
		}
	}
	var salt [24]byte
	salt[23] = 1
	if s.take(salt) || len(s.seen) != replayLimit {
		t.Fatal("replay cache unbounded")
	}
	for k := range s.seen {
		s.seen[k] = time.Now().Add(-time.Second)
	}
	if !s.take(salt) || len(s.seen) != 1 {
		t.Fatal("expired entries not reclaimed")
	}
}

func FuzzRecordReader(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, 100))
	f.Add(bytes.Repeat([]byte{0}, 65536))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRecord*3 {
			t.Skip()
		}
		raw := &memoryConn{}
		raw.Write(data)
		key := make([]byte, 32)
		c := newConn(raw, ChaCha20Poly1305, key, key, [32]byte{}, 2)
		c.Read(make([]byte, 100))
		c.Close()
	})
}
