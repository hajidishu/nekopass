package tunnelcrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func configs(t testing.TB, name string) (ClientConfig, ServerConfig) {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	rand.Read(token[:])
	link := hex.EncodeToString(token[:])
	return ClientConfig{Cipher: name, Key: key, LinkKey: link, Transport: "raw_tcp", IngressID: 2, ExitID: 3}, ServerConfig{Cipher: name, Key: key, Transport: "raw_tcp", ExitID: 3, LinkKey: func(id int64) (string, bool) { return link, id == 2 }}
}
func connect(t testing.TB, name string) (*Conn, *Conn) {
	t.Helper()
	client, cfg := configs(t, name)
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		c   *Conn
		err error
	}
	done := make(chan result, 1)
	go func() { c, e := server.Accept(ctx, b); done <- result{c, e} }()
	c, err := Dial(ctx, a, client)
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return c, r.c
}
func TestEncryptedDuplexAndFIN(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			a, b := connect(t, name)
			var wg sync.WaitGroup
			payload := bytes.Repeat([]byte("payload"), 30000)
			for _, pair := range [][2]*Conn{{a, b}, {b, a}} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := pair[0].Write(payload); err != nil {
						t.Error(err)
					}
					if err := pair[0].CloseWrite(); err != nil {
						t.Error(err)
					}
				}()
				wg.Add(1)
				go func() {
					defer wg.Done()
					var got bytes.Buffer
					buf := make([]byte, 37)
					_, err := io.CopyBuffer(&got, pair[1], buf)
					if err != nil || !bytes.Equal(got.Bytes(), payload) {
						t.Error("duplex data", err)
					}
				}()
			}
			wg.Wait()
			if _, err := a.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}
func TestRekeyBoundary(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			a, b := connect(t, name)
			a.wr.seq = (1 << 16) - 1
			b.rd.seq = a.wr.seq
			done := make(chan error, 1)
			go func() {
				for range 4 {
					if _, err := a.Write([]byte("hello")); err != nil {
						done <- err
						return
					}
				}
				done <- a.CloseWrite()
			}()
			got, err := io.ReadAll(b)
			if err != nil || string(got) != "hellohellohellohello" {
				t.Fatal(string(got), err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			a.wr.seq = math.MaxUint64
			if _, err = a.Write([]byte{1}); err == nil {
				t.Fatal("counter exhaustion accepted")
			}
		})
	}
}
func TestTruncatedStream(t *testing.T) {
	a, b := connect(t, ChaCha20Poly1305)
	a.Close()
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
func TestHandshakeRejectsWrongCredentials(t *testing.T) {
	for _, field := range []string{"key", "link", "ingress", "exit", "transport", "cipher"} {
		t.Run(field, func(t *testing.T) {
			client, cfg := configs(t, ChaCha20Poly1305)
			s, _ := NewServer(cfg)
			switch field {
			case "key":
				client.Key, _ = GenerateKey()
			case "link":
				client.LinkKey = strings.Repeat("ab", 32)
			case "ingress":
				client.IngressID++
			case "exit":
				client.ExitID++
			case "transport":
				client.Transport = "h2"
			case "cipher":
				client.Cipher = AES256GCM
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := s.Accept(ctx, b); done <- err }()
			if c, err := Dial(ctx, a, client); err == nil {
				c.Close()
				t.Fatal("bad handshake accepted")
			}
			if err := <-done; err == nil {
				t.Fatal("bad client accepted")
			}
		})
	}
}
func TestHandshakeCancellation(t *testing.T) {
	client, _ := configs(t, AES256GCM)
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := Dial(ctx, a, client); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled handshake accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not cancel")
	}
}

// Memory connection permits modifying complete encrypted records without a
// peer goroutine or timing-dependent TCP packet boundaries.
type memoryConn struct{ bytes.Buffer }

func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }
func TestRecordTamperReplayAndReflection(t *testing.T) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		t.Run(name, func(t *testing.T) {
			var send, receive [32]byte
			rand.Read(send[:])
			rand.Read(receive[:])
			binding := digest([]byte("test"))
			wire := &memoryConn{}
			writer := newConn(wire, name, send[:], receive[:], binding, 2)
			writer.Write([]byte("payload"))
			first := bytes.Clone(wire.Bytes())
			for i := range first {
				modified := bytes.Clone(first)
				modified[i] ^= 1
				raw := &memoryConn{}
				raw.Write(modified)
				reader := newConn(raw, name, receive[:], send[:], binding, 2)
				if _, err := reader.Read(make([]byte, 50)); err == nil {
					t.Fatalf("tamper accepted at %d", i)
				}
			}
			for _, key := range [][]byte{receive[:], make([]byte, 32)} {
				raw := &memoryConn{}
				raw.Write(first)
				reader := newConn(raw, name, send[:], key, binding, 2)
				if _, err := reader.Read(make([]byte, 50)); err == nil {
					t.Fatal("reflected/cross-session record accepted")
				}
			}
			raw := &memoryConn{}
			raw.Write(first)
			raw.Write(first)
			reader := newConn(raw, name, receive[:], send[:], binding, 2)
			if _, err := reader.Read(make([]byte, 50)); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(make([]byte, 50)); err == nil {
				t.Fatal("replayed record accepted")
			}
		})
	}
}
func BenchmarkRecords(b *testing.B) {
	for _, name := range []string{ChaCha20Poly1305, AES256GCM} {
		b.Run(name, func(b *testing.B) {
			var key [32]byte
			rand.Read(key[:])
			binding := digest(nil)
			wire := &memoryConn{}
			w := newConn(wire, name, key[:], key[:], binding, 2)
			r := newConn(wire, name, key[:], key[:], binding, 2)
			data := make([]byte, MaxRecord)
			buf := make([]byte, MaxRecord)
			b.SetBytes(MaxRecord)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := w.Write(data); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(r, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
