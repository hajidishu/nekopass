package tunnelcrypto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/handshakereplay"
	"golang.org/x/crypto/chacha20poly1305"
)

func firstFlightAt(t *testing.T, c ClientConfig, stamp int64) []byte {
	t.Helper()
	key, err := DecodeKey(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	psk, err := linkKey(c.LinkKey)
	if err != nil {
		t.Fatal(err)
	}
	var salt [24]byte
	rand.Read(salt[:])
	route := make([]byte, routeSize)
	route[0] = 3
	route[1] = cipherID(c.Cipher)
	route[2] = transportID(c.Transport)
	binary.BigEndian.PutUint64(route[3:11], uint64(c.IngressID))
	binary.BigEndian.PutUint64(route[11:19], uint64(c.ExitID))
	binary.BigEndian.PutUint64(route[19:27], uint64(stamp))
	n := newNoise(c.Cipher, prologue(route, salt[:]), psk)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := private.PublicKey().Bytes()
	n.ephemeral(pub)
	message := append(append(route, pub...), n.seal(nil)...)
	cover, _ := chacha20poly1305.NewX(derive(key, "nekopass/random/v2/cover", 32))
	return cover.Seal(salt[:], salt[:], message, []byte("client"))
}

func TestStreamReplaySurvivesListenerRecreationAndRejectsOldFirstFlights(t *testing.T) {
	for _, transport := range []string{"raw_tcp", "h2"} {
		t.Run(transport, func(t *testing.T) {
			c, s := configs(t, ChaCha20Poly1305)
			c.Transport = transport
			s.Transport = transport
			s.Replay = handshakereplay.NewMemory()
			server, _ := NewServer(s)
			wire := firstFlightAt(t, c, time.Now().Unix())
			conn := &memoryConn{}
			conn.Write(wire)
			accepted, err := server.Accept(context.Background(), conn)
			if err != nil || conn.Len() != serverWireSize {
				t.Fatal(err, conn.Len())
			}
			accepted.Close()
			server, _ = NewServer(s)
			replay := &memoryConn{}
			replay.Write(wire)
			if _, err = server.Accept(context.Background(), replay); err == nil || replay.Len() != 0 {
				t.Fatal("recreated listener answered captured initial", err, replay.Len())
			}
			for _, stamp := range []int64{time.Now().Unix() - handshakereplay.PastSeconds - 2, time.Now().Unix() + handshakereplay.FutureSeconds + 2} {
				old := &memoryConn{}
				old.Write(firstFlightAt(t, c, stamp))
				if _, err = server.Accept(context.Background(), old); err == nil || old.Len() != 0 {
					t.Fatal("authenticated expired/future initial answered", stamp, err)
				}
			}
		})
	}
}

func TestDatagramCapturedInitialGetsNoFreshSourceOrRestartResponse(t *testing.T) {
	c, s := configs(t, AES256GCM)
	c.Transport = "raw_udp"
	s.Transport = "raw_udp"
	s.Replay = handshakereplay.NewMemory()
	h, _ := NewDatagramHandshake(c)
	server, _ := NewDatagramServer(s)
	first := h.Initial()
	_, challenge, err := server.Check(first, "original:1000")
	if err != nil || len(challenge) == 0 {
		t.Fatal(err)
	}
	_, again, err := server.Check(first, "original:1000")
	if err != nil || !bytes.Equal(again, challenge) {
		t.Fatal("lost-challenge retry failed", err)
	}
	for i := 0; i < 8; i++ {
		if _, reply, err := server.Check(first, "probe:2000"); err == nil || reply != nil {
			t.Fatal("replayed first flight answered from a new source")
		}
	}
	retry, _, err := h.Handle(challenge)
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := server.Check(retry, "original:1000")
	if err != nil {
		t.Fatal(err)
	}
	reply, a, err := req.Respond()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, b, err := req.Respond()
	if err != nil || a != b || !bytes.Equal(reply, duplicate) {
		t.Fatal("retry allocated a different session", err)
	}
	if _, reply, err := server.Check(first, "original:1000"); err == nil || reply != nil {
		t.Fatal("completed first flight answered again")
	}
	server.Complete(req.Digest())
	if _, reply, err := server.Check(retry, "original:1000"); err == nil || reply != nil {
		t.Fatal("confirmed session answered captured cookie retry")
	}
	restarted, _ := NewDatagramServer(s)
	for _, packet := range [][]byte{first, retry} {
		if _, reply, err := restarted.Check(packet, "original:1000"); err == nil || reply != nil {
			t.Fatal("restarted listener answered old first flight")
		}
	}
}

type failReplayStore struct{}

func (failReplayStore) Claim([32]byte, int64) (bool, error) {
	return false, errors.New("storage failed")
}
func TestStreamReplayStorageFailureIsSilent(t *testing.T) {
	c, s := configs(t, ChaCha20Poly1305)
	s.Replay = failReplayStore{}
	server, _ := NewServer(s)
	conn := &memoryConn{}
	conn.Write(firstFlightAt(t, c, time.Now().Unix()))
	if _, err := server.Accept(context.Background(), conn); err == nil || conn.Len() != 0 {
		t.Fatal("storage failure emitted handshake response")
	}
}
