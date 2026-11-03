package tunnelcrypto

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/nekopass/nekopass/internal/handshakereplay"
	"golang.org/x/crypto/chacha20poly1305"
)

const routeSize = 27 // version, cipher, transport, ingress ID, exit ID, timestamp (encrypted)
const clientWireSize = 24 + routeSize + 48 + 16
const serverWireSize = 24 + 72 + 16
const replayLimit = handshakereplay.Limit

type ClientConfig struct {
	Cipher, Key, LinkKey, Transport string
	IngressID, ExitID               int64
}
type ServerConfig struct {
	Cipher, Key, Transport string
	ExitID                 int64
	LinkKey                func(int64) (string, bool)
	Replay                 handshakereplay.Store
}
type Server struct {
	cfg    ServerConfig
	cover  cipher.AEAD
	replay handshakereplay.Store
}

func NewServer(cfg ServerConfig) (*Server, error) {
	key, err := DecodeKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	if !ValidCipher(cfg.Cipher) || cfg.ExitID <= 0 || transportID(cfg.Transport) == 0 || cfg.LinkKey == nil {
		return nil, ErrAuthentication
	}
	cover, _ := chacha20poly1305.NewX(derive(key, "nekopass/random/v2/cover", 32))
	store := cfg.Replay
	if store == nil {
		store = handshakereplay.NewMemory()
	}
	return &Server{cfg: cfg, cover: cover, replay: store}, nil
}
func transportID(s string) byte {
	switch s {
	case "raw_tcp":
		return 1
	case "h2":
		return 2
	}
	return 0
}
func cipherID(s string) byte {
	if s == ChaCha20Poly1305 {
		return 1
	}
	if s == AES256GCM {
		return 2
	}
	return 0
}
func prologue(route, salt []byte) []byte {
	out := append([]byte("nekopass/random/v2/handshake\x00"), route...)
	return append(out, salt...)
}
func guard(ctx context.Context, c net.Conn) func() {
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	return func() { stop(); c.SetDeadline(time.Time{}) }
}
func writeFull(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, e := c.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func Dial(ctx context.Context, c net.Conn, cfg ClientConfig) (out *Conn, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	defer guard(ctx, c)()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	key, err := DecodeKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	psk, err := linkKey(cfg.LinkKey)
	if err != nil {
		return nil, err
	}
	if !ValidCipher(cfg.Cipher) || transportID(cfg.Transport) == 0 || cfg.IngressID <= 0 || cfg.ExitID <= 0 {
		return nil, ErrAuthentication
	}
	var salt [24]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	route := make([]byte, routeSize)
	route[0] = 3
	route[1] = cipherID(cfg.Cipher)
	route[2] = transportID(cfg.Transport)
	binary.BigEndian.PutUint64(route[3:11], uint64(cfg.IngressID))
	binary.BigEndian.PutUint64(route[11:19], uint64(cfg.ExitID))
	binary.BigEndian.PutUint64(route[19:27], uint64(time.Now().Unix()))
	n := newNoise(cfg.Cipher, prologue(route, salt[:]), psk)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := private.PublicKey().Bytes()
	n.ephemeral(pub)
	message := append(append(route, pub...), n.seal(nil)...)
	cover, _ := chacha20poly1305.NewX(derive(key, "nekopass/random/v2/cover", 32))
	wire := append(salt[:], cover.Seal(nil, salt[:], message, []byte("client"))...)
	if err = writeFull(c, wire); err != nil {
		return nil, err
	}
	reply := make([]byte, serverWireSize)
	if _, err = io.ReadFull(c, reply); err != nil {
		return nil, err
	}
	message, err = cover.Open(nil, reply[:24], reply[24:], append([]byte("server"), salt[:]...))
	if err != nil || len(message) != 72 {
		return nil, ErrAuthentication
	}
	n.ephemeral(message[:32])
	if err = n.exchange(private, message[:32]); err != nil {
		return nil, err
	}
	confirmation, err := n.open(message[32:])
	if err != nil || !hmac.Equal(confirmation, reply[:24]) {
		return nil, ErrAuthentication
	}
	send, receive := n.split()
	return newConn(c, cfg.Cipher, send, receive, n.h, cfg.IngressID), nil
}
func (s *Server) Accept(ctx context.Context, c net.Conn) (out *Conn, err error) {
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	defer guard(ctx, c)()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	wire := make([]byte, clientWireSize)
	if _, err = io.ReadFull(c, wire); err != nil {
		return nil, err
	}
	message, err := s.cover.Open(nil, wire[:24], wire[24:], []byte("client"))
	if err != nil || len(message) != routeSize+48 {
		return nil, ErrAuthentication
	}
	route := message[:routeSize]
	ingress := int64(binary.BigEndian.Uint64(route[3:11]))
	exit := int64(binary.BigEndian.Uint64(route[11:19]))
	stamp := int64(binary.BigEndian.Uint64(route[19:27]))
	if route[0] != 3 || route[1] != cipherID(s.cfg.Cipher) || route[2] != transportID(s.cfg.Transport) || ingress <= 0 || exit != s.cfg.ExitID || !handshakereplay.ValidTimestamp(stamp, time.Now().Unix()) {
		return nil, ErrAuthentication
	}
	token, ok := s.cfg.LinkKey(ingress)
	if !ok {
		return nil, ErrAuthentication
	}
	psk, err := linkKey(token)
	if err != nil {
		return nil, err
	}
	n := newNoise(s.cfg.Cipher, prologue(route, wire[:24]), psk)
	pub := message[routeSize : routeSize+32]
	n.ephemeral(pub)
	if _, err = n.open(message[routeSize+32:]); err != nil {
		return nil, err
	}
	var clientSalt [24]byte
	copy(clientSalt[:], wire[:24])
	claimed, replayErr := s.replay.Claim(sha256.Sum256(wire), handshakereplay.Expiry(stamp))
	if replayErr != nil || !claimed {
		return nil, ErrAuthentication
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub = private.PublicKey().Bytes()
	n.ephemeral(pub)
	if err = n.exchange(private, message[routeSize:routeSize+32]); err != nil {
		return nil, err
	}
	var salt [24]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	response := append(pub, n.seal(salt[:])...)
	reply := append(salt[:], s.cover.Seal(nil, salt[:], response, append([]byte("server"), clientSalt[:]...))...)
	if err = writeFull(c, reply); err != nil {
		return nil, err
	}
	clientSend, clientReceive := n.split()
	return newConn(c, s.cfg.Cipher, clientReceive, clientSend, n.h, ingress), nil
}
