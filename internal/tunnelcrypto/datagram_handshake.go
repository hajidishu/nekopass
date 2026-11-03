package tunnelcrypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/nekopass/nekopass/internal/handshakereplay"
	"golang.org/x/crypto/chacha20poly1305"
)

const DatagramInitialSize = clientWireSize
const DatagramCookieSize = 40

type DatagramHandshake struct {
	cfg       ClientConfig
	cover     cipher.AEAD
	header    *datagramHeaderKey
	noise     *noiseState
	private   *ecdh.PrivateKey
	completed bool
	initial   []byte
	salt      [24]byte
}
type DatagramServer struct {
	cfg          ServerConfig
	cover        cipher.AEAD
	header       *datagramHeaderKey
	cookieSecret [32]byte
	gate         *handshakereplay.Gate
	mu           sync.Mutex
	requests     map[[32]byte]*DatagramRequest
	pruned       int64
}
type DatagramRequest struct {
	server  *DatagramServer
	noise   *noiseState
	public  []byte
	salt    [24]byte
	digest  [32]byte
	ingress int64
	link    string
	expires int64
	mu      sync.Mutex
	reply   []byte
	session *DatagramSession
	failed  bool
}

func (r *DatagramRequest) Digest() [32]byte { return r.digest }
func (r *DatagramRequest) IngressID() int64 { return r.ingress }
func (r *DatagramRequest) LinkKey() string  { return r.link }
func datagramPrologue(route, salt []byte) []byte {
	return append(append([]byte("nekopass/random/udp/v2/handshake\x00"), route...), salt...)
}
func datagramCover(key string) (cipher.AEAD, error) {
	b, err := DecodeKey(key)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(derive(b, "nekopass/random/udp/v2/cover", 32))
}
func NewDatagramHandshake(cfg ClientConfig) (*DatagramHandshake, error) {
	if !ValidCipher(cfg.Cipher) || cfg.Transport != "raw_udp" || cfg.IngressID <= 0 || cfg.ExitID <= 0 {
		return nil, ErrAuthentication
	}
	cover, err := datagramCover(cfg.Key)
	if err != nil {
		return nil, err
	}
	header, err := newDatagramHeader(cfg.Key)
	if err != nil {
		return nil, err
	}
	psk, err := linkKey(cfg.LinkKey)
	if err != nil {
		return nil, err
	}
	h := &DatagramHandshake{cfg: cfg, cover: cover, header: header}
	if _, err = rand.Read(h.salt[:]); err != nil {
		return nil, err
	}
	route := make([]byte, routeSize)
	route[0] = 4
	route[1] = cipherID(cfg.Cipher)
	route[2] = 3
	binary.BigEndian.PutUint64(route[3:11], uint64(cfg.IngressID))
	binary.BigEndian.PutUint64(route[11:], uint64(cfg.ExitID))
	binary.BigEndian.PutUint64(route[19:27], uint64(time.Now().Unix()))
	h.noise = newNoise(cfg.Cipher, datagramPrologue(route, h.salt[:]), psk)
	h.private, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := h.private.PublicKey().Bytes()
	h.noise.ephemeral(pub)
	message := append(append(route, pub...), h.noise.seal(nil)...)
	h.initial = append(h.salt[:], cover.Seal(nil, h.salt[:], message, []byte("client"))...)
	return h, nil
}
func (h *DatagramHandshake) Initial() []byte { return append([]byte(nil), h.initial...) }
func (h *DatagramHandshake) Handle(wire []byte) (retry []byte, session *DatagramSession, err error) {
	if h.completed {
		return nil, nil, ErrAuthentication
	}
	if len(wire) < 41 || len(wire) > DatagramMTU {
		return nil, nil, ErrAuthentication
	}
	plain, err := h.cover.Open(nil, wire[:24], wire[24:], append([]byte("server"), h.salt[:]...))
	if err != nil || len(plain) == 0 {
		return nil, nil, ErrAuthentication
	}
	if plain[0] == 1 && len(plain) == 41 {
		return append(h.Initial(), plain[1:]...), nil, nil
	}
	if plain[0] != 2 || len(plain) != 89 {
		return nil, nil, ErrAuthentication
	}
	n := *h.noise // Invalid responses must not corrupt the pending handshake.
	n.ephemeral(plain[1:33])
	if err = n.exchange(h.private, plain[1:33]); err != nil {
		return nil, nil, err
	}
	confirmation, err := n.open(plain[33:])
	if err != nil || len(confirmation) != 40 || !hmac.Equal(confirmation[:24], wire[:24]) {
		return nil, nil, ErrAuthentication
	}
	send, receive := n.split()
	session = &DatagramSession{header: h.header, name: h.cfg.Cipher, initiator: true, ingress: h.cfg.IngressID, sendRoot: send, receiveRoot: receive}
	copy(session.id[:], confirmation[24:])
	h.completed = true
	return nil, session, nil
}
func NewDatagramServer(cfg ServerConfig) (*DatagramServer, error) {
	if !ValidCipher(cfg.Cipher) || cfg.Transport != "raw_udp" || cfg.ExitID <= 0 || cfg.LinkKey == nil {
		return nil, ErrAuthentication
	}
	cover, err := datagramCover(cfg.Key)
	if err != nil {
		return nil, err
	}
	header, err := newDatagramHeader(cfg.Key)
	if err != nil {
		return nil, err
	}
	s := &DatagramServer{cfg: cfg, cover: cover, header: header, gate: handshakereplay.NewGate(cfg.Replay), requests: make(map[[32]byte]*DatagramRequest)}
	_, err = rand.Read(s.cookieSecret[:])
	return s, err
}
func (s *DatagramServer) ParsePacket(wire []byte) (DatagramPacket, error) {
	return s.header.parse(wire, true)
}

func (s *DatagramServer) Complete(digest [32]byte) {
	s.gate.Retire(digest)
	s.mu.Lock()
	r := s.requests[digest]
	delete(s.requests, digest)
	s.mu.Unlock()
	if r != nil {
		r.mu.Lock()
		r.failed = true
		r.noise = nil
		r.reply = nil
		r.session = nil
		r.mu.Unlock()
	}
}

// The bucket is implicit: returning a clear timestamp here would create a
// predictable wire prefix. Salt and a truncated HMAC are both opaque on wire.
func (s *DatagramServer) cookie(source string, hash [32]byte, salt []byte, bucket int64) []byte {
	cookie := make([]byte, 40)
	copy(cookie[:16], salt)
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(bucket))
	m := hmac.New(sha256.New, s.cookieSecret[:])
	m.Write([]byte(source))
	m.Write(hash[:])
	m.Write(cookie[:16])
	m.Write(epoch[:])
	copy(cookie[16:], m.Sum(nil)[:24])
	return cookie
}
func (s *DatagramServer) response(salt [24]byte, kind byte, payload []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return s.cover.Seal(nonce[:], nonce[:], append([]byte{kind}, payload...), append([]byte("server"), salt[:]...)), nil
}

// Check validates the client's PSK before answering a source-address challenge.
// No DH or target socket is created before a source-bound challenge. Small,
// bounded pending entries are retained only for authenticated first flights.
func (s *DatagramServer) Check(wire []byte, source string) (*DatagramRequest, []byte, error) {
	if len(wire) != DatagramInitialSize && len(wire) != DatagramInitialSize+DatagramCookieSize {
		return nil, nil, ErrAuthentication
	}
	first := wire[:DatagramInitialSize]
	message, err := s.cover.Open(nil, first[:24], first[24:], []byte("client"))
	if err != nil || len(message) != routeSize+48 {
		return nil, nil, ErrAuthentication
	}
	route := message[:routeSize]
	ingress := int64(binary.BigEndian.Uint64(route[3:11]))
	exit := int64(binary.BigEndian.Uint64(route[11:]))
	stamp := int64(binary.BigEndian.Uint64(route[19:27]))
	if route[0] != 4 || route[1] != cipherID(s.cfg.Cipher) || route[2] != 3 || ingress <= 0 || exit != s.cfg.ExitID || !handshakereplay.ValidTimestamp(stamp, time.Now().Unix()) {
		return nil, nil, ErrAuthentication
	}
	token, ok := s.cfg.LinkKey(ingress)
	if !ok {
		return nil, nil, ErrAuthentication
	}
	psk, err := linkKey(token)
	if err != nil {
		return nil, nil, err
	}
	n := newNoise(s.cfg.Cipher, datagramPrologue(route, first[:24]), psk)
	pub := message[routeSize : routeSize+32]
	n.ephemeral(pub)
	if _, err = n.open(message[routeSize+32:]); err != nil {
		return nil, nil, err
	}
	r := &DatagramRequest{server: s, noise: n, public: append([]byte(nil), pub...), digest: sha256.Sum256(first), ingress: ingress, link: token, expires: handshakereplay.Expiry(stamp)}
	copy(r.salt[:], first[:24])
	challenge, verified, err := s.gate.Exchange(r.digest, source, r.expires, wire[DatagramInitialSize:], func() ([]byte, []byte, error) {
		var salt [16]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return nil, nil, err
		}
		cookie := s.cookie(source, r.digest, salt[:], time.Now().Unix()/60)
		reply, err := s.response(r.salt, 1, cookie)
		return reply, cookie, err
	})
	if err != nil || !verified {
		return nil, challenge, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gate.Pending(r.digest) {
		return nil, nil, ErrAuthentication
	}
	now := time.Now().Unix()
	if s.pruned != now || len(s.requests) >= handshakereplay.Limit {
		for key, request := range s.requests {
			if request.expires <= now {
				delete(s.requests, key)
			}
		}
		s.pruned = now
	}
	if cached := s.requests[r.digest]; cached != nil {
		return cached, nil, nil
	}
	if len(s.requests) >= handshakereplay.Limit {
		return nil, nil, ErrAuthentication
	}
	s.requests[r.digest] = r
	return r, nil, nil
}
func (r *DatagramRequest) Respond() (reply []byte, session *DatagramSession, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return nil, nil, ErrAuthentication
	}
	if r.session != nil {
		return append([]byte(nil), r.reply...), r.session, nil
	}
	reply, session, err = r.respond()
	if err != nil {
		r.failed = true
		return nil, nil, err
	}
	r.reply, r.session = append([]byte(nil), reply...), session
	return reply, session, nil
}
func (r *DatagramRequest) respond() (reply []byte, session *DatagramSession, err error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	n := *r.noise
	pub := private.PublicKey().Bytes()
	n.ephemeral(pub)
	if err = n.exchange(private, r.public); err != nil {
		return nil, nil, err
	}
	var nonce [24]byte
	var id [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(id[:]); err != nil {
		return nil, nil, err
	}
	payload := append(nonce[:], id[:]...)
	message := append([]byte{2}, pub...)
	message = append(message, n.seal(payload)...)
	reply = r.server.cover.Seal(nonce[:], nonce[:], message, append([]byte("server"), r.salt[:]...))
	send, receive := n.split()
	session = &DatagramSession{id: id, header: r.server.header, name: r.server.cfg.Cipher, initiator: false, ingress: r.ingress, sendRoot: receive, receiveRoot: send}
	return reply, session, nil
}
