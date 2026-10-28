package tunnelcrypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"

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
}
type DatagramRequest struct {
	server  *DatagramServer
	noise   *noiseState
	public  []byte
	salt    [24]byte
	digest  [32]byte
	ingress int64
	link    string
}

func (r *DatagramRequest) Digest() [32]byte { return r.digest }
func (r *DatagramRequest) IngressID() int64 { return r.ingress }
func (r *DatagramRequest) LinkKey() string  { return r.link }
func datagramPrologue(route, salt []byte) []byte {
	return append(append([]byte("nekopass/random/udp/v1/handshake\x00"), route...), salt...)
}
func datagramCover(key string) (cipher.AEAD, error) {
	b, err := DecodeKey(key)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(derive(b, "nekopass/random/udp/v1/cover", 32))
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
	route[0] = 2
	route[1] = cipherID(cfg.Cipher)
	route[2] = 3
	binary.BigEndian.PutUint64(route[3:11], uint64(cfg.IngressID))
	binary.BigEndian.PutUint64(route[11:], uint64(cfg.ExitID))
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
	s := &DatagramServer{cfg: cfg, cover: cover, header: header}
	_, err = rand.Read(s.cookieSecret[:])
	return s, err
}
func (s *DatagramServer) ParsePacket(wire []byte) (DatagramPacket, error) {
	return s.header.parse(wire, true)
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
// No DH, target socket, or per-client allocation is retained until the cookie
// proves return reachability. The caller deduplicates validated requests.
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
	if route[0] != 2 || route[1] != cipherID(s.cfg.Cipher) || route[2] != 3 || ingress <= 0 || exit != s.cfg.ExitID {
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
	r := &DatagramRequest{server: s, noise: n, public: pub, digest: sha256.Sum256(first), ingress: ingress, link: token}
	copy(r.salt[:], first[:24])
	valid := false
	now := time.Now().Unix() / 60
	if len(wire) > DatagramInitialSize {
		c := wire[DatagramInitialSize:]
		current := hmac.Equal(c, s.cookie(source, r.digest, c[:16], now))
		previous := hmac.Equal(c, s.cookie(source, r.digest, c[:16], now-1))
		valid = current || previous
	}
	if !valid {
		var salt [16]byte
		if _, err = rand.Read(salt[:]); err != nil {
			return nil, nil, err
		}
		reply, err := s.response(r.salt, 1, s.cookie(source, r.digest, salt[:], now))
		return nil, reply, err
	}
	return r, nil, nil
}
func (r *DatagramRequest) Respond() (reply []byte, session *DatagramSession, err error) {
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
