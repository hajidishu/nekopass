package tunnelcrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Datagram records use an encrypted routing header followed by independent
// AEAD records. No stream counters, clear session IDs, or clear packet types
// appear on the wire. The random header nonce is independent of the implicit
// body nonce, which is unique under each directional session key.
const DatagramMTU = 1200
const datagramHeaderSize = 64 // nonce[24] || AEAD(session[16] || sequence[8])
const MaxDatagramPayload = DatagramMTU - datagramHeaderSize - 16

var ErrReplay = errors.New("encrypted datagram replay")

type datagramHeaderKey struct{ aead cipher.AEAD }
type DatagramPacket struct {
	id        [16]byte
	seq       uint64
	wire      []byte
	key       *datagramHeaderKey
	initiator bool
}

func (p DatagramPacket) SessionID() [16]byte { return p.id }
func (p DatagramPacket) Sequence() uint64    { return p.seq }

type packetWindow struct {
	high uint64
	bits [128]uint64
}

func (w *packetWindow) available(seq uint64) bool {
	if seq == 0 || seq <= w.high && w.high-seq >= 8192 {
		return false
	}
	return seq > w.high || w.bits[(seq%8192)/64]&(uint64(1)<<(seq%64)) == 0
}
func (w *packetWindow) take(seq uint64) bool {
	if !w.available(seq) {
		return false
	}
	if seq > w.high {
		if seq-w.high >= 8192 {
			w.bits = [128]uint64{}
		} else {
			for i := w.high + 1; i <= seq; i++ {
				w.bits[(i%8192)/64] &^= uint64(1) << (i % 64)
			}
		}
		w.high = seq
	}
	w.bits[(seq%8192)/64] |= uint64(1) << (seq % 64)
	return true
}

type packetKey struct {
	epoch uint64
	aead  cipher.AEAD
}
type DatagramSession struct {
	id                    [16]byte
	ingress               int64
	initiator             bool
	name                  string
	header                *datagramHeaderKey
	sendRoot, receiveRoot []byte
	sendMu, receiveMu     sync.Mutex
	sequence              uint64
	sendKey               packetKey
	receiveKeys           [2]packetKey
	replay                packetWindow
}

func newDatagramHeader(key string) (*datagramHeaderKey, error) {
	b, err := DecodeKey(key)
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(derive(b, "nekopass/random/udp/v1/header", 32))
	return &datagramHeaderKey{aead: a}, err
}
func (h *datagramHeaderKey) parse(wire []byte, initiator bool) (DatagramPacket, error) {
	if len(wire) < datagramHeaderSize+16 || len(wire) > DatagramMTU {
		return DatagramPacket{}, ErrAuthentication
	}
	direction := byte(0)
	if initiator {
		direction = 1
	}
	var buf [24]byte
	plain, err := h.aead.Open(buf[:0], wire[:24], wire[24:64], []byte{direction})
	if err != nil {
		return DatagramPacket{}, ErrAuthentication
	}
	p := DatagramPacket{seq: binary.BigEndian.Uint64(plain[16:24]), wire: wire, key: h, initiator: initiator}
	copy(p.id[:], plain[:16])
	if p.seq == 0 || p.seq == math.MaxUint64 {
		return DatagramPacket{}, ErrAuthentication
	}
	return p, nil
}
func (s *DatagramSession) ID() [16]byte     { return s.id }
func (s *DatagramSession) IngressID() int64 { return s.ingress }
func (s *DatagramSession) Parse(wire []byte) (DatagramPacket, error) {
	return s.header.parse(wire, !s.initiator)
}
func (s *DatagramSession) epochKey(root []byte, epoch uint64) (cipher.AEAD, error) {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	return newAEAD(s.name, derive(root, "nekopass/random/udp/v1/data/"+string(e[:]), 32))
}
func (s *DatagramSession) Seal(payload []byte) ([]byte, error) {
	if len(payload) > MaxDatagramPayload {
		return nil, errors.New("encrypted datagram exceeds MTU")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sequence >= math.MaxUint64-1 {
		return nil, errors.New("encrypted datagram counter exhausted")
	}
	s.sequence++
	epoch := s.sequence >> 16
	if s.sendKey.aead == nil || s.sendKey.epoch != epoch {
		a, err := s.epochKey(s.sendRoot, epoch)
		if err != nil {
			return nil, err
		}
		s.sendKey = packetKey{epoch, a}
	}
	wire := make([]byte, 24, datagramHeaderSize+len(payload)+16)
	if _, err := rand.Read(wire); err != nil {
		return nil, err
	}
	var route [24]byte
	copy(route[:16], s.id[:])
	binary.BigEndian.PutUint64(route[16:], s.sequence)
	direction := byte(0)
	if s.initiator {
		direction = 1
	}
	wire = s.header.aead.Seal(wire, wire[:24], route[:], []byte{direction})
	n := nonce(s.name, s.sequence)
	return s.sendKey.aead.Seal(wire, n[:], payload, wire), nil
}

// Open authenticates before advancing replay or key-cache state. Successful
// plaintext aliases the packet's body; callers must own the packet buffer.
func (s *DatagramSession) Open(p DatagramPacket) ([]byte, error) {
	if p.key != s.header || p.id != s.id || p.initiator == s.initiator || len(p.wire) < 80 || len(p.wire) > DatagramMTU {
		return nil, ErrAuthentication
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if !s.replay.available(p.seq) {
		return nil, ErrReplay
	}
	epoch := p.seq >> 16
	var a cipher.AEAD
	for _, k := range s.receiveKeys {
		if k.aead != nil && k.epoch == epoch {
			a = k.aead
			break
		}
	}
	fresh := a == nil
	if fresh {
		var err error
		a, err = s.epochKey(s.receiveRoot, epoch)
		if err != nil {
			return nil, err
		}
	}
	n := nonce(s.name, p.seq)
	plain, err := a.Open(p.wire[64:64], n[:], p.wire[64:], p.wire[:64])
	if err != nil {
		return nil, ErrAuthentication
	}
	if !s.replay.take(p.seq) {
		return nil, ErrReplay
	}
	if fresh {
		s.receiveKeys[1] = s.receiveKeys[0]
		s.receiveKeys[0] = packetKey{epoch, a}
	}
	return plain, nil
}
