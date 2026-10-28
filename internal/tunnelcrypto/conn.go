package tunnelcrypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
)

// Each record is AEAD(length[2]) followed by AEAD(type[1] || payload).
// Independent directional header/data keys are derived from the Noise split.
// Nonces are implicit; keys rotate every 2^16 records (<=2 GiB per epoch).
// An authenticated FIN is required; bare EOF is truncation, not graceful close.
type recordState struct {
	root         []byte
	seq, epoch   uint64
	header, data cipher.AEAD
}
type Conn struct {
	net.Conn
	name                    string
	binding                 [32]byte
	ingress                 int64
	readMu, writeMu         sync.Mutex
	rd, wr                  recordState
	input                   []byte
	readBuffer              *[]byte
	readClosed, writeClosed bool
}

var buffers = sync.Pool{New: func() any { b := make([]byte, MaxRecord+35); return &b }}

func (c *Conn) releaseReadBuffer() {
	if c.readBuffer != nil {
		buffers.Put(c.readBuffer)
		c.readBuffer = nil
	}
}

func newConn(c net.Conn, name string, send, receive []byte, binding [32]byte, ingress int64) *Conn {
	return &Conn{Conn: c, name: name, binding: binding, ingress: ingress, rd: recordState{root: receive}, wr: recordState{root: send}}
}
func (c *Conn) AuthenticatedIngress() int64 { return c.ingress }
func (c *Conn) Binding() []byte             { return append([]byte(nil), c.binding[:]...) }
func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.readMu.Lock()
	c.input = nil
	c.releaseReadBuffer()
	c.readMu.Unlock()
	return err
}
func (c *Conn) keys(s *recordState) error {
	if s.seq == math.MaxUint64 {
		return errors.New("encrypted record counter exhausted")
	}
	epoch := s.seq >> 16
	if s.header != nil && s.epoch == epoch {
		return nil
	}
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], epoch)
	label := "nekopass/random/v1/records/" + string(id[:])
	k := derive(s.root, label, 64)
	var err error
	s.header, err = newAEAD(c.name, k[:32])
	if err != nil {
		return err
	}
	s.data, err = newAEAD(c.name, k[32:])
	s.epoch = epoch
	return err
}
func (c *Conn) writeRecord(kind byte, payload []byte) error {
	if err := c.keys(&c.wr); err != nil {
		return err
	}
	n := nonce(c.name, c.wr.seq)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)+1))
	buf := buffers.Get().(*[]byte)
	defer buffers.Put(buf)
	header := c.wr.header.Seal((*buf)[:0], n[:], length[:], c.binding[:])
	plain := (*buf)[18 : 19+len(payload)]
	plain[0] = kind
	copy(plain[1:], payload)
	wire := c.wr.data.Seal(header, n[:], plain, header)
	c.wr.seq++
	if err := writeFull(c.Conn, wire); err != nil {
		c.Conn.Close()
		return err
	}
	return nil
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), MaxRecord)
		if err := c.writeRecord(1, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	if err := c.writeRecord(2, nil); err != nil {
		return err
	}
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.input) > 0 {
		n := copy(p, c.input)
		c.input = c.input[n:]
		if len(c.input) == 0 {
			c.input = nil
			c.releaseReadBuffer()
		}
		return n, nil
	}
	if c.readClosed {
		return 0, io.EOF
	}
	if err := c.keys(&c.rd); err != nil {
		return 0, err
	}
	n := nonce(c.name, c.rd.seq)
	header := make([]byte, 18)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		c.Conn.Close()
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	length, err := c.rd.header.Open(nil, n[:], header, c.binding[:])
	if err != nil {
		return c.reject()
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 1 || size > MaxRecord+1 {
		return c.reject()
	}
	buf := buffers.Get().(*[]byte)
	data := (*buf)[:size+16]
	if _, err = io.ReadFull(c.Conn, data); err != nil {
		buffers.Put(buf)
		c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	plain, err := c.rd.data.Open(data[:0], n[:], data, header)
	if err != nil {
		buffers.Put(buf)
		return c.reject()
	}
	c.rd.seq++
	switch plain[0] {
	case 1:
		if len(plain) == 1 {
			buffers.Put(buf)
			return c.reject()
		}
		n := copy(p, plain[1:])
		c.input = plain[1+n:]
		if len(c.input) > 0 {
			c.readBuffer = buf
		} else {
			c.input = nil
			buffers.Put(buf)
		}
		return n, nil
	case 2:
		buffers.Put(buf)
		if len(plain) != 1 {
			return c.reject()
		}
		c.readClosed = true
		return 0, io.EOF
	default:
		buffers.Put(buf)
		return c.reject()
	}
}
func (c *Conn) reject() (int, error) { c.Conn.Close(); return 0, ErrAuthentication }
