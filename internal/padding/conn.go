package padding

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const overhead = 7
const dataCommand = 2
const wasteCommand = 0
const finCommand = 3
const shapedDataCommand = 4
const chunkSize = 32 << 10

// Version 2 carries padding inside FIN itself. Both peers must negotiate this
// version before exchanging frames; a version 1 FIN has an empty payload.
const WireVersion = 2

// MuxWireVersion keeps short writes padded for the entire carrier lifetime.
const MuxWireVersion = 3
const finMin = 64
const finMax = 1024
const finReserve = overhead + finMax
const dataPaddingBudget = MaxBudget - finReserve

var frames = sync.Pool{New: func() any { b := make([]byte, chunkSize+overhead); return &b }}
var errFrame = errors.New("invalid padding tunnel frame or budget exhausted")

// Conn always reports business bytes, never frame headers or padding bytes.
// It owns per-connection state; no lock is shared with another connection.
type Conn struct {
	net.Conn
	scheme                                *Scheme
	readMu, writeMu                       sync.Mutex
	remaining                             int
	tailPadding                           int
	continuous                            bool
	finished, writeClosed                 bool
	writeCloseErr                         error
	reads, wasteBytes, extraBytes, writes int
}

func NewConn(c net.Conn, s *Scheme) *Conn { return &Conn{Conn: c, scheme: s} }

func NewMuxConn(c net.Conn, s *Scheme) *Conn { return &Conn{Conn: c, scheme: s, continuous: true} }

func header(command byte, length int) [overhead]byte {
	var h [overhead]byte
	h[0] = command
	if command != wasteCommand {
		binary.BigEndian.PutUint32(h[1:5], 1)
	}
	binary.BigEndian.PutUint16(h[5:], uint16(length))
	return h
}
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.finished {
		return 0, io.EOF
	}
	for c.remaining == 0 {
		if c.tailPadding > 0 {
			if err := discard(c.Conn, c.tailPadding); err != nil {
				return 0, err
			}
			c.tailPadding = 0
		}
		var h [overhead]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		id := binary.BigEndian.Uint32(h[1:5])
		n := int(binary.BigEndian.Uint16(h[5:]))
		switch h[0] {
		case dataCommand:
			if c.continuous || id != 1 || n == 0 || n > chunkSize {
				return 0, errFrame
			}
			c.remaining = n
		case shapedDataCommand:
			if !c.continuous || id != 1 || n < 4 || n > (15<<10)+2+256 {
				return 0, errFrame
			}
			var size [2]byte
			if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
				return 0, err
			}
			real := int(binary.BigEndian.Uint16(size[:]))
			extra := n - 2 - real
			if real < 1 || real > 15<<10 || extra < 1 || extra > 256 {
				return 0, errFrame
			}
			c.remaining, c.tailPadding = real, extra
		case wasteCommand:
			c.reads++
			c.wasteBytes += n + overhead
			if id != 0 || n == 0 || n > MaxRecord || c.reads > maxFrames || c.wasteBytes > MaxBudget {
				return 0, errFrame
			}
			if err := discard(c.Conn, n); err != nil {
				return 0, err
			}
		case finCommand:
			if id != 1 || n < finMin || n > finMax || c.reads >= maxFrames || c.wasteBytes+n+overhead > MaxBudget {
				return 0, errFrame
			}
			if err := discard(c.Conn, n); err != nil {
				return 0, err
			}
			c.reads++
			c.wasteBytes += n + overhead
			c.finished = true
			return 0, io.EOF
		default:
			return 0, errFrame
		}
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func discard(r io.Reader, n int) error {
	_, err := io.CopyN(io.Discard, r, int64(n))
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
func write(c net.Conn, b []byte) (int, error) {
	n, err := c.Write(b)
	if n != len(b) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

// shaped writes complete serialized data frames, splitting TLS writes if the
// policy requests it. Waste is inserted only after a complete real frame.
func (c *Conn) shaped(b []byte) (sent int, err error) {
	c.writes++
	if c.writes < c.scheme.stop && c.extraBytes < dataPaddingBudget {
		for _, r := range c.scheme.rules[c.writes] {
			if r.low < 0 {
				if len(b) == 0 {
					break
				}
				continue
			}
			size, e := randomSize(r)
			if e != nil {
				return sent, e
			}
			if len(b) > size {
				n, e := write(c.Conn, b[:size])
				sent += n
				if e != nil {
					return sent, e
				}
				b = b[size:]
				continue
			}
			if len(b) > 0 {
				extra := size - len(b)
				if extra > overhead && c.extraBytes+extra <= dataPaddingBudget {
					// The caller's pooled frame has room for the final fragment and
					// padding is small and bounded; never retain it between writes.
					out := make([]byte, len(b)+extra)
					copy(out, b)
					h := header(wasteCommand, extra-overhead)
					copy(out[len(b):], h[:])
					c.extraBytes += extra
					n, e := write(c.Conn, out)
					sent += min(n, len(b))
					if e != nil {
						return sent, e
					}
				} else {
					n, e := write(c.Conn, b)
					sent += n
					if e != nil {
						return sent, e
					}
				}
				b = nil
			} else if c.extraBytes+size+overhead <= dataPaddingBudget {
				h := header(wasteCommand, size)
				out := make([]byte, overhead+size)
				copy(out, h[:])
				c.extraBytes += len(out)
				if _, e := write(c.Conn, out); e != nil {
					return sent, e
				}
			}
		}
	}
	if len(b) > 0 {
		n, e := write(c.Conn, b)
		return sent + n, e
	}
	return sent, nil
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}
	holder := frames.Get().(*[]byte)
	defer frames.Put(holder)
	total := 0
	for len(p) > 0 {
		n := min(len(p), chunkSize)
		prefix, extra, command := overhead, 0, byte(dataCommand)
		if c.continuous {
			n = min(len(p), 15<<10)
			maxExtra := 256
			if n > 1024 {
				maxExtra = 64
			}
			var err error
			extra, err = randomSize(interval{1, maxExtra + 1})
			if err != nil {
				return total, err
			}
			prefix, command = overhead+2, shapedDataCommand
		}
		b := (*holder)[:prefix+n+extra]
		h := header(command, len(b)-overhead)
		copy(b, h[:])
		if c.continuous {
			binary.BigEndian.PutUint16(b[overhead:prefix], uint16(n))
		}
		copy(b[prefix:], p[:n])
		// Clear pooled tail bytes: no unrelated business data is carried as waste.
		clear(b[prefix+n:])
		written, err := c.shaped(b)
		total += max(0, min(n, written-prefix))
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return c.writeCloseErr
	}
	c.writeClosed = true
	// FIN is padded even after stop or the data-padding budget is reached.
	// A single bounded write avoids the former standalone seven-byte record.
	n, err := randomSize(interval{finMin, finMax + 1})
	if err == nil {
		frame := make([]byte, overhead+n)
		h := header(finCommand, n)
		copy(frame, h[:])
		c.extraBytes += len(frame)
		_, err = write(c.Conn, frame)
	}
	if err == nil {
		if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			err = half.CloseWrite()
		}
	}
	c.writeCloseErr = err
	if err != nil {
		// A partially sent FIN cannot be retried. Unblock the opposite reader.
		_ = c.Conn.Close()
	}
	return err
}
