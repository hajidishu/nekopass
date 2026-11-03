package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// Yamux writes DATA headers and bodies separately. Hold only its 12-byte header
// until the first body write; control frames are sent immediately. The padding
// layer underneath shapes each resulting write without a timer or flush delay.
type muxWriteConn struct {
	net.Conn
	mu        sync.Mutex
	header    [12]byte
	pending   bool
	remaining uint32
	failed    error
}

var muxJoinBuffers = sync.Pool{New: func() any { b := make([]byte, 16<<10); return &b }}

func (c *muxWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return 0, c.failed
	}
	if c.pending {
		if len(p) == 0 {
			return 0, nil
		}
		if uint64(len(p)) > uint64(c.remaining) {
			c.failed = errors.New("invalid Mux DATA body")
			c.Conn.Close()
			return 0, c.failed
		}
		holder := muxJoinBuffers.Get().(*[]byte)
		defer muxJoinBuffers.Put(holder)
		first := *holder
		n := min(len(p), len(first)-len(c.header))
		copy(first[:], c.header[:])
		copy(first[len(c.header):], p[:n])
		written, err := c.Conn.Write(first[:len(c.header)+n])
		accepted := max(0, written-len(c.header))
		if err == nil && written != len(c.header)+n {
			err = io.ErrShortWrite
		}
		c.pending = false
		c.remaining -= uint32(accepted)
		if err == nil && n < len(p) {
			var more int
			more, err = c.Conn.Write(p[n:])
			accepted += more
			c.remaining -= uint32(more)
			if err == nil && more != len(p)-n {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			c.failed = err
			c.Conn.Close()
		}
		return accepted, err
	}
	if c.remaining > 0 {
		if uint64(len(p)) > uint64(c.remaining) {
			c.failed = errors.New("invalid Mux DATA continuation")
			c.Conn.Close()
			return 0, c.failed
		}
		n, err := c.Conn.Write(p)
		c.remaining -= uint32(n)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err != nil {
			c.failed = err
			c.Conn.Close()
		}
		return n, err
	}
	if len(p) != 12 || p[0] != 0 || p[1] > 3 {
		c.failed = errors.New("invalid Mux frame header")
		c.Conn.Close()
		return 0, c.failed
	}
	if p[1] == 0 {
		size := binary.BigEndian.Uint32(p[8:])
		if size > 256<<10 {
			c.failed = errors.New("Mux DATA frame too large")
			c.Conn.Close()
			return 0, c.failed
		}
		if size > 0 {
			copy(c.header[:], p)
			c.remaining = size
			c.pending = true
			return len(p), nil
		}
	}
	n, err := c.Conn.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.failed = err
		c.Conn.Close()
	}
	return n, err
}
