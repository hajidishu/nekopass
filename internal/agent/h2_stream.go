package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Four-byte lengths in the encrypted response preserve a download FIN while
// request upload is still open. A zero length is FIN; frame bytes aren't billed.
type h2PayloadReader struct {
	body      io.ReadCloser
	remaining uint32
	finished  bool
}

func (r *h2PayloadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.finished {
		return 0, io.EOF
	}
	if r.remaining == 0 {
		var header [4]byte
		if _, err := io.ReadFull(r.body, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		r.remaining = binary.BigEndian.Uint32(header[:])
		if r.remaining == 0 {
			r.finished = true
			return 0, io.EOF
		}
		if r.remaining > 64<<10 {
			return 0, errors.New("TLS stream frame too large")
		}
	}
	n, err := r.body.Read(p[:min(len(p), int(r.remaining))])
	r.remaining -= uint32(n)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (r *h2PayloadReader) Close() error { return r.body.Close() }

// A request body is the TCP upload; END_STREAM is its independent FIN.
// The response body remains readable after CloseWrite.
type h2StreamConn struct {
	r                               io.ReadCloser
	w                               *io.PipeWriter
	cancel                          context.CancelFunc
	local, remote                   net.Addr
	mu                              sync.Mutex
	readTimer, writeTimer           *time.Timer
	readGeneration, writeGeneration uint64
	deadline                        bool
	closed                          bool
	once                            sync.Once
}

func (c *h2StreamConn) Read(p []byte) (int, error) { n, err := c.r.Read(p); return n, c.mapError(err) }
func (c *h2StreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	return n, c.mapError(err)
}
func (c *h2StreamConn) mapError(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil && c.deadline {
		return os.ErrDeadlineExceeded
	}
	return err
}
func (c *h2StreamConn) CloseWrite() error { return c.w.Close() }
func (c *h2StreamConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.mu.Unlock()
		c.cancel()
		c.w.CloseWithError(net.ErrClosed)
		c.r.Close()
	})
	return nil
}
func (c *h2StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *h2StreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *h2StreamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *h2StreamConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true) }
func (c *h2StreamConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false) }
func (c *h2StreamConn) setDeadline(t time.Time, read bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	timer := &c.writeTimer
	generation := &c.writeGeneration
	if read {
		timer = &c.readTimer
		generation = &c.readGeneration
	}
	*generation++
	current := *generation
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if !t.IsZero() {
		*timer = time.AfterFunc(max(time.Until(t), 0), func() { c.expireDeadline(read, current) })
	}
	return nil
}

func (c *h2StreamConn) expireDeadline(read bool, generation uint64) {
	c.mu.Lock()
	current := c.writeGeneration
	if read {
		current = c.readGeneration
	}
	if c.closed || current != generation {
		c.mu.Unlock()
		return
	}
	c.deadline = true
	c.mu.Unlock()
	c.Close()
}
