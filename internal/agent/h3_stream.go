package agent

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type h3IO interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}
type h3StreamConn struct {
	h3IO
	ctx             context.Context
	cancel          context.CancelFunc
	stop            func() bool
	local, remote   net.Addr
	release         func()
	once            sync.Once
	readMu, writeMu sync.Mutex
	writeClosed     atomic.Bool
}

func newH3StreamConn(lifetime context.Context, str h3IO, local, remote net.Addr, release func()) *h3StreamConn {
	ctx, cancel := context.WithCancel(lifetime)
	var lease sync.Once
	finish := func() {
		lease.Do(func() {
			if release != nil {
				release()
			}
		})
	}
	c := &h3StreamConn{h3IO: str, ctx: ctx, cancel: cancel, local: local, remote: remote, release: finish}
	c.stop = context.AfterFunc(ctx, func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		finish()
	})
	return c
}
func (c *h3StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *h3StreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *h3StreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.h3IO.Read(p)
}
func (c *h3StreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.h3IO.Write(p)
}
func (c *h3StreamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed.Swap(true) {
		return nil
	}
	return c.h3IO.Close()
}

func (c *h3StreamConn) Close() error {
	c.once.Do(func() {
		c.stop()
		c.cancel()
		c.h3IO.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		// Keep data preceding a queued FIN eligible for retransmission.
		if !c.writeClosed.Load() {
			c.h3IO.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
		c.release()
	})
	return nil
}
