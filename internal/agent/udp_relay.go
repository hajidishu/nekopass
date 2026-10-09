package agent

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// A relay never meters at the exit: the ingress charges each payload once.
func (e *Engine) relayDatagrams(ctx context.Context, peer, target net.Conn, allowed func() bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { peer.Close(); target.Close() })
	defer stop()
	last := time.Now()
	var mu sync.Mutex
	finished := make(chan struct{}, 2)
	copyPackets := func(dst, src net.Conn) {
		defer func() { cancel(); finished <- struct{}{} }()
		buf := make([]byte, maxDatagram)
		for {
			n, err := src.Read(buf)
			if err != nil || ctx.Err() != nil || !allowed() || !e.targetAllowed(target) {
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(time.Second))
			written, err := dst.Write(buf[:n])
			_ = dst.SetWriteDeadline(time.Time{})
			if err != nil || written != n {
				return
			}
			mu.Lock()
			last = time.Now()
			mu.Unlock()
		}
	}
	go copyPackets(target, peer)
	go copyPackets(peer, target)
	timeout := 60 * time.Second
	if cfg := e.node.Load(); cfg != nil && cfg.UdpIdleTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.UdpIdleTimeoutSeconds) * time.Second
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			peer.Close()
			target.Close()
			<-finished
			<-finished
			return
		case <-tick.C:
			mu.Lock()
			idle := time.Since(last) > timeout
			mu.Unlock()
			if idle || !allowed() || !e.targetAllowed(target) {
				cancel()
			}
		}
	}
}

type httpDatagramConn struct {
	r      io.ReadCloser
	w      io.Writer
	flush  func() error
	cancel context.CancelFunc
}

func (c *httpDatagramConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *httpDatagramConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(p)))
	if _, err := c.w.Write(head[:]); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err == nil {
		err = c.flush()
	}
	return n, err
}
func (c *httpDatagramConn) Close() error                     { c.cancel(); return c.r.Close() }
func (c *httpDatagramConn) LocalAddr() net.Addr              { return datagramAddr("HTTP/2") }
func (c *httpDatagramConn) RemoteAddr() net.Addr             { return datagramAddr("HTTP/2") }
func (c *httpDatagramConn) SetDeadline(time.Time) error      { return nil }
func (c *httpDatagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpDatagramConn) SetWriteDeadline(time.Time) error { return nil }

type datagramAddr string

func (a datagramAddr) Network() string { return "udp" }
func (a datagramAddr) String() string  { return string(a) }
