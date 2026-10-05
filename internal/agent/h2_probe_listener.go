package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// Capture only pre-handshake bytes. An early TLS alert is held back so that
// rejected ClientHello bytes can instead reach the real HTTPS decoy unchanged.
// Once a server flight has been emitted, the TLS transcript cannot be replayed.
type probeCaptureConn struct {
	net.Conn
	capturing atomic.Bool
	committed atomic.Bool
	mu        sync.Mutex
	input     []byte
	truncated bool
	once      sync.Once
	onClose   func()
}

func (c *probeCaptureConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if c.capturing.Load() && n > 0 {
		c.mu.Lock()
		if len(c.input)+n <= 64<<10 {
			c.input = append(c.input, p[:n]...)
		} else {
			c.truncated = true
		}
		c.mu.Unlock()
	}
	return n, e
}
func (c *probeCaptureConn) Write(p []byte) (int, error) {
	if c.capturing.Load() {
		if len(p) > 0 && p[0] == 21 && !c.committed.Load() {
			return len(p), nil
		}
		c.committed.Store(true)
	}
	return c.Conn.Write(p)
}
func (c *probeCaptureConn) Close() error { e := c.Conn.Close(); c.once.Do(c.onClose); return e }
func (c *probeCaptureConn) stopCapture() []byte {
	c.capturing.Store(false)
	c.mu.Lock()
	defer c.mu.Unlock()
	data := c.input
	c.input = nil
	if c.truncated {
		return nil
	}
	return data
}

type camouflageTLSListener struct {
	net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	settings    *tls.Config
	engine      *Engine
	ready       chan net.Conn
	mu          sync.Mutex
	closed      bool
	connections map[*probeCaptureConn]bool
	wg          sync.WaitGroup
}

func newCamouflageTLSListener(parent context.Context, ln net.Listener, settings *tls.Config, e *Engine) *camouflageTLSListener {
	ctx, cancel := context.WithCancel(parent)
	l := &camouflageTLSListener{Listener: ln, ctx: ctx, cancel: cancel, settings: settings, engine: e, ready: make(chan net.Conn), connections: map[*probeCaptureConn]bool{}}
	l.wg.Add(1)
	go l.acceptLoop()
	return l
}
func (l *camouflageTLSListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *camouflageTLSListener) Close() error {
	l.mu.Lock()
	l.closed = true
	list := make([]*probeCaptureConn, 0, len(l.connections))
	for c := range l.connections {
		list = append(list, c)
	}
	l.mu.Unlock()
	l.cancel()
	err := l.Listener.Close()
	for _, c := range list {
		c.Close()
	}
	l.wg.Wait()
	return err
}
func (l *camouflageTLSListener) acceptLoop() {
	defer l.wg.Done()
	for {
		raw, e := l.Listener.Accept()
		if e != nil {
			l.cancel()
			return
		}
		c := &probeCaptureConn{Conn: raw}
		c.capturing.Store(true)
		c.onClose = func() { l.mu.Lock(); delete(l.connections, c); l.mu.Unlock() }
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			raw.Close()
			return
		}
		l.connections[c] = true
		l.wg.Add(1)
		l.mu.Unlock()
		go func() { defer l.wg.Done(); l.route(c) }()
	}
}
func (l *camouflageTLSListener) route(c *probeCaptureConn) {
	settings := l.settings.Clone()
	settings.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		pair := l.engine.h2Certificate.Load()
		if pair == nil || len(pair.Certificate) == 0 {
			return nil, errors.New("certificate unavailable")
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return nil, e
		}
		if hello.ServerName == "" || leaf.VerifyHostname(hello.ServerName) != nil {
			return nil, errors.New("unknown TLS server name")
		}
		if e := hello.SupportsCertificate(pair); e != nil {
			return nil, e
		}
		if len(hello.SupportedProtos) > 0 {
			match := false
			for _, alpn := range hello.SupportedProtos {
				if alpn == "h2" || alpn == "http/1.1" {
					match = true
				}
			}
			if !match {
				return nil, errors.New("unsupported ALPN")
			}
		}
		return nil, nil
	}
	conn := tls.Server(c, settings)
	ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
	err := conn.HandshakeContext(ctx)
	cancel()
	captured := c.stopCapture()
	if err != nil {
		if !c.committed.Load() && len(captured) > 0 {
			l.fallback(c, captured)
		}
		c.Close()
		return
	}
	select {
	case l.ready <- conn:
	case <-l.ctx.Done():
		conn.Close()
	}
}
func (l *camouflageTLSListener) fallback(c *probeCaptureConn, captured []byte) {
	node := l.engine.node.Load()
	if node == nil || node.Tls == nil || node.Tls.FallbackUrl == "" {
		return
	}
	u, e := url.Parse(node.Tls.FallbackUrl)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
	defer cancel()
	upstream, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(l.ctx, func() { upstream.Close() })
	defer stop()
	deadline := time.Now().Add(30 * time.Second)
	c.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	if _, e = io.Copy(upstream, bytes.NewReader(captured)); e != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		io.Copy(upstream, c)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		close(done)
	}()
	io.Copy(c, upstream)
	c.Close()
	upstream.Close()
	<-done
}
