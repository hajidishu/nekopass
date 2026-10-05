package control

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// The advertised HTTPS endpoint can be a reverse proxy. With no local
// certificate the backend stays h2c; HTTP selects a directly accessible h2c port.
type agentListenPlan struct {
	address, mode, endpoint string
	credentials             credentials.TransportCredentials
}

type agentListener struct {
	mu                         sync.Mutex
	listener                   net.Listener
	plan                       agentListenPlan
	closed                     bool
	address, certFile, keyFile string
}

func (l *agentListener) prepare(v SystemSettings) (agentListenPlan, error) {
	p := agentListenPlan{address: l.address, mode: "proxy", credentials: insecure.NewCredentials()}
	if v.AgentHost != "" {
		p.endpoint = controlInstallServer(v)
	}
	if v.AgentTransport == "plain" {
		p.mode = "plain"
		host, port, err := net.SplitHostPort(l.address)
		if err != nil {
			return p, err
		}
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			host = "0.0.0.0"
			if ip != nil && ip.To4() == nil {
				host = "::"
			}
			p.address = net.JoinHostPort(host, port)
		}
	} else if l.certFile != "" || l.keyFile != "" {
		pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
		if err != nil {
			return p, errors.New("无法加载节点控制端口的 TLS 证书和私钥，请检查主控证书配置")
		}
		p.mode = "tls"
		p.credentials = credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	}
	return p, nil
}

func (l *agentListener) apply(p agentListenPlan) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	if p.address != l.plan.address {
		previous := l.listener
		previous.Close()
		next, err := net.Listen("tcp", p.address)
		if err != nil {
			l.listener, _ = net.Listen("tcp", l.plan.address)
			if l.listener == nil {
				l.closed = true
			}
			return errors.New("无法切换节点控制端口的监听地址，请检查端口占用")
		}
		l.listener = next
	}
	l.plan = p
	return nil
}

func (l *agentListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		ln, closed := l.listener, l.closed
		l.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		c, err := ln.Accept()
		if err == nil {
			return c, nil
		}
		l.mu.Lock()
		replaced := !l.closed && ln != l.listener
		l.mu.Unlock()
		if !replaced {
			return nil, err
		}
	}
}
func (l *agentListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.listener.Close()
}
func (l *agentListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.listener.Addr()
}
func (l *agentListener) current() agentListenPlan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.plan
}

type agentCredentials struct{ listener *agentListener }

func (c *agentCredentials) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.listener.current().credentials.ClientHandshake(ctx, authority, conn)
}
func (c *agentCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.listener.current().credentials.ServerHandshake(conn)
}
func (c *agentCredentials) Info() credentials.ProtocolInfo {
	return c.listener.current().credentials.Info()
}
func (c *agentCredentials) Clone() credentials.TransportCredentials {
	return &agentCredentials{listener: c.listener}
}
func (c *agentCredentials) OverrideServerName(string) error {
	return errors.New("server-side credentials")
}

func (s *Server) StartAgentListener(ctx context.Context, address, certFile, keyFile string) (net.Listener, credentials.TransportCredentials, error) {
	v, err := s.readSettings(ctx)
	if err != nil {
		return nil, nil, err
	}
	l := &agentListener{address: address, certFile: certFile, keyFile: keyFile}
	p, err := l.prepare(v)
	if err != nil {
		return nil, nil, err
	}
	l.listener, err = net.Listen("tcp", p.address)
	if err != nil {
		return nil, nil, err
	}
	if _, port, _ := net.SplitHostPort(address); port == "0" {
		p.address = l.listener.Addr().String()
		l.address = p.address
	}
	l.plan = p
	s.agentListener = l
	return l, &agentCredentials{listener: l}, nil
}

func (s *Server) agentListenerStatus() any {
	if s.agentListener == nil {
		return nil
	}
	p := s.agentListener.current()
	return map[string]string{"address": p.address, "mode": p.mode}
}

func (s *Server) controlEndpoint() string {
	if s.agentListener == nil {
		return ""
	}
	return s.agentListener.current().endpoint
}
