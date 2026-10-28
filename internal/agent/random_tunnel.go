package agent

import (
	"context"
	"errors"
	"net"
	"sync"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

func dialRandom(ctx context.Context, conn net.Conn, r *pb.Rule) (*tunnelcrypto.Conn, error) {
	if r.Random == nil {
		conn.Close()
		return nil, errors.New("random encryption settings missing")
	}
	transport, _ := tunnel.Split(r.TunnelProtocol)
	return tunnelcrypto.Dial(ctx, conn, tunnelcrypto.ClientConfig{Cipher: r.Random.Cipher, Key: r.Random.Key, LinkKey: r.TunnelToken, Transport: transport, IngressID: r.IngressNodeId, ExitID: r.EgressNodeId})
}

// Work is bounded before launching a handshake. Invalid clients receive no
// application response; HTTP/2 is started only after mutual authentication.
type randomListener struct {
	net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	ready  chan net.Conn
	wg     sync.WaitGroup
}

func (e *Engine) newRandomListener(ctx context.Context, ln net.Listener, node *pb.NodeConfig) (net.Listener, error) {
	if node.Random == nil {
		return nil, errors.New("random encryption settings missing")
	}
	transport, _ := tunnel.Split(node.TunnelProtocol)
	server, err := tunnelcrypto.NewServer(tunnelcrypto.ServerConfig{Cipher: node.Random.Cipher, Key: node.Random.Key, Transport: transport, ExitID: node.NodeId, LinkKey: func(id int64) (string, bool) {
		policy := e.tunnelPolicy.Load()
		if policy == nil {
			return "", false
		}
		key, ok := policy.links[id]
		return key, ok
	}})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &randomListener{Listener: ln, ctx: ctx, cancel: cancel, ready: make(chan net.Conn)}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer cancel()
		stop := context.AfterFunc(ctx, func() { ln.Close() })
		defer stop()
		slots := make(chan struct{}, 128)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				defer func() { <-slots }()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				secured, err := server.Accept(ctx, conn)
				if err != nil {
					return
				}
				select {
				case l.ready <- secured:
				case <-ctx.Done():
					secured.Close()
				}
			}()
		}
	}()
	return l, nil
}
func (l *randomListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *randomListener) Close() error {
	l.cancel()
	err := l.Listener.Close()
	l.wg.Wait()
	return err
}

func authenticatedIngress(c net.Conn) int64 {
	if v, ok := c.(interface{ AuthenticatedIngress() int64 }); ok {
		return v.AuthenticatedIngress()
	}
	return 0
}
