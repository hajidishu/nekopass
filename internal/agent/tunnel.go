package agent

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

var tunnelMagic = [4]byte{'N', 'P', 'T', 1}

type tunnelListener struct {
	ln     net.Listener
	cancel context.CancelFunc
	config *pb.ControlMessage
}
type tunnelPolicy struct {
	links       map[int64]string
	rules       map[int64]*pb.EgressRule
	dialTimeout time.Duration
}

func tunnelRuleAllowed(policy *tunnelPolicy, ruleID, ingress, userID, epoch int64, target string) bool {
	if policy == nil {
		return false
	}
	allowed := policy.rules[ruleID]
	if allowed == nil || allowed.IngressNodeId != ingress || allowed.UserId != userID || allowed.QuotaEpoch != epoch || allowed.ExpiresUnix != 0 && time.Now().Unix() >= allowed.ExpiresUnix {
		return false
	}
	for _, address := range allowed.Targets {
		if address == target {
			return true
		}
	}
	return false
}

func (e *Engine) plainTunnelAllowed(ruleID, ingress, userID, epoch int64, target, key string) bool {
	node := e.node.Load()
	policy := e.tunnelPolicy.Load()
	return node != nil && node.Enabled && node.TunnelExitEnabled && node.TunnelProtocol == "plain_tcp" && policy != nil && policy.links[ingress] == key && tunnelRuleAllowed(policy, ruleID, ingress, userID, epoch, target)
}

// Each connection carries one framed request and one response before raw TCP
// bytes are relayed. The separate policy structs leave room for later protocols.
func writeTunnelHello(conn net.Conn, rule *pb.Rule, target string) error {
	if len(rule.TunnelToken) != 64 || len(target) == 0 || len(target) > 512 {
		return errors.New("invalid tunnel configuration")
	}
	var header [4 + 8 + 8 + 64 + 2]byte
	copy(header[:4], tunnelMagic[:])
	binary.BigEndian.PutUint64(header[4:12], uint64(rule.IngressNodeId))
	binary.BigEndian.PutUint64(header[12:20], uint64(rule.Id))
	copy(header[20:84], rule.TunnelToken)
	binary.BigEndian.PutUint16(header[84:86], uint16(len(target)))
	if _, e := conn.Write(header[:]); e != nil {
		return e
	}
	_, e := io.WriteString(conn, target)
	return e
}

func dialTunnel(ctx context.Context, rule *pb.Rule, target string) (net.Conn, error) {
	if rule.TunnelProtocol != "plain_tcp" {
		return nil, errors.New("unsupported tunnel protocol")
	}
	if rule.TunnelHost == "" || rule.TunnelPort < 1 {
		return nil, errors.New("tunnel destination unavailable")
	}
	d := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort(rule.TunnelHost, strconv.Itoa(int(rule.TunnelPort))))
	if e != nil {
		return nil, e
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if e = writeTunnelHello(conn, rule, target); e != nil {
		conn.Close()
		return nil, e
	}
	var reply [1]byte
	if _, e = io.ReadFull(conn, reply[:]); e != nil {
		conn.Close()
		return nil, e
	}
	if reply[0] != 0 {
		conn.Close()
		return nil, fmt.Errorf("tunnel exit rejected target or connection: %d", reply[0])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func policyOf(c *pb.ControlMessage) *tunnelPolicy {
	p := &tunnelPolicy{links: map[int64]string{}, rules: map[int64]*pb.EgressRule{}, dialTimeout: 8 * time.Second}
	if c.Node != nil && c.Node.DialTimeoutSeconds > 0 {
		p.dialTimeout = time.Duration(c.Node.DialTimeoutSeconds) * time.Second
	}
	for _, link := range c.TunnelLinks {
		p.links[link.IngressNodeId] = link.Token
	}
	for _, rule := range c.EgressRules {
		p.rules[rule.RuleId] = proto.Clone(rule).(*pb.EgressRule)
	}
	return p
}

func (e *Engine) configureTunnel(c *pb.ControlMessage) error {
	if e.tunnel != nil {
		old := e.tunnel.config
		if c.Node != nil && c.Node.Enabled && c.Node.TunnelExitEnabled && old.Node != nil && old.Node.TunnelExitEnabled && old.Node.TunnelProtocol == c.Node.TunnelProtocol && old.Node.TunnelListenHost == c.Node.TunnelListenHost && old.Node.TunnelListenPort == c.Node.TunnelListenPort && sameH2Listener(old.Node.Tls, c.Node.Tls) {
			if c.Node.TunnelProtocol == "tls_h2" {
				pair, err := tls.X509KeyPair([]byte(c.Node.Tls.Certificate), []byte(c.Node.Tls.PrivateKey))
				if err != nil {
					return errors.New("TLS certificate update invalid")
				}
				e.h2Certificate.Store(&pair)
			}
			e.tunnelPolicy.Store(policyOf(c))
			e.tunnel.config = proto.Clone(c).(*pb.ControlMessage)
			return nil
		}
		e.tunnel.cancel()
		e.tunnel.ln.Close()
		e.tunnel = nil
	}
	if c.Node == nil || !c.Node.Enabled || !c.Node.TunnelExitEnabled {
		return nil
	}
	if c.Node.TunnelProtocol != "plain_tcp" && c.Node.TunnelProtocol != "tls_h2" {
		return errors.New("unsupported tunnel protocol")
	}
	if c.Node.TunnelListenPort < 1 || c.Node.TunnelListenPort > 65535 {
		return errors.New("invalid tunnel listen port")
	}
	address := net.JoinHostPort(c.Node.TunnelListenHost, strconv.Itoa(int(c.Node.TunnelListenPort)))
	if c.Node.TunnelProtocol == "tls_h2" {
		if c.Node.Tls == nil {
			return errors.New("TLS configuration not synchronized")
		}
		if _, err := tls.X509KeyPair([]byte(c.Node.Tls.Certificate), []byte(c.Node.Tls.PrivateKey)); err != nil {
			return errors.New("TLS certificate not ready")
		}
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.tunnel = &tunnelListener{ln: ln, cancel: cancel, config: proto.Clone(c).(*pb.ControlMessage)}
	e.tunnelPolicy.Store(policyOf(c))
	if c.Node.TunnelProtocol == "tls_h2" {
		if err := e.startH2Server(ctx, ln, c.Node.Tls); err != nil {
			cancel()
			ln.Close()
			e.tunnel = nil
			return err
		}
		return nil
	}
	e.wg.Add(1)
	go e.acceptTunnel(ctx, ln)
	return nil
}

func sameH2Listener(a, b *pb.TLSServerConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.StreamWindowMib == b.StreamWindowMib && a.ConnectionWindowMib == b.ConnectionWindowMib && a.MaxStreams == b.MaxStreams
}

func (e *Engine) acceptTunnel(ctx context.Context, ln net.Listener) {
	defer e.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		active := e.connections.Add(1)
		if cap := e.maxConnections.Load(); cap > 0 && active > cap {
			e.connections.Add(-1)
			conn.Close()
			continue
		}
		e.wg.Add(1)
		go func() { defer e.wg.Done(); defer e.connections.Add(-1); e.handleTunnel(ctx, conn) }()
	}
}
func (e *Engine) handleTunnel(ctx context.Context, upstream net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopUpstream := context.AfterFunc(ctx, func() { upstream.Close() })
	defer stopUpstream()
	defer upstream.Close()
	_ = upstream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var header [4 + 8 + 8 + 64 + 2]byte
	if _, err := io.ReadFull(upstream, header[:]); err != nil {
		return
	}
	if [4]byte(header[:4]) != tunnelMagic {
		return
	}
	ingress := int64(binary.BigEndian.Uint64(header[4:12]))
	ruleID := int64(binary.BigEndian.Uint64(header[12:20]))
	length := int(binary.BigEndian.Uint16(header[84:86]))
	if length < 1 || length > 512 {
		return
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(upstream, buf); err != nil {
		return
	}
	target := string(buf)
	policy := e.tunnelPolicy.Load()
	if policy == nil {
		return
	}
	allowed := policy.rules[ruleID]
	key := string(header[20:84])
	if allowed == nil || len(policy.links[ingress]) != 64 || policy.links[ingress] != key {
		_, _ = upstream.Write([]byte{1})
		return
	}
	userID, epoch := allowed.UserId, allowed.QuotaEpoch
	if !e.plainTunnelAllowed(ruleID, ingress, userID, epoch, target, key) {
		_, _ = upstream.Write([]byte{1})
		return
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !e.plainTunnelAllowed(ruleID, ingress, userID, epoch, target, key) {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-watchDone }()
	dialer := net.Dialer{Timeout: policy.dialTimeout, KeepAlive: 30 * time.Second}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_, _ = upstream.Write([]byte{2})
		return
	}
	defer targetConn.Close()
	stopTarget := context.AfterFunc(ctx, func() { targetConn.Close() })
	defer stopTarget()
	// Authorization may have changed while the target connection was opening.
	if ctx.Err() != nil || !e.plainTunnelAllowed(ruleID, ingress, userID, epoch, target, key) {
		_, _ = upstream.Write([]byte{1})
		return
	}
	_ = upstream.SetDeadline(time.Time{})
	if _, err = upstream.Write([]byte{0}); err != nil {
		return
	}
	finished := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, upstream)
		if tcp, ok := targetConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- err
	}()
	go func() {
		_, err := io.Copy(upstream, targetConn)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- err
	}()
	select {
	case <-ctx.Done():
		upstream.Close()
		targetConn.Close()
	case err = <-finished:
		if err != nil {
			upstream.Close()
			targetConn.Close()
		} else {
			_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
			_ = targetConn.SetDeadline(time.Now().Add(30 * time.Second))
		}
	}
	<-finished
}
