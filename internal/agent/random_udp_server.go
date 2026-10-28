package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
	"google.golang.org/protobuf/proto"
)

type randomUDPHandshakeReply struct {
	reply   []byte
	id      [16]byte
	expires time.Time
}
type randomUDPListener struct {
	e            *Engine
	node         *pb.NodeConfig
	ctx          context.Context
	cancel       context.CancelFunc
	socket       *net.UDPConn
	gate         *tunnelcrypto.DatagramServer
	mu           sync.Mutex
	associations map[[16]byte]*randomUDPAssociation
	handshakes   map[[32]byte]*randomUDPHandshakeReply
	slots        chan struct{}
	dials        chan struct{}
}

func (e *Engine) startRandomUDP(node *pb.NodeConfig) error {
	if node.Random == nil {
		return tunnelcrypto.ErrAuthentication
	}
	gate, err := tunnelcrypto.NewDatagramServer(tunnelcrypto.ServerConfig{Cipher: node.Random.Cipher, Key: node.Random.Key, Transport: "raw_udp", ExitID: node.NodeId, LinkKey: func(id int64) (string, bool) {
		p := e.tunnelPolicy.Load()
		if p == nil {
			return "", false
		}
		key, ok := p.links[id]
		return key, ok
	}})
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(node.TunnelListenHost, strconv.Itoa(int(node.TunnelListenPort))))
	if err != nil {
		return err
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &randomUDPListener{e: e, node: proto.Clone(node).(*pb.NodeConfig), ctx: ctx, cancel: cancel, socket: socket, gate: gate, associations: map[[16]byte]*randomUDPAssociation{}, handshakes: map[[32]byte]*randomUDPHandshakeReply{}, slots: make(chan struct{}, 32), dials: make(chan struct{}, 32)}
	e.randomUDP = l
	e.wg.Add(2)
	go l.read()
	go l.maintain()
	return nil
}
func (l *randomUDPListener) Close() { l.cancel(); l.socket.Close() }
func (l *randomUDPListener) allowed(a *randomUDPAssociation) bool {
	n, p := l.e.node.Load(), l.e.tunnelPolicy.Load()
	return a.ctx.Err() == nil && n != nil && n.Enabled && n.TunnelExitEnabled && n.TunnelProtocol == "random_udp" && n.Random.GetKey() == l.node.Random.GetKey() && n.Random.GetCipher() == l.node.Random.GetCipher() && p != nil && len(a.linkKey) == 64 && p.links[a.crypto.IngressID()] == a.linkKey
}
func (l *randomUDPListener) read() {
	defer l.e.wg.Done()
	defer func() {
		l.cancel()
		l.mu.Lock()
		all := make([]*randomUDPAssociation, 0, len(l.associations))
		for _, a := range l.associations {
			all = append(all, a)
		}
		l.mu.Unlock()
		for _, a := range all {
			a.Close()
		}
	}()
	buf := make([]byte, tunnelcrypto.DatagramMTU+1)
	for {
		n, from, err := l.socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if packet, err := l.gate.ParsePacket(buf[:n]); err == nil {
			l.mu.Lock()
			a := l.associations[packet.SessionID()]
			l.mu.Unlock()
			if a != nil && a.remote.String() == from.String() && l.allowed(a) {
				a.receive(packet)
			}
			continue
		}
		req, challenge, err := l.gate.Check(buf[:n], from.String())
		if err != nil {
			continue
		}
		if challenge != nil {
			if len(challenge) <= n {
				_, _ = l.socket.WriteToUDP(challenge, from)
			}
			continue
		}
		if req == nil {
			continue
		}
		digest := req.Digest()
		key := sha256.Sum256(append(digest[:], []byte(from.String())...))
		l.mu.Lock()
		if cached := l.handshakes[key]; cached != nil {
			reply := cached.reply
			l.mu.Unlock()
			if len(reply) > 0 {
				_, _ = l.socket.WriteToUDP(reply, from)
			}
			continue
		}
		if len(l.handshakes) >= 65536 || len(l.associations) >= 4096 || l.ctx.Err() != nil {
			l.mu.Unlock()
			continue
		}
		select {
		case l.slots <- struct{}{}:
		default:
			l.mu.Unlock()
			continue
		}
		cached := &randomUDPHandshakeReply{expires: time.Now().Add(2 * time.Minute)}
		l.handshakes[key] = cached
		l.mu.Unlock()
		l.e.wg.Add(1)
		go func() {
			defer l.e.wg.Done()
			var lease sync.Once
			release := func() { lease.Do(func() { <-l.slots }) }
			keep := false
			defer func() {
				if !keep {
					release()
				}
			}()
			reply, c, err := req.Respond()
			if err != nil || l.ctx.Err() != nil {
				return
			}
			p := l.e.tunnelPolicy.Load()
			if p == nil {
				return
			}
			link := req.LinkKey()
			if p.links[req.IngressID()] != link {
				return
			}
			a := newRandomUDPAssociation(l.ctx, l.socket, from, c, link, &l.e.udpQueued)
			a.server = l
			a.onConfirmed = release
			a.onClose = func() {
				l.mu.Lock()
				if l.associations[c.ID()] == a {
					delete(l.associations, c.ID())
				}
				cached.reply = nil
				l.mu.Unlock()
			}
			l.mu.Lock()
			if l.ctx.Err() != nil || l.associations[c.ID()] != nil {
				l.mu.Unlock()
				a.Close()
				return
			}
			l.associations[c.ID()] = a
			cached.reply = reply
			cached.id = c.ID()
			keep = true
			l.mu.Unlock()
			if _, err = l.socket.WriteToUDP(reply, from); err != nil {
				a.Close()
			}
		}()
	}
}
func (l *randomUDPListener) maintain() {
	defer l.e.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case now := <-ticker.C:
			l.mu.Lock()
			all := make([]*randomUDPAssociation, 0, len(l.associations))
			for _, a := range l.associations {
				all = append(all, a)
			}
			for key, v := range l.handshakes {
				if now.After(v.expires) {
					delete(l.handshakes, key)
				}
			}
			l.mu.Unlock()
			idle := time.Duration(l.node.UdpIdleTimeoutSeconds) * time.Second
			if idle <= 0 {
				idle = 60 * time.Second
			}
			for _, a := range all {
				age := now.Sub(time.Unix(0, a.lastReceive.Load()))
				if !l.allowed(a) || age > idle || !a.confirmed.Load() && age > 5*time.Second {
					a.Close()
					continue
				}
				a.expire(now)
			}
		}
	}
}
func (a *randomUDPAssociation) expire(now time.Time) {
	a.mu.Lock()
	var closing []*randomUDPFlow
	for id, f := range a.flows {
		if f.closedAt.IsZero() && !f.remoteClosedAt.IsZero() && now.Sub(f.remoteClosedAt) > 100*time.Millisecond {
			closing = append(closing, f)
			continue
		}
		if !f.closedAt.IsZero() && now.Sub(f.closedAt) > 5*time.Second {
			delete(a.flows, id)
			continue
		}
		f.nativePeer.mu.Lock()
		for key, p := range f.parts {
			if now.After(p.expires) {
				f.queued.Add(-int64(p.bytes))
				delete(f.parts, key)
			}
		}
		f.nativePeer.mu.Unlock()
	}
	a.mu.Unlock()
	for _, f := range closing {
		f.Close()
	}
}
func (l *randomUDPListener) openFlow(a *randomUDPAssociation, id uint64, body []byte) {
	a.mu.Lock()
	existing := a.flows[id]
	if existing != nil {
		state := existing.state
		a.mu.Unlock()
		if state != 0 {
			_ = a.control(randomUDPAck, id, []byte{state})
		}
		return
	}
	a.mu.Unlock()
	var open udpStreamOpen
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&open) != nil || decoder.Decode(new(any)) != io.EOF || open.Network != "udp" || open.Ingress != a.crypto.IngressID() || open.Rule <= 0 || open.User <= 0 || open.Epoch < 0 || len(open.Target) > 512 || open.Time < time.Now().Unix()-120 || open.Time > time.Now().Unix()+120 || !l.allowed(a) {
		_ = a.control(randomUDPAck, id, []byte{randomUDPDenied})
		return
	}
	p := l.e.tunnelPolicy.Load()
	if p == nil || !h2RuleAllowed(p, open.h2Open) {
		_ = a.control(randomUDPAck, id, []byte{randomUDPDenied})
		return
	}
	select {
	case l.dials <- struct{}{}:
	default:
		_ = a.control(randomUDPAck, id, []byte{randomUDPBusy})
		return
	}
	active := l.e.connections.Add(1)
	if cap := l.e.maxConnections.Load(); active > maxRandomUDPFlows || cap > 0 && active > cap {
		l.e.connections.Add(-1)
		<-l.dials
		_ = a.control(randomUDPAck, id, []byte{randomUDPBusy})
		return
	}
	a.mu.Lock()
	if len(a.flows) >= maxRandomUDPFlows || !a.opened.takeSequence(id) || a.ctx.Err() != nil {
		a.mu.Unlock()
		l.e.connections.Add(-1)
		<-l.dials
		return
	}
	f := a.newFlowLocked(id, nil)
	a.mu.Unlock()
	l.e.wg.Add(1)
	go func() {
		defer l.e.wg.Done()
		defer l.e.connections.Add(-1)
		defer f.Close()
		allowed := func() bool {
			p := l.e.tunnelPolicy.Load()
			return l.allowed(a) && p != nil && h2RuleAllowed(p, open.h2Open)
		}
		ack := func(code byte) {
			a.mu.Lock()
			if f.ctx.Err() == nil {
				f.state = code
			}
			a.mu.Unlock()
			_ = a.control(randomUDPAck, id, []byte{code})
		}
		if open.Target == tunnelHealthTarget {
			<-l.dials
			if !allowed() {
				ack(randomUDPDenied)
				return
			}
			ack(randomUDPReady)
			f.SetReadDeadline(time.Now().Add(2 * time.Second))
			var b [1]byte
			if n, err := f.Read(b[:]); err == nil && n == 1 && b[0] == 0 {
				_, _ = f.Write(b[:])
			}
			return
		}
		ctx, cancel := context.WithTimeout(f.ctx, p.dialTimeout)
		target, err := l.e.dialTarget(ctx, "udp", open.Target)
		cancel()
		<-l.dials
		if err != nil {
			ack(randomUDPTargetFailed)
			return
		}
		defer target.Close()
		if f.ctx.Err() != nil || !allowed() {
			ack(randomUDPDenied)
			return
		}
		ack(randomUDPReady)
		l.e.relayDatagrams(f.ctx, f, target, allowed)
	}()
}
