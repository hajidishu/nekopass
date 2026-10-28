package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

type randomUDPDial struct {
	done        chan struct{}
	association *randomUDPAssociation
	err         error
}
type randomUDPPool struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	peers  map[string]*randomUDPDial
	wg     sync.WaitGroup
}

func newRandomUDPPool() *randomUDPPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &randomUDPPool{ctx: ctx, cancel: cancel, peers: map[string]*randomUDPDial{}}
}
func (p *randomUDPPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.cancel()
	all := make([]*randomUDPAssociation, 0, len(p.peers))
	for _, d := range p.peers {
		if d.association != nil {
			all = append(all, d.association)
		}
	}
	p.mu.Unlock()
	for _, a := range all {
		a.Close()
	}
	p.wg.Wait()
}
func (p *randomUDPPool) Prune(rules []*pb.Rule) {
	wanted := map[string]bool{}
	for _, r := range rules {
		if r.Enabled && r.TunnelProtocol == "random_udp" {
			wanted[h2PoolKey(r)] = true
		}
		for _, v := range r.EgressPeers {
			if r.Enabled && v.Protocol == "random_udp" {
				wanted[h2PoolKey(peerRule(r, v))] = true
			}
		}
	}
	p.mu.Lock()
	var close []*randomUDPAssociation
	for key, d := range p.peers {
		if wanted[key] || d.association == nil {
			continue
		}
		a := d.association
		a.mu.Lock()
		empty := len(a.flows) == 0
		a.mu.Unlock()
		if empty {
			close = append(close, a)
		}
	}
	p.mu.Unlock()
	for _, a := range close {
		a.Close()
	}
}
func (p *randomUDPPool) association(ctx context.Context, r *pb.Rule, queued *atomic.Int64) (*randomUDPAssociation, error) {
	key := h2PoolKey(r)
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if d := p.peers[key]; d != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-p.ctx.Done():
				return nil, net.ErrClosed
			case <-d.done:
			}
			if d.err != nil {
				return nil, d.err
			}
			if d.association.ctx.Err() != nil {
				p.mu.Lock()
				if p.peers[key] == d {
					delete(p.peers, key)
				}
				p.mu.Unlock()
				continue
			}
			return d.association, nil
		}
		d := &randomUDPDial{done: make(chan struct{})}
		p.peers[key] = d
		p.wg.Add(1)
		p.mu.Unlock()
		defer p.wg.Done()
		dialCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(p.ctx, cancel)
		defer stop()
		defer cancel()
		a, err := dialRandomUDPAssociation(dialCtx, p.ctx, r, queued)
		p.mu.Lock()
		if err == nil && p.closed {
			err = net.ErrClosed
			a.Close()
		}
		d.err = err
		if err != nil {
			delete(p.peers, key)
		} else {
			d.association = a
			a.onClose = func() {
				p.mu.Lock()
				if p.peers[key] == d {
					delete(p.peers, key)
				}
				p.mu.Unlock()
			}
			p.wg.Add(2)
			go func() { defer p.wg.Done(); a.readClient() }()
			go func() { defer p.wg.Done(); a.maintainClient() }()
		}
		close(d.done)
		p.mu.Unlock()
		return a, err
	}
}
func dialRandomUDPAssociation(ctx, lifetime context.Context, r *pb.Rule, queued *atomic.Int64) (*randomUDPAssociation, error) {
	if r.Random == nil {
		return nil, errors.New("random UDP encryption settings missing")
	}
	h, err := tunnelcrypto.NewDatagramHandshake(tunnelcrypto.ClientConfig{Cipher: r.Random.Cipher, Key: r.Random.Key, LinkKey: r.TunnelToken, Transport: "raw_udp", IngressID: r.IngressNodeId, ExitID: r.EgressNodeId})
	if err != nil {
		return nil, err
	}
	if r.TunnelHost == "" || r.TunnelPort < 1 || r.TunnelPort > 65535 {
		return nil, errors.New("UDP tunnel address invalid")
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, r.TunnelHost)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, errors.New("UDP exit address unavailable")
	}
	addr := &net.UDPAddr{IP: resolved[0].IP, Port: int(r.TunnelPort), Zone: resolved[0].Zone}
	network := "udp4"
	if addr.IP.To4() == nil {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			socket.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	defer stop()
	request := h.Initial()
	buf := make([]byte, tunnelcrypto.DatagramMTU+1)
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	attempts := 0
	for phase := 0; phase < 2; {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempts >= 3 || !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		if _, err = socket.WriteToUDP(request, addr); err != nil {
			return nil, err
		}
		wait := min(time.Duration(300*(1<<attempts))*time.Millisecond, time.Until(deadline))
		attempts++
		until := time.Now().Add(wait)
		socket.SetReadDeadline(until)
		for {
			n, from, err := socket.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return nil, err
			}
			if from.String() != addr.String() {
				continue
			}
			retry, session, err := h.Handle(buf[:n])
			if err != nil {
				continue
			}
			if session != nil {
				socket.SetDeadline(time.Time{})
				success = true
				return newRandomUDPAssociation(lifetime, socket, addr, session, r.TunnelToken, queued), nil
			}
			if retry != nil && phase == 0 {
				request = retry
				phase = 1
				attempts = 0
				break
			}
		}
	}
	return nil, context.DeadlineExceeded
}
func (p *randomUDPPool) Dial(ctx, lifetime context.Context, r *pb.Rule, target string, queued *atomic.Int64) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	a, err := p.association(ctx, r, queued)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.ctx.Err() != nil || len(a.flows) >= maxRandomUDPFlows || a.flowSequence == math.MaxUint64 {
		a.mu.Unlock()
		return nil, errors.New("UDP tunnel capacity reached")
	}
	a.flowSequence++
	f := a.newFlowLocked(a.flowSequence, lifetime)
	a.mu.Unlock()
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	open := udpStreamOpen{h2Open: h2Open{Network: "udp", Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target}, Time: time.Now().Unix()}
	body, err := json.Marshal(open)
	if err != nil || len(body) > nativePartSize {
		return nil, errors.New("UDP tunnel metadata too large")
	}
	start := time.Now()
	attempts := 0
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if a.lastReceive.Load() < start.UnixNano() {
				a.Close()
			}
			return nil, ctx.Err()
		case <-f.ctx.Done():
			return nil, net.ErrClosed
		case code := <-f.ready:
			if code == randomUDPReady && f.ctx.Err() == nil {
				success = true
				return f, nil
			}
			if code == randomUDPTargetFailed {
				return nil, errTunnelTarget
			}
			return nil, errors.New("UDP tunnel exit rejected connection")
		case <-timer.C:
			if attempts >= 8 {
				return nil, context.DeadlineExceeded
			}
			attempts++
			if err = a.control(randomUDPOpen, f.id, body); err != nil {
				return nil, err
			}
			timer.Reset(time.Duration(500*(1<<min(attempts-1, 3))) * time.Millisecond)
		}
	}
}
func (a *randomUDPAssociation) readClient() {
	defer a.Close()
	stop := context.AfterFunc(a.ctx, func() { a.socket.Close() })
	defer stop()
	buf := make([]byte, tunnelcrypto.DatagramMTU+1)
	for {
		n, from, err := a.socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if from.String() != a.remote.String() {
			continue
		}
		packet, err := a.crypto.Parse(buf[:n])
		if err == nil {
			a.receive(packet)
		}
	}
}
func (a *randomUDPAssociation) maintainClient() {
	defer a.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextPing := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-ticker.C:
			a.expire(now)
			a.mu.Lock()
			empty := len(a.flows) == 0
			a.mu.Unlock()
			if empty {
				if now.Sub(time.Unix(0, a.lastActivity.Load())) > 8*time.Second {
					return
				}
				continue
			}
			if now.Sub(time.Unix(0, a.lastReceive.Load())) > 10*time.Second {
				return
			}
			if now.Sub(time.Unix(0, a.lastReceive.Load())) < 2*time.Second {
				continue
			}
			if now.Before(nextPing) {
				continue
			}
			var nonce [8]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return
			}
			a.pingMu.Lock()
			a.ping = nonce
			a.pingMu.Unlock()
			if a.control(randomUDPPing, 0, nonce[:]) != nil {
				return
			}
			nextPing = now.Add(2*time.Second + time.Duration(nonce[0])*time.Second/255)
		}
	}
}
