package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

const maxDatagram = 65535
const maxQueuedUDPBytes = 32 << 20

// Account for the queue entry and slice header even when a datagram has no
// payload. Otherwise empty datagrams bypass the shared memory budget.
const minQueuedUDPItemBytes = 64

func udpQueueCharge(n int) int64 { return int64(max(n, minQueuedUDPItemBytes)) }

var errUDPRate = errors.New("UDP packet rate limited")

func networkIncludes(protocol, network string) bool {
	if protocol == "" {
		protocol = "tcp"
	}
	return protocol == network || protocol == "tcp_udp"
}

type udpListener struct {
	rule     *pb.Rule
	runtime  *ruleRuntime
	conn     *net.UDPConn
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	sessions map[netip.AddrPort]*udpAssociation
}
type udpAssociation struct {
	rate     int64
	listener *udpListener
	source   netip.AddrPort
	queue    chan []byte
	ctx      context.Context
	cancel   context.CancelFunc
	last     atomic.Int64
}

func (a *Account) takeDatagram(n int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || n > maxDatagram || !a.validLocked() {
		return ErrQuota
	}
	a.wanted = time.Now()
	if !a.policy.QuotaUnlimited && a.credit+(a.disk.Issued-a.disk.Spent-a.disk.Released) < int64(max(1, n)) {
		return ErrQuota
	}
	if a.limiter.Burst() < n {
		a.limiter.SetBurst(n)
	}
	if !a.limiter.AllowN(time.Now(), n) {
		return errUDPRate
	}
	if a.policy.QuotaUnlimited {
		if a.unlimitedCredit < int64(n) {
			block := min(int64(ReservationBlock), int64(^uint64(0)>>1)-a.disk.Spent-a.disk.UnlimitedSpent)
			if block < int64(n)-a.unlimitedCredit {
				return ErrQuota
			}
			a.disk.UnlimitedSpent += block
			if err := a.persist(); err != nil {
				return err
			}
			a.unlimitedCredit += block
		}
		a.unlimitedCredit -= int64(n)
		return nil
	}
	if a.credit < int64(n) {
		block := min(int64(ReservationBlock), a.disk.Issued-a.disk.Spent-a.disk.Released)
		if block < int64(n)-a.credit {
			return ErrQuota
		}
		a.disk.Spent += block
		if err := a.persist(); err != nil {
			return err
		}
		a.credit += block
	}
	a.credit -= int64(n)
	return nil
}

func (e *Engine) configureUDP(c *pb.ControlMessage) []string {
	wanted := map[int64]*pb.Rule{}
	for _, r := range c.Rules {
		a := e.users[r.UserId]
		if networkIncludes(r.Protocol, "udp") && r.Enabled && a != nil && a.valid() && (c.Node == nil && e.maxConnections.Load() > 0 || c.Node != nil && c.Node.Enabled) {
			wanted[r.Id] = r
		}
	}
	for id, l := range e.udpListeners {
		if wanted[id] == nil || !sameRuntimeRule(l.rule, wanted[id]) {
			l.cancel()
			l.conn.Close()
			delete(e.udpListeners, id)
		}
	}
	var failures []string
	for id, r := range wanted {
		if e.udpListeners[id] != nil {
			e.udpListeners[id].runtime.group.Store(r)
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(r.ListenHost, strconv.Itoa(int(r.ListenPort))))
		if err != nil {
			failures = append(failures, fmt.Sprintf("UDP rule %d: %v", id, err))
			continue
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			failures = append(failures, fmt.Sprintf("UDP rule %d: %v", id, err))
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		l := &udpListener{rule: r, runtime: newRuleRuntime(r), conn: conn, ctx: ctx, cancel: cancel, sessions: map[netip.AddrPort]*udpAssociation{}}
		l.runtime.configureNode(e.nodeConfiguration())
		l.runtime.dialTarget = e.dialTarget
		l.runtime.egress = e.egress
		l.runtime.h2 = e.h2
		e.udpListeners[id] = l
		counter := e.counters[id]
		if counter == nil {
			counter = &atomic.Int64{}
			e.counters[id] = counter
		}
		e.wg.Add(1)
		go e.readUDP(l, e.users[r.UserId], counter)
	}
	return failures
}

func (e *Engine) readUDP(l *udpListener, a *Account, count *atomic.Int64) {
	defer e.wg.Done()
	defer func() {
		l.mu.Lock()
		for _, s := range l.sessions {
			s.cancel()
		}
		l.mu.Unlock()
	}()
	buffer := make([]byte, maxDatagram)
	for {
		n, source, err := l.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if !a.valid() {
			continue
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		l.mu.Lock()
		session := l.sessions[source]
		if session == nil && len(l.sessions) < 65536 {
			active := e.connections.Add(1)
			if cap := e.maxConnections.Load(); cap > 0 && active > cap {
				e.connections.Add(-1)
				l.mu.Unlock()
				continue
			}
			ip := source.Addr().String()
			if !a.acquire() {
				e.connections.Add(-1)
				l.mu.Unlock()
				continue
			}
			if !l.runtime.open() {
				a.active.Add(-1)
				e.connections.Add(-1)
				l.mu.Unlock()
				continue
			}
			if !a.addIP(ip) {
				l.runtime.close()
				a.active.Add(-1)
				e.connections.Add(-1)
				l.mu.Unlock()
				continue
			}
			if !l.runtime.addIP(ip) {
				a.removeIP(ip)
				l.runtime.close()
				a.active.Add(-1)
				e.connections.Add(-1)
				l.mu.Unlock()
				continue
			}
			ctx, cancel := context.WithCancel(l.ctx)
			session = &udpAssociation{listener: l, source: source, queue: make(chan []byte, 8), ctx: ctx, cancel: cancel}
			session.last.Store(time.Now().UnixNano())
			l.sessions[source] = session
			e.wg.Add(1)
			go e.runUDP(session, a, count)
		}
		if session != nil {
			charge := udpQueueCharge(n)
			if e.udpQueued.Add(charge) <= maxQueuedUDPBytes {
				packet := append([]byte{}, buffer[:n]...)
				select {
				case session.queue <- packet:
					session.last.Store(time.Now().UnixNano())
				default:
					e.udpQueued.Add(-charge)
				}
			} else {
				e.udpQueued.Add(-charge)
			}
		}
		l.mu.Unlock()
	}
}

func (r *ruleRuntime) dialDatagram(ctx context.Context, queued *atomic.Int64) (net.Conn, func(), error) {
	tried := map[int]bool{}
	for len(tried) < len(r.targets) {
		i := r.selectTarget(tried)
		tried[i] = true
		dialCtx, cancel := context.WithTimeout(ctx, r.dialTimeout)
		var conn net.Conn
		var err error
		var releaseExit func()
		if r.policy.EgressGroupId != 0 {
			conn, releaseExit, err = r.egress.dial(dialCtx, ctx, r.group.Load(), r.targets[i], true)
		} else if r.policy.EgressNodeId == 0 {
			conn, err = r.dialTarget(dialCtx, "udp", r.targets[i])
		} else {
			conn, err = dialDatagramTunnel(dialCtx, ctx, r.policy, r.targets[i], r.h2, queued)
		}
		cancel()
		if err == nil {
			if r.policy.EgressGroupId == 0 {
				conn = &billedConn{Conn: conn, rate: ruleRate(r.policy)}
			}
			return conn, func() {
				if releaseExit != nil {
					releaseExit()
				}
				r.releaseTarget(i)
			}, nil
		}
		r.releaseTarget(i)
	}
	return nil, nil, errors.New("UDP target unavailable")
}

func (e *Engine) runUDP(s *udpAssociation, a *Account, count *atomic.Int64) {
	l := s.listener
	defer e.wg.Done()
	defer func() {
		s.cancel()
		l.mu.Lock()
		delete(l.sessions, s.source)
		for {
			select {
			case p := <-s.queue:
				e.udpQueued.Add(-udpQueueCharge(len(p)))
			default:
				l.mu.Unlock()
				a.removeIP(s.source.Addr().String())
				l.runtime.removeIP(s.source.Addr().String())
				l.runtime.close()
				a.active.Add(-1)
				e.connections.Add(-1)
				return
			}
		}
	}()
	target, release, err := l.runtime.dialDatagram(s.ctx, &e.udpQueued)
	if err != nil {
		return
	}
	defer release()
	s.rate = connectionRate(target, l.rule)
	defer a.beginMeter(s.rate)()
	defer target.Close()
	stop := context.AfterFunc(s.ctx, func() { target.Close() })
	defer stop()
	timeout := 60 * time.Second
	if cfg := e.node.Load(); cfg != nil && cfg.UdpIdleTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.UdpIdleTimeoutSeconds) * time.Second
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer s.cancel()
		buf := make([]byte, maxDatagram)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			reservation, ok := e.reserveUDPPacket(s, a, n)
			if !ok {
				continue
			}
			written, err := l.conn.WriteToUDPAddrPort(buf[:n], s.source)
			reservation.finish(written)
			if err != nil {
				return
			}
			count.Add(int64(written))
			s.last.Store(time.Now().UnixNano())
		}
	}()
	defer func() { s.cancel(); target.Close(); <-done }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			if !a.billingAllowed(s.rate) || time.Since(time.Unix(0, s.last.Load())) > timeout || l.rule.EgressNodeId == 0 && l.rule.EgressGroupId == 0 && !e.targetAllowed(target) {
				return
			}
		case p := <-s.queue:
			e.udpQueued.Add(-udpQueueCharge(len(p)))
			reservation, ok := e.reserveUDPPacket(s, a, len(p))
			if !ok {
				continue
			}
			_ = target.SetWriteDeadline(time.Now().Add(time.Second))
			written, err := target.Write(p)
			reservation.finish(written)
			_ = target.SetWriteDeadline(time.Time{})
			if err != nil || written != len(p) {
				return
			}
			count.Add(int64(written))
		}
	}
}

func (e *Engine) reserveUDPPacket(s *udpAssociation, a *Account, n int) (*trafficReservation, bool) {
	if s.ctx.Err() != nil || !a.valid() {
		return nil, false
	}
	if limiter := s.listener.runtime.limiter; limiter != nil {
		if limiter.Burst() < n {
			limiter.SetBurst(n)
		}
		if !limiter.AllowN(time.Now(), n) {
			return nil, false
		}
	}
	reservation, err := a.reserveUDP(n, s.rate)
	if err != nil && !errors.Is(err, errUDPRate) {
		s.cancel()
	}
	return reservation, err == nil
}
