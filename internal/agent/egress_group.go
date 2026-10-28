package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"google.golang.org/protobuf/proto"
)

// Not a valid host:port and cannot be supplied as a business target. Health
// requests still require a live rule grant and the normal tunnel credentials.
const tunnelHealthTarget = "@nekopass-health-v1"

var errTunnelTarget = errors.New("tunnel target unavailable")

func peerRule(r *pb.Rule, p *pb.EgressPeer) *pb.Rule {
	// Dialing needs only authentication and peer configuration. Cloning the
	// entire rule here would copy every peer's certificate once per candidate.
	return &pb.Rule{Id: r.Id, UserId: r.UserId, IngressNodeId: r.IngressNodeId, QuotaEpoch: r.QuotaEpoch, Protocol: r.Protocol, TrafficRate: p.TrafficRate, MeteringConfigured: r.MeteringConfigured, EgressNodeId: p.NodeId, TunnelHost: p.Host, TunnelPort: p.Port, TunnelToken: p.Token, TunnelProtocol: p.Protocol, Tls: p.Tls, Random: p.Random}
}
func peerKey(r *pb.Rule) string {
	return fmt.Sprint(r.EgressNodeId) + "/" + r.TunnelToken + "/" + h2PoolKey(r)
}

type egressHealth struct {
	rule                *pb.Rule
	active              int64
	failures, successes int
	interval            time.Duration
	next                time.Time
	probing             bool
}
type egressSchedule struct {
	current             map[string]int64
	health              map[string]*groupHealth
	failures, successes int
}
type groupHealth struct {
	failures, successes int
	blocked             bool
}
type egressCandidate struct {
	rule    *pb.Rule
	key     string
	weight  int64
	standby bool
}

type egressManager struct {
	prepared  map[*pb.Rule][]egressCandidate
	mu        sync.Mutex
	peers     map[string]*egressHealth
	schedules map[string]*egressSchedule
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	h2        *h2Transport
	queued    *atomic.Int64
}

func newEgressManager(h2 *h2Transport, queued *atomic.Int64) *egressManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &egressManager{prepared: map[*pb.Rule][]egressCandidate{}, peers: map[string]*egressHealth{}, schedules: map[string]*egressSchedule{}, ctx: ctx, cancel: cancel, done: make(chan struct{}), h2: h2, queued: queued}
	go m.run()
	return m
}
func (m *egressManager) update(rules []*pb.Rule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := map[string]*egressHealth{}
	representatives := map[string]*pb.Rule{}
	groups := map[string]bool{}
	prepared := map[*pb.Rule][]egressCandidate{}
	for _, r := range rules {
		if !r.Enabled || r.EgressGroupId == 0 {
			continue
		}
		groups[scheduleKey(r)] = true
		s := m.schedules[scheduleKey(r)]
		if s == nil {
			s = &egressSchedule{current: map[string]int64{}, health: map[string]*groupHealth{}}
			m.schedules[scheduleKey(r)] = s
		}
		s.failures = int(max(1, r.HealthFailures))
		s.successes = int(max(1, r.HealthSuccesses))
		for _, p := range r.EgressPeers {
			v := peerRule(r, p)
			key := peerKey(v)
			if s.health[key] == nil {
				s.health[key] = &groupHealth{}
			}
			prepared[r] = append(prepared[r], egressCandidate{v, key, int64(max(1, min(p.Weight, 1000))), p.Standby})
			interval := time.Duration(max(2, r.HealthIntervalSeconds)) * time.Second
			// Keep an existing representative while its grant remains present.
			// A newly added rule may reach ingress before its exit authorization;
			// it must not displace another user's already working health request.
			if representatives[key] == nil || m.peers[key] != nil && proto.Equal(m.peers[key].rule, v) {
				representatives[key] = v
			}
			if h := wanted[key]; h != nil {
				h.interval = min(h.interval, interval)
				continue
			}
			h := m.peers[key]
			if h == nil {
				h = &egressHealth{}
			}
			h.interval = interval
			wanted[key] = h
		}
	}
	for key, h := range wanted {
		if h.rule != nil && !proto.Equal(h.rule, representatives[key]) {
			// A new representative grant must be checked without waiting for
			// the old grant's next interval. Its in-flight result is ignored.
			h.next = time.Time{}
		}
		h.rule = representatives[key]
	}
	m.peers = wanted
	m.prepared = prepared
	for k := range m.schedules {
		if !groups[k] {
			delete(m.schedules, k)
		} else {
			for key := range m.schedules[k].health {
				if wanted[key] == nil {
					delete(m.schedules[k].current, key)
					delete(m.schedules[k].health, key)
				}
			}
		}
	}
}
func scheduleKey(r *pb.Rule) string {
	return fmt.Sprintf("%d/%s", r.EgressGroupId, r.Protocol)
}
func (m *egressManager) choose(r *pb.Rule, excluded map[string]bool) (*pb.Rule, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	skey := scheduleKey(r)
	s := m.schedules[skey]
	if s == nil {
		s = &egressSchedule{current: map[string]int64{}, health: map[string]*groupHealth{}, failures: int(max(1, r.HealthFailures)), successes: int(max(1, r.HealthSuccesses))}
		m.schedules[skey] = s
	}
	type candidate struct {
		rule   *pb.Rule
		key    string
		weight int64
		h      *egressHealth
	}
	var main, backup []candidate
	prepared := m.prepared[r]
	if prepared == nil {
		for _, p := range r.EgressPeers {
			v := peerRule(r, p)
			prepared = append(prepared, egressCandidate{v, peerKey(v), int64(max(1, min(p.Weight, 1000))), p.Standby})
		}
	}
	for _, p := range prepared {
		v, key := p.rule, p.key
		h := m.peers[key]
		if h == nil || excluded[key] {
			continue
		}
		if state := s.health[key]; state != nil && state.blocked {
			continue
		}
		c := candidate{v, key, p.weight, h}
		if p.standby {
			backup = append(backup, c)
		} else {
			main = append(main, c)
		}
	}
	cs := main
	if len(cs) == 0 {
		cs = backup
	}
	if len(cs) == 0 {
		return nil, nil, errors.New("no healthy egress nodes")
	}
	selected := 0
	var total int64
	for _, c := range cs {
		total += c.weight
	}
	switch r.EgressStrategy {
	case "round_robin":
		for i, c := range cs {
			s.current[c.key] += c.weight
			if s.current[c.key] > s.current[cs[selected].key] {
				selected = i
			}
		}
		s.current[cs[selected].key] -= total
	case "random":
		n := rand.Int64N(total)
		for i, c := range cs {
			n -= c.weight
			if n < 0 {
				selected = i
				break
			}
		}
	default:
		// Randomize ties by weight, then compare normalized active sessions.
		n := rand.Int64N(total)
		for i, c := range cs {
			n -= c.weight
			if n < 0 {
				selected = i
				break
			}
		}
		for i, c := range cs {
			best := cs[selected]
			if c.h.active*best.weight < best.h.active*c.weight {
				selected = i
			}
		}
	}
	c := cs[selected]
	c.h.active++
	var once sync.Once
	return c.rule, func() { once.Do(func() { m.mu.Lock(); c.h.active--; m.mu.Unlock() }) }, nil
}
func (m *egressManager) outcome(key string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outcomeLocked(key, err)
}

func (m *egressManager) probeOutcome(key string, sampled *egressHealth, rule *pb.Rule, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.peers[key]
	if current != sampled || current == nil || !proto.Equal(current.rule, rule) {
		return
	}
	m.outcomeLocked(key, err)
}

func (m *egressManager) outcomeLocked(key string, err error) {
	h := m.peers[key]
	if h == nil {
		return
	}
	if errors.Is(err, errTunnelTarget) {
		return
	}
	// Update group-specific hysteresis even while there is no user traffic.
	// Groups can share one probe and still use different failure thresholds.
	for _, s := range m.schedules {
		if state := s.health[key]; state != nil {
			if err == nil {
				state.failures = 0
				state.successes++
				if state.blocked && state.successes >= s.successes {
					state.blocked = false
				}
			} else {
				state.successes = 0
				state.failures++
				if state.failures >= s.failures {
					state.blocked = true
				}
			}
		}
	}
	if err == nil {
		h.failures = 0
		h.successes++
	} else {
		h.successes = 0
		h.failures++
	}
}
func (m *egressManager) dial(ctx, lifetime context.Context, r *pb.Rule, target string, udp bool) (net.Conn, func(), error) {
	excluded := map[string]bool{}
	var last error
	for len(excluded) < len(r.EgressPeers) {
		v, release, err := m.choose(r, excluded)
		if err != nil {
			if last != nil {
				return nil, nil, last
			}
			return nil, nil, err
		}
		key := peerKey(v)
		excluded[key] = true
		// The request includes the exit's business-target dial. Respect the
		// configured overall budget instead of treating a slow target as an
		// unavailable exit. Transport connect and health probes have their own
		// deadlines; cancellation of the overall request never poisons health.
		c, err := dialEgress(ctx, lifetime, v, target, udp, m.h2, m.queued)
		var connectError *net.OpError
		if ctx.Err() == nil && (err == nil || errors.As(err, &connectError) && connectError.Op == "dial") {
			// Only an endpoint connection failure is evidence about every rule
			// sharing this peer. Authorization/stream errors can be specific to
			// one rule or local pool; authenticated probes handle other failures.
			m.outcome(key, err)
		}
		if err == nil {
			return &billedConn{Conn: c, rate: ruleRate(v)}, release, nil
		}
		release()
		if errors.Is(err, errTunnelTarget) {
			return nil, nil, err
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no egress candidates")
	}
	return nil, nil, last
}
func dialEgress(ctx, lifetime context.Context, r *pb.Rule, target string, udp bool, h2 *h2Transport, queued *atomic.Int64) (net.Conn, error) {
	if udp {
		return dialDatagramTunnel(ctx, lifetime, r, target, h2, queued)
	}
	if tunnel.H3(r.TunnelProtocol) {
		if h2 == nil {
			return nil, errors.New("HTTP/3 transport unavailable")
		}
		return h2.h3.Dial(ctx, lifetime, r, target, false, queued)
	}
	if tunnel.H2(r.TunnelProtocol) {
		if h2 == nil {
			return nil, errors.New("HTTP/2 transport unavailable")
		}
		return h2.Dial(ctx, lifetime, r, target)
	}
	return dialTunnel(ctx, r, target)
}
func (m *egressManager) run() {
	defer close(m.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, 8)
	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-tick.C:
			m.mu.Lock()
			for key, h := range m.peers {
				if h.probing || now.Before(h.next) {
					continue
				}
				select {
				case slots <- struct{}{}:
				default:
					continue
				}
				h.probing = true
				h.next = now.Add(h.interval)
				r := h.rule
				wg.Add(1)
				go func(key string, h *egressHealth, r *pb.Rule) {
					defer wg.Done()
					defer func() { <-slots; m.mu.Lock(); h.probing = false; m.mu.Unlock() }()
					ctx, cancel := context.WithTimeout(m.ctx, 2*time.Second)
					defer cancel()
					c, err := dialEgress(ctx, ctx, r, tunnelHealthTarget, r.Protocol == "udp", m.h2, m.queued)
					if err == nil {
						if tunnel.UDP(r.TunnelProtocol) { // Native datagrams acknowledge before the DTLS/target stage.
							_ = c.SetDeadline(time.Now().Add(time.Second))
							_, err = c.Write([]byte{0})
							if err == nil {
								var b [1]byte
								var n int
								n, err = c.Read(b[:])
								if err == nil && (n != 1 || b[0] != 0) {
									err = errors.New("invalid health response")
								}
							}
						}
						c.Close()
					}
					if m.ctx.Err() == nil {
						m.probeOutcome(key, h, r, err)
					}
				}(key, h, r)
			}
			m.mu.Unlock()
		}
	}
}
func (m *egressManager) close() { m.cancel(); <-m.done }

// Group membership and scheduling changes affect new sessions; the listener
// and existing sessions keep their immutable rule/authentication snapshot.
func sameRuntimeRule(a, b *pb.Rule) bool {
	if a.GetEgressGroupId() == 0 || a.GetEgressGroupId() != b.GetEgressGroupId() {
		return proto.Equal(a, b)
	}
	for _, old := range a.EgressPeers {
		for _, next := range b.EgressPeers {
			if old.NodeId == next.NodeId && old.TrafficRate != next.TrafficRate {
				return false
			}
		}
	}
	a = proto.Clone(a).(*pb.Rule)
	b = proto.Clone(b).(*pb.Rule)
	for _, r := range []*pb.Rule{a, b} {
		r.EgressPeers = nil
		r.EgressStrategy = ""
		r.HealthIntervalSeconds = 0
		r.HealthFailures = 0
		r.HealthSuccesses = 0
	}
	return proto.Equal(a, b)
}
