package agent

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"golang.org/x/time/rate"
)

type ruleRuntime struct {
	mu           sync.Mutex
	policy       *pb.Rule
	active       int
	ips          map[string]int
	targets      []string
	targetActive []int
	next         int
	limiter      *rate.Limiter
	dialTimeout  time.Duration
	idleTimeout  time.Duration
	h2           *h2Transport
}

func newRuleRuntime(r *pb.Rule) *ruleRuntime {
	targets := append([]string{}, r.Targets...)
	if len(targets) == 0 {
		targets = []string{net.JoinHostPort(r.TargetHost, strconv.Itoa(int(r.TargetPort)))}
	}
	v := &ruleRuntime{policy: r, ips: map[string]int{}, targets: targets, targetActive: make([]int, len(targets))}
	if r.SpeedBps > 0 {
		v.limiter = rate.NewLimiter(rate.Limit(r.SpeedBps), int(max(int64(BufferSize), min(r.SpeedBps/100, 1<<20))))
	}
	return v
}
func (r *ruleRuntime) open() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policy.ConnectionLimit > 0 && r.active >= int(r.policy.ConnectionLimit) {
		return false
	}
	r.active++
	return true
}
func (r *ruleRuntime) close() { r.mu.Lock(); r.active--; r.mu.Unlock() }
func (r *ruleRuntime) addIP(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ips[ip] == 0 && r.policy.IpLimit > 0 && len(r.ips) >= int(r.policy.IpLimit) {
		return false
	}
	r.ips[ip]++
	return true
}
func (r *ruleRuntime) removeIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ips[ip]--
	if r.ips[ip] <= 0 {
		delete(r.ips, ip)
	}
}
func (r *ruleRuntime) selectTarget(excluded map[int]bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := []int{}
	for i := range r.targets {
		if !excluded[i] {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return -1
	}
	selected := candidates[rand.IntN(len(candidates))]
	switch r.policy.Balance {
	case "round_robin":
		for j := 0; j < len(r.targets); j++ {
			i := (r.next + j) % len(r.targets)
			if !excluded[i] {
				selected = i
				r.next = (i + 1) % len(r.targets)
				break
			}
		}
	case "least_connections":
		for _, i := range candidates {
			if r.targetActive[i] < r.targetActive[selected] {
				selected = i
			}
		}
	}
	r.targetActive[selected]++
	return selected
}
func (r *ruleRuntime) releaseTarget(i int) { r.mu.Lock(); r.targetActive[i]--; r.mu.Unlock() }
func (r *ruleRuntime) dial(ctx context.Context) (net.Conn, func(), error) {
	tried := map[int]bool{}
	var last error
	timeout := r.dialTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for len(tried) < len(r.targets) {
		i := r.selectTarget(tried)
		tried[i] = true
		d := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
		var c net.Conn
		var e error
		if r.policy.EgressNodeId == 0 {
			c, e = d.DialContext(dialCtx, "tcp", r.targets[i])
		} else {
			if tunnel.H2(r.policy.TunnelProtocol) {
				if r.h2 == nil {
					return nil, nil, errors.New("TLS transport unavailable")
				}
				c, e = r.h2.Dial(dialCtx, ctx, r.policy, r.targets[i])
			} else {
				c, e = dialTunnel(dialCtx, r.policy, r.targets[i])
			}
		}
		if e == nil {
			return c, func() { r.releaseTarget(i) }, nil
		}
		r.releaseTarget(i)
		last = e
		if dialCtx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no targets")
	}
	return nil, nil, last
}

func (r *ruleRuntime) configureNode(c *pb.NodeConfig) {
	r.dialTimeout = time.Duration(c.DialTimeoutSeconds) * time.Second
	r.idleTimeout = time.Duration(c.IdleTimeoutSeconds) * time.Second
}
