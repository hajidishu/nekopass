package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

const maxMuxReceiveBytes = 32 << 20

var errMuxCapacity = errors.New("Mux connection capacity reached")
var errMuxDraining = errors.New("Mux stream is finishing")

type tunnelConnectionLeaseKey struct{}

// Account Yamux DATA before it is buffered, independently of business billing.
// The per-stream overhead also bounds tiny and adversarial DATA frames.
type muxBudgetConn struct {
	net.Conn
	mu          sync.Mutex
	global      *atomic.Int64
	charges     map[uint32]int64
	closed      bool
	header      [12]byte
	headerBytes int
	remaining   uint32
	terminal    error
}

func newMuxBudgetConn(c net.Conn, b *atomic.Int64) *muxBudgetConn {
	return &muxBudgetConn{Conn: c, global: b, charges: map[uint32]int64{}}
}
func (c *muxBudgetConn) Read(p []byte) (int, error) {
	if c.terminal != nil {
		return 0, c.terminal
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.remaining > 0 {
		n, e := c.Conn.Read(p[:min(len(p), int(c.remaining))])
		c.remaining -= uint32(n)
		return n, e
	}
	n, e := c.Conn.Read(p[:min(len(p), 12-c.headerBytes)])
	copy(c.header[c.headerBytes:], p[:n])
	c.headerBytes += n
	if c.headerBytes == 12 {
		c.headerBytes = 0
		if c.header[1] == 0 { // DATA; other frame types use the length field as a value.
			size := binary.BigEndian.Uint32(c.header[8:])
			id := binary.BigEndian.Uint32(c.header[4:8])
			c.remaining = size
			c.mu.Lock()
			charge := int64(size)
			if charge > 0 && c.charges[id] == 0 {
				charge += 64
			}
			if c.closed || size > 256<<10 || len(c.charges) >= 4096 && c.charges[id] == 0 {
				c.terminal = errors.New("invalid Mux receive frame")
			} else if charge > 0 {
				if c.global.Add(charge) > maxMuxReceiveBytes {
					c.global.Add(-charge)
					c.terminal = errors.New("Mux receive budget exhausted")
				} else {
					c.charges[id] += charge
				}
			}
			c.mu.Unlock()
		}
	}
	return n, e
}
func (c *muxBudgetConn) consumed(id uint32, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.charges[id] == 0 {
		return
	}
	v := min(int64(n), max(int64(0), c.charges[id]-64))
	c.charges[id] -= v
	if v > 0 {
		c.global.Add(-v)
	}
}
func (c *muxBudgetConn) release(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.charges[id]; n > 0 {
		c.global.Add(-n)
		delete(c.charges, id)
	}
}
func (c *muxBudgetConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		for _, n := range c.charges {
			c.global.Add(-n)
		}
		clear(c.charges)
	}
	return err
}

func muxYamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.AcceptBacklog = 128
	c.MaxStreamWindowSize = 256 << 10
	c.StreamOpenTimeout = 8 * time.Second
	c.StreamCloseTimeout = 30 * time.Second
	c.ConnectionWriteTimeout = 10 * time.Second
	return c
}

type rawMuxPeer struct {
	session *yamux.Session
	budget  *muxBudgetConn
	active  int
	idle    time.Time
}
type rawMuxGroup struct {
	mu      sync.Mutex
	gate    chan struct{}
	retired bool

	peers  []*rawMuxPeer
	config tunnel.MuxConfig
}
type rawMuxPool struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	pools  map[string]*rawMuxGroup
	queued atomic.Int64
	closed bool
}

func newRawMuxPool() *rawMuxPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &rawMuxPool{ctx: ctx, cancel: cancel, done: make(chan struct{}), pools: map[string]*rawMuxGroup{}}
	go p.maintain()
	return p
}
func (p *rawMuxPool) snapshot() map[string]*rawMuxGroup {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := make(map[string]*rawMuxGroup, len(p.pools))
	for k, g := range p.pools {
		m[k] = g
	}
	return m
}
func (p *rawMuxPool) maintain() {
	defer close(p.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-tick.C:
			for _, g := range p.snapshot() {
				g.mu.Lock()
				keep := g.peers[:0]
				for _, v := range g.peers {
					if v.session.IsClosed() || v.active == 0 && now.Sub(v.idle) > time.Duration(g.config.IdleTimeoutSeconds)*time.Second {
						v.session.Close()
						v.budget.Close()
					} else {
						keep = append(keep, v)
					}
				}
				clear(g.peers[len(keep):])
				g.peers = keep
				g.mu.Unlock()
			}
		}
	}
}
func closeRawMuxGroup(g *rawMuxGroup) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.retired = true
	for _, v := range g.peers {
		v.session.Close()
		v.budget.Close()
	}
	g.peers = nil
}
func (p *rawMuxPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.cancel()
	groups := p.pools
	p.pools = map[string]*rawMuxGroup{}
	p.mu.Unlock()
	for _, g := range groups {
		closeRawMuxGroup(g)
	}
	<-p.done
}
func (p *rawMuxPool) Prune(rules []*pb.Rule) {
	wanted := map[string]bool{}
	for _, r := range rules {
		if r.Enabled && tunnel.Raw(r.TunnelProtocol) && r.Mux.GetEnabled() {
			wanted[rawMuxKey(r, false)] = true
			wanted[rawMuxKey(r, true)] = true
		}
		for _, peer := range r.EgressPeers {
			v := peerRule(r, peer)
			if r.Enabled && tunnel.Raw(v.TunnelProtocol) && v.Mux.GetEnabled() {
				wanted[rawMuxKey(v, false)] = true
				wanted[rawMuxKey(v, true)] = true
			}
		}
	}
	p.mu.Lock()
	var retiring []*rawMuxGroup
	for key, g := range p.pools {
		if !wanted[key] {
			retiring = append(retiring, g)
			delete(p.pools, key)
		}
	}
	p.mu.Unlock()
	for _, g := range retiring {
		closeRawMuxGroup(g)
	}
}

func rawMuxKey(r *pb.Rule, udp bool) string {
	key := h2PoolKey(r)
	if udp {
		return key + "/mux-udp"
	}
	return key + "/mux-tcp"
}

type rawMuxConn struct {
	stateMu sync.Mutex
	closed  bool

	net.Conn
	stream  *yamux.Stream
	budget  *muxBudgetConn
	once    sync.Once
	release func()
	stop    func() bool
}

func (c *rawMuxConn) setStop(stop func() bool) {
	c.stateMu.Lock()
	c.stop = stop
	closed := c.closed
	c.stateMu.Unlock()
	if closed {
		stop()
	}
}
func (c *rawMuxConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.budget.consumed(c.stream.StreamID(), n)
	return n, e
}
func (c *rawMuxConn) CloseWrite() error { return c.stream.Close() }
func (c *rawMuxConn) Close() error {
	var err error
	c.once.Do(func() {
		c.Conn.SetReadDeadline(time.Now())
		err = c.stream.Close()
		c.budget.release(c.stream.StreamID())
		c.stateMu.Lock()
		c.closed = true
		stop := c.stop
		c.stateMu.Unlock()
		if stop != nil {
			stop()
		}
		if c.release != nil {
			c.release()
		}
	})
	return err
}

func (p *rawMuxPool) Dial(ctx, lifetime context.Context, r *pb.Rule, target string, udp bool) (net.Conn, error) {
	if !tunnel.Raw(r.TunnelProtocol) || !r.Mux.GetEnabled() {
		return nil, errors.New("raw TCP Mux is not enabled")
	}
	cfg := tunnel.MuxSettings(r.Mux)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key := rawMuxKey(r, udp)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	g := p.pools[key]
	if g == nil {
		g = &rawMuxGroup{config: cfg, gate: make(chan struct{}, 1)}
		p.pools[key] = g
	}
	p.mu.Unlock()
	var peer *rawMuxPeer
	for {
		select {
		case g.gate <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.ctx.Done():
			return nil, net.ErrClosed
		}
		var err error
		peer, err = p.reserve(ctx, g, r)
		<-g.gate
		if !errors.Is(err, errMuxDraining) {
			if err != nil {
				return nil, err
			}
			break
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(errMuxCapacity, ctx.Err())
		case <-p.ctx.Done():
			timer.Stop()
			return nil, net.ErrClosed
		case <-timer.C:
		}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			g.mu.Lock()
			peer.active--
			if peer.active == 0 {
				peer.idle = time.Now()
			}
			g.mu.Unlock()
		})
	}
	type result struct {
		s   *yamux.Stream
		err error
	}
	opened := make(chan result, 1)
	go func() { s, err := peer.session.OpenStream(); opened <- result{s, err} }()
	var stream *yamux.Stream
	select {
	case <-ctx.Done():
		release()
		go func() {
			select {
			case v := <-opened:
				if v.s != nil {
					v.s.Close()
				}
			case <-time.After(9 * time.Second):
			}
		}()
		return nil, ctx.Err()
	case v := <-opened:
		if v.err != nil {
			release()
			return nil, v.err
		}
		stream = v.s
	}
	conn := &rawMuxConn{Conn: stream, stream: stream, budget: peer.budget, release: release}
	conn.setStop(context.AfterFunc(lifetime, func() { conn.Close() }))
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(8 * time.Second))
	}
	network := "tcp"
	if udp {
		network = "udp"
	}
	metadata, _ := json.Marshal(h2Open{Network: network, Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target})
	if len(metadata) > 2048 {
		conn.Close()
		return nil, errors.New("Mux metadata too large")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(metadata)))
	if _, err := conn.Write(append(header[:], metadata...)); err != nil {
		conn.Close()
		return nil, err
	}
	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if response[0] != 0 {
		conn.Close()
		if response[0] == 2 {
			return nil, errTunnelTarget
		}
		return nil, errors.New("Mux stream refused")
	}
	conn.SetDeadline(time.Time{})
	if udp {
		return &framedDatagram{Conn: conn}, nil
	}
	return conn, nil
}

func (p *rawMuxPool) reserve(ctx context.Context, g *rawMuxGroup, r *pb.Rule) (*rawMuxPeer, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retired || p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var selected *rawMuxPeer
	pendingClose := false
	alive := 0
	keep := g.peers[:0]
	for _, v := range g.peers {
		if v.session.IsClosed() {
			v.budget.Close()
			continue
		}
		alive++
		keep = append(keep, v)
		if v.active < g.config.MaxStreams && int(v.session.NumStreams()) >= g.config.MaxStreams {
			pendingClose = true
		}
		if max(v.active, int(v.session.NumStreams())) < g.config.MaxStreams && (selected == nil || v.active < selected.active) {
			selected = v
		}
	}
	clear(g.peers[len(keep):])
	g.peers = keep
	if selected == nil {
		if g.config.MaxConnections > 0 && alive >= g.config.MaxConnections {
			if pendingClose {
				return nil, errMuxDraining
			}
			return nil, errMuxCapacity
		}
		dial, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(p.ctx, cancel)
		raw, err := dialRawTunnelRequest(dial, r, tunnelHealthTarget, true)
		stop()
		cancel()
		if err != nil {
			return nil, err
		}
		bounded := newMuxBudgetConn(raw, &p.queued)
		session, err := yamux.Client(bounded, muxYamuxConfig())
		if err != nil {
			bounded.Close()
			return nil, err
		}
		selected = &rawMuxPeer{session: session, budget: bounded, idle: time.Now()}
		g.peers = append(g.peers, selected)
	}
	selected.active++
	return selected, nil
}
func (e *Engine) takeMuxCarrier(ingress int64, network string) bool {
	key := fmt.Sprint(ingress, "/", network)
	cfg := tunnel.MuxSettings(e.node.Load().GetMux())
	if !cfg.Enabled {
		return false
	}
	e.muxMu.Lock()
	defer e.muxMu.Unlock()
	if e.muxCarriers == nil {
		e.muxCarriers = map[string]int{}
	}
	if cfg.MaxConnections > 0 && e.muxCarriers[key] >= cfg.MaxConnections {
		return false
	}
	if cap := e.maxConnections.Load(); cap > 0 && int64(e.muxTotal) >= cap {
		return false
	}
	e.muxCarriers[key]++
	e.muxTotal++
	return true
}
func (e *Engine) releaseMuxCarrier(ingress int64, network string) {
	key := fmt.Sprint(ingress, "/", network)
	e.muxMu.Lock()
	defer e.muxMu.Unlock()
	e.muxCarriers[key]--
	e.muxTotal--
	if e.muxCarriers[key] <= 0 {
		delete(e.muxCarriers, key)
	}
}
func (e *Engine) serveRawMux(ctx context.Context, c net.Conn, ingress int64, key string) {
	bounded := newMuxBudgetConn(c, &e.h2.rawMux.queued)
	session, err := yamux.Server(bounded, muxYamuxConfig())
	if err != nil {
		return
	}
	defer session.Close()
	defer bounded.Close()
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	cfg := tunnel.MuxSettings(e.node.Load().GetMux())
	var active atomic.Int64
	var idle atomic.Int64
	idle.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case now := <-tick.C:
				n, p := e.node.Load(), e.tunnelPolicy.Load()
				if n == nil || !n.Enabled || !n.TunnelExitEnabled || !n.Mux.GetEnabled() || p == nil || p.links[ingress] != key || active.Load() == 0 && now.Sub(time.Unix(0, idle.Load())) > time.Duration(cfg.IdleTimeoutSeconds)*time.Second {
					session.Close()
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		current := active.Add(1)
		count := e.connections.Add(1)
		cap := e.maxConnections.Load()
		if current > int64(cfg.MaxStreams) || cap > 0 && count > cap {
			active.Add(-1)
			e.connections.Add(-1)
			stream.Close()
			continue
		}
		conn := &rawMuxConn{Conn: stream, stream: stream, budget: bounded}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			defer e.connections.Add(-1)
			defer func() {
				if active.Add(-1) == 0 {
					idle.Store(time.Now().UnixNano())
				}
			}()
			e.handleMuxStream(ctx, conn, ingress, key)
		}()
	}
}
func (e *Engine) handleMuxStream(parent context.Context, conn net.Conn, ingress int64, key string) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > 2048 {
		return
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}
	var open h2Open
	if json.Unmarshal(data, &open) != nil || open.Ingress != ingress || open.Network != "tcp" && open.Network != "udp" {
		return
	}
	allowed := func() bool {
		node, p := e.node.Load(), e.tunnelPolicy.Load()
		return node != nil && node.Enabled && node.TunnelExitEnabled && node.Mux.GetEnabled() && tunnel.Raw(node.TunnelProtocol) && p != nil && p.links[ingress] == key && h2RuleAllowed(p, open)
	}
	if !allowed() {
		conn.Write([]byte{1})
		return
	}
	if open.Target == tunnelHealthTarget {
		conn.Write([]byte{0})
		return
	}
	policy := e.tunnelPolicy.Load()
	timeout := policy.dialTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	dial, cancelDial := context.WithTimeout(ctx, timeout)
	target, err := e.dialTarget(dial, open.Network, open.Target)
	cancelDial()
	if err != nil {
		conn.Write([]byte{2})
		return
	}
	defer target.Close()
	if !allowed() {
		conn.Write([]byte{1})
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err = conn.Write([]byte{0}); err != nil {
		return
	}
	if open.Network == "udp" {
		e.relayDatagrams(ctx, &framedDatagram{Conn: conn}, target, allowed)
		return
	}
	stopTarget := context.AfterFunc(ctx, func() { target.Close() })
	defer stopTarget()
	watch := make(chan struct{})
	defer close(watch)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-watch:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if !allowed() || !e.targetAllowed(target) {
					cancel()
					return
				}
			}
		}
	}()
	finished := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		if half, ok := target.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		finished <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		if half, ok := conn.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		finished <- err
	}()
	select {
	case <-ctx.Done():
		conn.Close()
		target.Close()
		<-finished
		<-finished
	case err := <-finished:
		if err != nil {
			conn.Close()
			target.Close()
		} else {
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			target.SetDeadline(time.Now().Add(30 * time.Second))
		}
		select {
		case <-finished:
		case <-ctx.Done():
			conn.Close()
			target.Close()
			<-finished
		}
	}
}
