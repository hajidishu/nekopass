package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekopass/nekopass/internal/ddns"
	"github.com/nekopass/nekopass/internal/networkpolicy"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

type listener struct {
	runtime *ruleRuntime
	rule    *pb.Rule
	ln      net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
}
type Engine struct {
	mu              sync.Mutex
	state           *State
	users           map[int64]*Account
	retired         map[string]*Account
	listeners       map[int64]*listener
	udpListeners    map[int64]*udpListener
	udpQueued       atomic.Int64
	udpNonceMu      sync.Mutex
	udpNonces       map[string]time.Time
	nativeUDP       *nativeUDPListener
	counters        map[int64]*atomic.Int64
	revision        int64
	syncError       string
	wg              sync.WaitGroup
	closed          bool
	maxConnections  atomic.Int64
	node            atomic.Pointer[pb.NodeConfig]
	targetPolicy    atomic.Pointer[networkpolicy.Policy]
	probe           atomic.Pointer[pb.Probe]
	connections     atomic.Int64
	tunnel          *tunnelListener
	tunnelPolicy    atomic.Pointer[tunnelPolicy]
	h2              *h2Transport
	h2Certificate   atomic.Pointer[tls.Certificate]
	acmeAck         atomic.Int64
	challengeServer *http.Server
	ddnsConfig      *pb.DDNSConfig
	ddnsCancel      context.CancelFunc
	ddnsStatus      atomic.Pointer[pb.DDNSStatus]
	ddnsClient      func() *ddns.Client
	updateDirectory string
	updateStatus    *pb.UpdateStatus
}

var buffers = sync.Pool{New: func() any { b := make([]byte, BufferSize); return &b }}

func NewEngine(s *State, maxConnections int64) (*Engine, error) {
	e := &Engine{state: s, users: map[int64]*Account{}, retired: map[string]*Account{}, listeners: map[int64]*listener{}, counters: map[int64]*atomic.Int64{}}
	e.h2 = newH2Transport()
	e.udpListeners = map[int64]*udpListener{}
	e.udpNonces = map[string]time.Time{}
	e.ddnsClient = ddns.NewClient
	e.maxConnections.Store(maxConnections)
	users, err := s.LoadUsers()
	if err != nil {
		return nil, err
	}
	for id, d := range users {
		e.users[id] = newAccount(id, d, s)
	}
	retired, err := s.LoadRetired()
	if err != nil {
		return nil, err
	}
	for key, d := range retired {
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			return nil, errors.New("invalid retired quota identity")
		}
		id, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, err
		}
		e.retired[key] = newAccount(id, d, s)
	}
	counts, err := s.LoadRules()
	if err != nil {
		return nil, err
	}
	for id, n := range counts {
		v := &atomic.Int64{}
		v.Store(n)
		e.counters[id] = v
	}
	return e, nil
}
func (e *Engine) Apply(c *pb.ControlMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine closed")
	}
	if c.Node != nil {
		policy, err := targetPolicy(c.Node.SecurityConfigured, c.Node.TargetDenyCidrs)
		if err != nil {
			return err
		}
		e.targetPolicy.Store(policy)
	}
	if err := e.restoreState(c); err != nil {
		return err
	}
	for _, ack := range c.AcknowledgedUsage {
		key := epochKey(ack.UserId, ack.QuotaEpoch)
		a := e.retired[key]
		if a == nil {
			continue
		}
		a.mu.Lock()
		matches := a.active.Load() == 0 && a.disk.Spent == ack.Spent && a.disk.Released == ack.Released && a.disk.Traffic == ack.Traffic && a.disk.UnlimitedSpent == ack.UnlimitedSpent
		a.mu.Unlock()
		if matches {
			if err := e.state.DropRetired(key); err != nil {
				return err
			}
			delete(e.retired, key)
		}
	}
	if err := e.state.SaveConfig(c); err != nil {
		return err
	}
	if err := e.configureUpdate(c.Update); err != nil {
		return err
	}
	restartListeners := false
	if c.Node != nil {
		old := e.node.Load()
		restartListeners = old != nil && (old.DialTimeoutSeconds != c.Node.DialTimeoutSeconds || old.IdleTimeoutSeconds != c.Node.IdleTimeoutSeconds || !slices.Equal(old.ProxyTrustedCidrs, c.Node.ProxyTrustedCidrs) || old.SecurityConfigured != c.Node.SecurityConfigured)
		e.node.Store(proto.Clone(c.Node).(*pb.NodeConfig))
		e.maxConnections.Store(c.Node.MaxConnections)
		e.configureDDNS(c.Node.Ddns)
	} else {
		e.configureDDNS(nil)
	}

	wantedUsers := map[int64]bool{}
	resetUsers := map[int64]bool{}
	for _, p := range c.Users {
		wantedUsers[p.Id] = true
		a := e.users[p.Id]
		if a != nil && a.disk.Epoch != p.QuotaEpoch {
			a.mu.Lock()
			if p.QuotaEpoch < a.disk.Epoch {
				a.mu.Unlock()
				return errors.New("quota epoch regressed")
			}
			a.policy = nil
			if err := a.persist(); err != nil {
				a.mu.Unlock()
				return err
			}
			e.retired[epochKey(a.id, a.disk.Epoch)] = a
			a.mu.Unlock()
			a = nil
			resetUsers[p.Id] = true
		}
		if a == nil {
			a = newAccount(p.Id, DiskUser{Epoch: p.QuotaEpoch}, e.state)
			if err := e.state.SaveUser(p.Id, a.disk); err != nil {
				return err
			}
			e.users[p.Id] = a
		}
		if err := a.configure(p); err != nil {
			return err
		}
	}
	for id, a := range e.users {
		if !wantedUsers[id] {
			a.mu.Lock()
			a.policy = nil
			a.mu.Unlock()
		}
	}
	wanted := map[int64]*pb.Rule{}
	for _, r := range c.Rules {
		if networkIncludes(r.Protocol, "tcp") && (c.Node == nil && e.maxConnections.Load() > 0 || c.Node != nil && c.Node.Enabled) && r.Enabled && e.users[r.UserId] != nil && e.users[r.UserId].valid() {
			wanted[r.Id] = r
		}
	}
	for id, l := range e.listeners {
		r := wanted[id]
		if restartListeners || resetUsers[l.rule.UserId] || r == nil || !proto.Equal(r, l.rule) {
			l.cancel()
			l.ln.Close()
			delete(e.listeners, id)
		}
	}
	var errs []string
	e.h2.Prune(c.Rules)
	if err := e.configureACME(c); err != nil {
		errs = append(errs, "certificate validation port unavailable")
	}
	if err := e.configureTunnel(c); err != nil {
		errs = append(errs, "tunnel: "+err.Error())
	}
	for id, r := range wanted {
		if e.listeners[id] != nil {
			continue
		}
		address := net.JoinHostPort(r.ListenHost, strconv.Itoa(int(r.ListenPort)))
		ln, err := net.Listen("tcp", address)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule %d: %v", id, err))
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		l := &listener{rule: r, runtime: newRuleRuntime(r), ln: ln, ctx: ctx, cancel: cancel}
		l.runtime.configureNode(e.nodeConfiguration())
		l.runtime.h2 = e.h2
		l.runtime.dialTarget = e.dialTarget
		e.listeners[id] = l
		count := e.counters[id]
		if count == nil {
			count = &atomic.Int64{}
			e.counters[id] = count
		}
		a := e.users[r.UserId]
		e.wg.Add(1)
		go e.accept(l, a, count)
	}
	errs = append(errs, e.configureUDP(c)...)
	e.syncError = strings.Join(errs, "; ")
	if len(errs) == 0 {
		e.revision = c.Revision
	}
	return nil
}
func (e *Engine) accept(l *listener, a *Account, count *atomic.Int64) {
	defer e.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		active := e.connections.Add(1)
		if cap := e.maxConnections.Load(); cap > 0 && active > cap {
			e.connections.Add(-1)
			c.Close()
			continue
		}
		if !a.acquire() {
			e.connections.Add(-1)
			c.Close()
			continue
		}
		if !l.runtime.open() {
			a.active.Add(-1)
			e.connections.Add(-1)
			c.Close()
			continue
		}
		e.wg.Add(1)
		go func() {
			defer l.runtime.close()
			defer e.wg.Done()
			defer e.connections.Add(-1)
			defer a.active.Add(-1)
			e.forward(l, c, a, count)
		}()
	}
}
func (e *Engine) forward(l *listener, client net.Conn, a *Account, count *atomic.Int64) {
	activity := &atomic.Int64{}
	activity.Store(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.WithValue(l.ctx, activityKey{}, activity))
	defer cancel()
	defer client.Close()
	trusted := l.rule.ProxyTrustedCidrs
	if node := e.node.Load(); node != nil && node.SecurityConfigured {
		trusted = node.ProxyTrustedCidrs
	}
	effective, addresses, err := readProxy(client, l.rule.ProxyAccept, trusted)
	if err != nil {
		return
	}
	client = effective
	ip := addresses.src.Addr().Unmap().String()
	if !a.addIP(ip) {
		return
	}
	defer a.removeIP(ip)
	if !l.runtime.addIP(ip) {
		return
	}
	defer l.runtime.removeIP(ip)
	target, release, err := l.runtime.dial(ctx)
	if err != nil {
		return
	}
	defer release()
	if err = writeProxy(target, l.rule.ProxySend, addresses); err != nil {
		target.Close()
		return
	}
	defer target.Close()
	activity.Store(time.Now().UnixNano())
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				client.Close()
				target.Close()
				return
			case <-stopped:
				return
			case <-ticker.C:
				if !a.valid() || (l.rule.EgressNodeId == 0 && !e.targetAllowed(target)) || (l.runtime.idleTimeout > 0 && time.Since(time.Unix(0, activity.Load())) >= l.runtime.idleTimeout) {
					cancel()
				}
			}
		}
	}()
	result := make(chan error, 2)
	go func() { result <- copyData(ctx, target, client, a, count, l.runtime.limiter) }()
	go func() { result <- copyData(ctx, client, target, a, count, l.runtime.limiter) }()
	first := <-result
	if first != nil {
		cancel()
		client.Close()
		target.Close()
	} else {
		// Preserve TCP half-close, but don't retain half-closed connections indefinitely.
		_ = client.SetDeadline(time.Now().Add(30 * time.Second))
		_ = target.SetDeadline(time.Now().Add(30 * time.Second))
	}
	<-result
}

type activityKey struct{}

func copyData(ctx context.Context, dst, src net.Conn, a *Account, count *atomic.Int64, limits ...*rate.Limiter) error {
	holder := buffers.Get().(*[]byte)
	defer buffers.Put(holder)
	buf := *holder
	activity, _ := ctx.Value(activityKey{}).(*atomic.Int64)
	for {
		if activity == nil {
			_ = src.SetReadDeadline(time.Now().Add(5 * time.Minute))
		}
		n, readErr := src.Read(buf)
		if n > 0 && activity != nil {
			activity.Store(time.Now().UnixNano())
		}
		for offset := 0; offset < n; {
			size, err := a.take(ctx, n-offset)
			if err != nil {
				return err
			}
			if err = a.limiter.WaitN(ctx, size); err != nil {
				return err
			}
			for _, limiter := range limits {
				if limiter != nil {
					if err = limiter.WaitN(ctx, size); err != nil {
						return err
					}
				}
			}
			_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, err := dst.Write(buf[offset : offset+size])
			if written > 0 && activity != nil {
				activity.Store(time.Now().UnixNano())
			}
			a.count(written)
			count.Add(int64(written))
			offset += written
			if err != nil {
				return err
			}
			if written != size {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if tcp, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = tcp.CloseWrite()
				}
				return nil
			}
			return readErr
		}
	}
}
func (e *Engine) Report() (*pb.AgentMessage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.users {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	for _, a := range e.retired {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	r := &pb.AgentMessage{ProtocolVersion: 16, AgentVersion: release.Version, UpdateSupported: e.updateDirectory != "", UpdateStatus: e.readUpdateStatus(), AcmeAck: e.acmeAck.Load(), Probe: e.probe.Load(), InstanceId: e.state.Instance, AppliedRevision: e.revision, Error: e.syncError, ActiveConnections: e.connections.Load(), DdnsStatus: e.ddnsStatus.Load()}
	pending, err := e.state.RestorePending()
	if err != nil {
		return nil, err
	}
	if pending {
		r.RestoreState = true
		r.AppliedRevision = 0
		r.ActiveConnections = 0
		return r, nil
	}
	users := map[int64]DiskUser{}
	for _, a := range e.users {
		u, wanted, err := a.report()
		if err != nil {
			return nil, err
		}
		if a.disk.Issued > 0 || u.Spent > 0 || u.Traffic > 0 || u.Released > 0 || u.UnlimitedSpent > 0 {
			r.Usage = append(r.Usage, u)
		}
		users[a.id] = a.disk
		if wanted {
			r.RequestUsers = append(r.RequestUsers, a.id)
		}
	}
	retired := map[string]DiskUser{}
	for key, a := range e.retired {
		u, _, err := a.report()
		if err != nil {
			return nil, err
		}
		r.Usage = append(r.Usage, u)
		retired[key] = a.disk
	}
	values := map[int64]int64{}
	for id, v := range e.counters {
		values[id] = v.Load()
		r.RuleUsage = append(r.RuleUsage, &pb.RuleUsage{RuleId: id, Traffic: values[id]})
	}
	if err := e.state.checkpoint(users, values, retired); err != nil {
		for _, a := range e.users {
			a.fatal = err
		}
		return nil, err
	}
	return r, nil
}
func (e *Engine) Close() {
	e.mu.Lock()
	e.closed = true
	if e.ddnsCancel != nil {
		e.ddnsCancel()
		e.ddnsCancel = nil
	}
	if e.tunnel != nil {
		e.tunnel.cancel()
		e.tunnel.ln.Close()
		e.tunnel = nil
	}
	if e.nativeUDP != nil {
		e.nativeUDP.cancel()
		e.nativeUDP.conn.Close()
		e.nativeUDP = nil
	}
	for _, l := range e.listeners {
		l.cancel()
		l.ln.Close()
	}
	for _, l := range e.udpListeners {
		l.cancel()
		l.conn.Close()
	}
	e.mu.Unlock()
	e.h2.Close()
	if e.challengeServer != nil {
		e.challengeServer.Close()
	}
	e.wg.Wait()
	if _, err := e.Report(); err != nil {
		slog.Error("final usage checkpoint", "error", err)
	}
}
