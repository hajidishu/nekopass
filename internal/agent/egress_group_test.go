package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"google.golang.org/protobuf/proto"
)

func TestGroupWeightedSchedulingStandbyAndRecovery(t *testing.T) {
	h2 := newH2Transport()
	defer h2.Close()
	var queued atomic.Int64
	m := newEgressManager(h2, &queued)
	defer m.close()
	r := &pb.Rule{Id: 11, UserId: 5, IngressNodeId: 2, EgressGroupId: 10, Enabled: true, Protocol: "tcp", HealthIntervalSeconds: 60, HealthFailures: 3, HealthSuccesses: 2, EgressStrategy: "round_robin", EgressPeers: []*pb.EgressPeer{{NodeId: 3, Weight: 2}, {NodeId: 4, Weight: 1}, {NodeId: 5, Weight: 1, Standby: true}}}
	m.update([]*pb.Rule{r})
	counts := map[int64]int{}
	for i := 0; i < 300; i++ {
		v, release, err := m.choose(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		counts[v.EgressNodeId]++
		release()
	}
	if counts[3] != 200 || counts[4] != 100 || counts[5] != 0 {
		t.Fatal("weighted round robin or standby incorrect", counts)
	}
	r.EgressStrategy = "least_connections"
	var releases []func()
	counts = map[int64]int{}
	for i := 0; i < 30; i++ {
		v, release, err := m.choose(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		counts[v.EgressNodeId]++
		releases = append(releases, release)
	}
	if counts[3] != 20 || counts[4] != 10 {
		t.Fatal("weighted least connections incorrect", counts)
	}
	for _, release := range releases {
		release()
	}
	for _, p := range r.EgressPeers[:2] {
		for i := 0; i < 3; i++ {
			m.outcome(peerKey(peerRule(r, p)), errors.New("unreachable"))
		}
	}
	v, release, err := m.choose(r, nil)
	if err != nil || v.EgressNodeId != 5 {
		t.Fatal("standby not activated", err)
	}
	release()
	key := peerKey(peerRule(r, r.EgressPeers[0]))
	m.outcome(key, nil)
	v, release, err = m.choose(r, nil)
	if err != nil || v.EgressNodeId != 5 {
		t.Fatal("primary recovered prematurely", err)
	}
	release()
	m.outcome(key, nil)
	v, release, err = m.choose(r, nil)
	if err != nil || v.EgressNodeId != 3 {
		t.Fatal("primary did not recover", err)
	}
	release()
	// Target failures must not eject an otherwise healthy tunnel.
	for i := 0; i < 10; i++ {
		m.outcome(key, errTunnelTarget)
	}
	v, release, err = m.choose(r, nil)
	if err != nil || v.EgressNodeId != 3 {
		t.Fatal("target failure poisoned exit health", err)
	}
	release()
}

func TestGroupRecoveryThresholdWithoutUserTraffic(t *testing.T) {
	h2 := newH2Transport()
	defer h2.Close()
	var queued atomic.Int64
	m := newEgressManager(h2, &queued)
	defer m.close()
	r := &pb.Rule{Id: 1, Enabled: true, EgressGroupId: 1, Protocol: "tcp", HealthIntervalSeconds: 60, HealthFailures: 3, HealthSuccesses: 2, EgressPeers: []*pb.EgressPeer{{NodeId: 1, Weight: 1}, {NodeId: 2, Weight: 1, Standby: true}}}
	other := proto.Clone(r).(*pb.Rule)
	other.Id = 2
	other.EgressGroupId = 2
	other.HealthSuccesses = 1
	m.update([]*pb.Rule{r, other})
	key := peerKey(peerRule(r, r.EgressPeers[0]))
	for i := 0; i < 3; i++ {
		m.outcome(key, errors.New("offline"))
	}
	m.outcome(key, nil)
	// No choose() took place while the primary was offline.
	v, release, err := m.choose(r, nil)
	if err != nil || v.EgressNodeId != 2 {
		t.Fatal("primary recovered after just one success", err)
	}
	release()
	v, release, err = m.choose(other, nil)
	if err != nil || v.EgressNodeId != 1 {
		t.Fatal("shared probe ignored independent group thresholds", err)
	}
	release()
	m.outcome(key, nil)
	v, release, err = m.choose(r, nil)
	if err != nil || v.EgressNodeId != 1 {
		t.Fatal("primary did not recover after two successes", err)
	}
	release()
}

func TestGroupAuthenticatedHealthAllTransports(t *testing.T) {
	for _, mode := range []string{"random_tcp", "random_h2", "plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "plain_udp", "dtls_udp", "random_udp", "tls_h3"} {
		t.Run(mode, func(t *testing.T) {
			exit, h2, cfg, r := h2Fixture(t, "127.0.0.1:1")
			randomFixture(t, cfg, r, "chacha20-poly1305")
			cfg.Node.TunnelProtocol = mode
			r.TunnelProtocol = mode
			r.Protocol = "tcp"
			if tunnel.UDP(mode) {
				r.Protocol = "udp"
				cfg.EgressRules[0].Protocol = "udp"
			}
			if !tunnel.TLS(mode) {
				r.Tls.Fingerprint = "off"
			}
			if mode == "tls_tcp" {
				cfg.Node.Tls.PaddingEnabled = true
				r.Tls.PaddingEnabled = true
			}
			if err := exit.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			var queued atomic.Int64
			conn, err := dialEgress(ctx, ctx, r, tunnelHealthTarget, r.Protocol == "udp", h2, &queued)
			if err != nil {
				t.Fatal("health failed", err)
			}
			if tunnel.UDP(mode) {
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				conn.Write([]byte{0})
				var b [1]byte
				if n, err := conn.Read(b[:]); err != nil || n != 1 || b[0] != 0 {
					t.Fatal("native health response invalid", err)
				}
			}
			conn.Close()
			bad := proto.Clone(r).(*pb.Rule)
			bad.UserId++
			if !tunnel.Raw(mode) {
				if c, err := dialEgress(ctx, ctx, bad, tunnelHealthTarget, bad.Protocol == "udp", h2, &queued); err == nil {
					c.Close()
					t.Fatal("health bypassed user authorization")
				}
			}
			cfg.EgressRules = nil
			if err := exit.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			if c, err := dialEgress(ctx, ctx, r, tunnelHealthTarget, r.Protocol == "udp", h2, &queued); err == nil {
				c.Close()
				t.Fatal("health bypassed revoked rule")
			}
		})
	}
}

func TestGroupTargetRejectionDoesNotLookLikeTunnelFailure(t *testing.T) {
	for _, mode := range []string{"random_tcp", "random_h2", "plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "tls_h3"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				exit, h2, cfg, r := h2Fixture(t, "127.0.0.1:1")
				randomFixture(t, cfg, r, "chacha20-poly1305")
				cfg.Node.TunnelProtocol = mode
				r.TunnelProtocol = mode
				r.Protocol = network
				cfg.EgressRules[0].Protocol = network
				cfg.Node.SecurityConfigured = true
				cfg.Node.TargetDenyCidrs = []string{"127.0.0.0/8"}
				if err := exit.Apply(cfg); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var queued atomic.Int64
				if c, err := dialEgress(ctx, ctx, r, "127.0.0.1:1", network == "udp", h2, &queued); !errors.Is(err, errTunnelTarget) {
					if c != nil {
						c.Close()
					}
					t.Fatal("target rejection classified as tunnel failure", err)
				}
			})
		}
	}
}

func TestGroupTCPFailoverStickySessionsAndQuota(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	exit, _, cfg, r := h2Fixture(t, target.Addr().String())
	randomFixture(t, cfg, r, "chacha20-poly1305")
	cfg.Node.TunnelProtocol = "plain_tcp"
	if err = exit.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := int32(dead.Addr().(*net.TCPAddr).Port)
	dead.Close()
	state, err := OpenState(filepath.Join(t.TempDir(), "entry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	entry, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	r.EgressNodeId = 0
	r.EgressGroupId = 10
	r.Enabled = true
	r.Protocol = "tcp"
	r.ListenHost = "127.0.0.1"
	r.Targets = []string{target.Addr().String()}
	r.Tls = nil
	r.EgressPeers = []*pb.EgressPeer{{NodeId: 4, Host: "127.0.0.1", Port: deadPort, Token: r.TunnelToken, Protocol: "plain_tcp", Weight: 1}, {NodeId: 3, Host: "127.0.0.1", Port: cfg.Node.TunnelListenPort, Token: r.TunnelToken, Protocol: "plain_tcp", Weight: 1, Standby: true}}
	r.HealthFailures = 1
	r.HealthSuccesses = 2
	r.HealthIntervalSeconds = 2
	r.EgressStrategy = "round_robin"
	message := &pb.ControlMessage{Revision: 1, Node: &pb.NodeConfig{Enabled: true, ListenHost: "127.0.0.1", SecurityConfigured: true, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, MaxConnections: 100}, Users: []*pb.UserPolicy{{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1 << 20}}, Rules: []*pb.Rule{r}}
	if err = entry.Apply(message); err != nil {
		t.Fatal(err)
	}
	l := entry.listeners[r.Id]
	conn, err := net.Dial("tcp", l.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	echo := func() {
		t.Helper()
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		var b [5]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil || string(b[:]) != "hello" {
			t.Fatal("failover lost payload", err)
		}
	}
	echo()
	// A scheduling-only edit must retain the listener and established connection.
	updated := proto.Clone(message).(*pb.ControlMessage)
	updated.Revision++
	updated.Rules[0].EgressStrategy = "random"
	updated.Rules[0].EgressPeers[0].Weight = 4
	if err = entry.Apply(updated); err != nil {
		t.Fatal(err)
	}
	if entry.listeners[r.Id] != l {
		t.Fatal("group edit restarted listener")
	}
	echo()
	deadline := time.Now().Add(time.Second)
	for entry.counters[r.Id].Load() != 20 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entry.counters[r.Id].Load() != 20 {
		t.Fatal("health or failover counted as payload", entry.counters[r.Id].Load())
	}
	entry.users[5].mu.Lock()
	traffic := entry.users[5].disk.Traffic
	entry.users[5].mu.Unlock()
	if traffic != 20 {
		t.Fatal("user payload accounting changed", traffic)
	}
}

func TestGroupUDPMixedTransportsStickySessionsAndMetering(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, maxDatagram)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], from)
		}
	}()
	var peers []*pb.EgressPeer
	var base *pb.Rule
	for i, mode := range []string{"plain_udp", "tls_h3"} {
		exit, _, cfg, r := h2Fixture(t, echo.LocalAddr().String())
		randomFixture(t, cfg, r, "chacha20-poly1305")
		cfg.Node.TunnelProtocol = mode
		cfg.EgressRules[0].Protocol = "udp"
		r.TunnelProtocol = mode
		r.Protocol = "udp"
		if err = exit.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, &pb.EgressPeer{NodeId: int64(30 + i), Host: r.TunnelHost, Port: r.TunnelPort, Token: r.TunnelToken, Protocol: mode, Tls: r.Tls, Weight: 1})
		base = r
	}
	state, err := OpenState(filepath.Join(t.TempDir(), "udp-entry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	entry, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	r := proto.Clone(base).(*pb.Rule)
	r.Enabled = true
	r.EgressNodeId = 0
	r.EgressGroupId = 10
	r.EgressPeers = peers
	r.EgressStrategy = "round_robin"
	r.HealthIntervalSeconds = 2
	r.HealthFailures = 3
	r.HealthSuccesses = 2
	r.ListenHost = "127.0.0.1"
	r.Targets = []string{echo.LocalAddr().String()}
	r.Tls = nil
	message := &pb.ControlMessage{Revision: 1, Node: &pb.NodeConfig{Enabled: true, SecurityConfigured: true, MaxConnections: 100, DialTimeoutSeconds: 8, UdpIdleTimeoutSeconds: 60}, Users: []*pb.UserPolicy{{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1 << 20}}, Rules: []*pb.Rule{r}}
	if err = entry.Apply(message); err != nil {
		t.Fatal(err)
	}
	l := entry.udpListeners[r.Id]
	var clients []*net.UDPConn
	for i := 0; i < 2; i++ {
		c, err := net.DialUDP("udp", nil, l.conn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clients = append(clients, c)
	}
	var used int64
	check := func(c *net.UDPConn, p []byte) {
		t.Helper()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, maxDatagram)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != string(p) {
			t.Fatal("group UDP boundary/payload changed", err)
		}
		used += int64(len(p) * 2)
	}
	for _, c := range clients {
		check(c, []byte("hello"))
		check(c, nil)
	}
	entry.egress.mu.Lock()
	for _, h := range entry.egress.peers {
		if h.active != 1 {
			t.Error("UDP session not balanced/sticky", h.active)
		}
	}
	entry.egress.mu.Unlock()
	updated := proto.Clone(message).(*pb.ControlMessage)
	updated.Revision++
	updated.Rules[0].EgressStrategy = "random"
	if err = entry.Apply(updated); err != nil {
		t.Fatal(err)
	}
	if entry.udpListeners[r.Id] != l {
		t.Fatal("scheduling edit discarded UDP associations")
	}
	for _, c := range clients {
		check(c, []byte("still same association"))
	}
	deadline := time.Now().Add(time.Second)
	for entry.counters[r.Id].Load() != used && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entry.counters[r.Id].Load() != used {
		t.Fatal("UDP group accounting included framing/probes", entry.counters[r.Id].Load(), used)
	}
}
