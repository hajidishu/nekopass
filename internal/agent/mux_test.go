package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
	"google.golang.org/protobuf/proto"
)

func TestMuxReceiveBudgetBoundsAndRelease(t *testing.T) {
	for _, full := range []bool{false, true} {
		var global atomic.Int64
		baseline := int64(0)
		if full {
			baseline = maxMuxReceiveBytes - 32
			global.Store(baseline)
		}
		left, right := net.Pipe()
		bounded := newMuxBudgetConn(left, &global)
		var header [12]byte
		header[1] = 0
		binary.BigEndian.PutUint32(header[4:], 1)
		binary.BigEndian.PutUint32(header[8:], 1)
		done := make(chan struct{})
		go func() { defer close(done); right.Write(append(header[:], 42)); right.Close() }()
		var got [12]byte
		if _, err := io.ReadFull(bounded, got[:]); err != nil {
			t.Fatal(err)
		}
		if full {
			if _, err := bounded.Read(make([]byte, 1)); err == nil {
				t.Fatal("saturated budget accepted data")
			}
		} else {
			b := make([]byte, 1)
			if _, err := io.ReadFull(bounded, b); err != nil {
				t.Fatal(err)
			}
			bounded.consumed(1, 1)
			if global.Load() != 64 {
				t.Fatal("stream overhead not tracked", global.Load())
			}
			bounded.release(1)
		}
		bounded.Close()
		<-done
		if global.Load() != baseline {
			t.Fatal("budget leaked or became negative", global.Load(), baseline)
		}
	}
}

func TestMuxPoolCapacityDoesNotPoisonExitHealth(t *testing.T) {
	h := newH2Transport()
	defer h.Close()
	var queued atomic.Int64
	m := newEgressManager(h, &queued)
	defer m.close()
	r := &pb.Rule{Id: 1, Enabled: true, EgressGroupId: 1, Protocol: "tcp", HealthFailures: 1, HealthSuccesses: 1, EgressPeers: []*pb.EgressPeer{{NodeId: 2, Weight: 1}}}
	m.update([]*pb.Rule{r})
	key := peerKey(peerRule(r, r.EgressPeers[0]))
	m.outcome(key, errMuxCapacity)
	selected, release, err := m.choose(r, nil)
	if err != nil || selected.EgressNodeId != 2 {
		t.Fatal("local Mux capacity marked healthy exit as failed", err)
	}
	release()
}

func TestMuxNodeLimitCountsLogicalSessions(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "random_tcp", "plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			udp := mode == "plain_udp" || mode == "dtls_udp" || mode == "random_udp"
			target := ""
			if udp {
				target = randomUDPEcho(t)
			} else {
				target, _ = inboundEcho(t, false)
			}
			e, h, c, r := muxFixture(t, mode, target)
			c.Node.MaxConnections = 1
			c.Node.Mux.MaxConnections = 1
			r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var conn net.Conn
			var err error
			if udp {
				conn, err = dialDatagramTunnel(ctx, ctx, r, target, h, &atomic.Int64{})
			} else {
				conn, err = h.rawMux.Dial(ctx, ctx, r, target, false)
			}
			if err != nil {
				t.Fatal("carrier consumed the logical session slot", err)
			}
			defer conn.Close()
			muxExchange(t, conn, []byte("one-logical-session"), udp)
		})
	}
}

func TestNativeMuxCapacityCloseAndIdleRecovery(t *testing.T) {
	for _, mode := range []string{"plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			target := randomUDPEcho(t)
			e, h, c, r := muxFixture(t, mode, target)
			c.Node.Mux.MaxConnections = 1
			c.Node.Mux.MaxStreams = 1
			r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var queued atomic.Int64
			first, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			if other, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued); !errors.Is(err, errMuxCapacity) {
				if other != nil {
					other.Close()
				}
				t.Fatal("native carrier cap ignored", err)
			}
			association := first.(*randomUDPFlow).association
			first.Close()
			second, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
			if err != nil {
				t.Fatal("closed UDP flow occupied capacity", err)
			}
			muxExchange(t, second, []byte("capacity-recovered"), true)
			second.Close()
			association.lastActivity.Store(time.Now().Add(-20 * time.Second).UnixNano())
			until := time.Now().Add(3 * time.Second)
			for association.ctx.Err() == nil && time.Now().Before(until) {
				time.Sleep(10 * time.Millisecond)
			}
			if association.ctx.Err() == nil {
				t.Fatal("idle UDP association not reclaimed")
			}
			next, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
			if err != nil {
				t.Fatal("closed UDP association was not replaceable", err)
			}
			next.Close()
		})
	}
}

func TestMuxConcurrentStreamsAndPoolCancellation(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, h, c, r := muxFixture(t, "tls_tcp", target)
	c.Node.MaxConnections = 200
	c.Node.Mux.MaxStreams = 32
	c.Node.Mux.MaxConnections = 2
	r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := h.rawMux.Dial(ctx, ctx, r, target, false)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			body := bytes.Repeat([]byte{byte(i)}, 8192)
			if _, err = conn.Write(body); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(body))
			_, err = io.ReadFull(conn, got)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(body, got) {
				errs <- errors.New("concurrent stream mixed bytes")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	idle := make(chan struct{})
	go func() { h.rawMux.Close(); close(idle) }()
	select {
	case <-idle:
	case <-time.After(2 * time.Second):
		t.Fatal("pool shutdown blocked")
	}
	if h.rawMux.queued.Load() != 0 {
		t.Fatal("concurrent pool leaked receive budget")
	}
}

func TestMuxManySimultaneousSessions(t *testing.T) {
	for _, mode := range []string{"tls_tcp", "plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			udp := mode != "tls_tcp"
			target := ""
			if udp {
				target = randomUDPEcho(t)
			} else {
				target, _ = inboundEcho(t, false)
			}
			e, h, c, r := muxFixture(t, mode, target)
			c.Node.MaxConnections = 0
			c.Node.Mux.MaxConnections = 0
			c.Node.Mux.MaxStreams = 64
			r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			if e.nativeUDP != nil {
				e.nativeUDP.conn.SetReadBuffer(1 << 20)
			}
			if e.randomUDP != nil {
				e.randomUDP.socket.SetReadBuffer(1 << 20)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var queued atomic.Int64
			var wg sync.WaitGroup
			errs := make(chan error, 256)
			ready := make(chan struct{})
			var opened atomic.Int64
			for i := range 256 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					var conn net.Conn
					var err error
					if udp {
						conn, err = dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
					} else {
						conn, err = h.rawMux.Dial(ctx, ctx, r, target, false)
					}
					if err != nil {
						errs <- err
						return
					}
					defer conn.Close()
					if udp {
						a := conn.(*randomUDPFlow).association
						if a.socket != nil {
							a.socket.SetReadBuffer(1 << 20)
						} else if peer, ok := a.datagrams.(*nativePeer); ok {
							peer.conn.SetReadBuffer(1 << 20)
						}
					}
					opened.Add(1)
					select {
					case <-ready:
					case <-ctx.Done():
						errs <- ctx.Err()
						return
					}
					size := 1024
					if udp {
						size = 64
					}
					body := bytes.Repeat([]byte{byte(i)}, size)
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					if _, err = conn.Write(body); err != nil {
						errs <- err
						return
					}
					b := make([]byte, len(body))
					var n int
					if udp {
						n, err = conn.Read(b)
					} else {
						n, err = io.ReadFull(conn, b)
					}
					if err != nil {
						errs <- err
					} else if !bytes.Equal(body, b[:n]) {
						errs <- errors.New("stress session payload mixed")
					}
				}(i)
			}
			until := time.Now().Add(20 * time.Second)
			for opened.Load() < 256 && len(errs) == 0 && time.Now().Before(until) {
				time.Sleep(10 * time.Millisecond)
			}
			close(ready)
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			if opened.Load() != 256 {
				t.Error("not all stress sessions opened", opened.Load())
			}
			h.Close()
			if queued.Load() != 0 || h.rawMux.queued.Load() != 0 {
				t.Error("stress shutdown leaked receive reservations", queued.Load(), h.rawMux.queued.Load())
			}
		})
	}
}

func TestMuxEndToEndGroupAccountingAndPause(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "random_tcp", "plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			udp := mode == "plain_udp" || mode == "dtls_udp" || mode == "random_udp"
			target := ""
			network := "tcp"
			if udp {
				target = randomUDPEcho(t)
				network = "udp"
			} else {
				target, _ = inboundEcho(t, false)
			}
			_, _, _, r := muxFixture(t, mode, target)
			s, err := OpenState(filepath.Join(t.TempDir(), "entry.db"))
			if err != nil {
				t.Fatal(err)
			}
			entry, err := NewEngine(s, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			defer entry.Close()
			rule := proto.Clone(r).(*pb.Rule)
			rule.Protocol = network
			rule.Enabled = true
			rule.ListenHost = "127.0.0.1"
			rule.Targets = []string{target}
			rule.MeteringConfigured = true
			rule.TrafficRate = 15000
			// Exercise peer selection, transport settings and the selected exit's rate.
			rule.EgressGroupId = 12
			rule.EgressNodeId = 0
			rule.EgressStrategy = "round_robin"
			rule.EgressPeers = []*pb.EgressPeer{{NodeId: r.EgressNodeId, Host: r.TunnelHost, Port: r.TunnelPort, Token: r.TunnelToken, Protocol: mode, Tls: r.Tls, Random: r.Random, Mux: r.Mux, Weight: 1, TrafficRate: 20000}}
			rule.Mux = nil
			cfg := &pb.ControlMessage{Node: &pb.NodeConfig{NodeId: 2, Enabled: true, SecurityConfigured: true, MaxConnections: 100, DialTimeoutSeconds: 8, UdpIdleTimeoutSeconds: 60}, Users: []*pb.UserPolicy{{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1000, MeteringConfigured: true, MaxConnections: 1}}, Rules: []*pb.Rule{rule}}
			if err = entry.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			var client net.Conn
			if udp {
				client, err = net.Dial("udp", entry.udpListeners[rule.Id].conn.LocalAddr().String())
			} else {
				client, err = net.Dial("tcp", entry.listeners[rule.Id].ln.Addr().String())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			muxExchange(t, client, []byte("hello"), udp)
			until := time.Now().Add(time.Second)
			for entry.counters[rule.Id].Load() != 10 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			account := entry.users[5]
			account.mu.Lock()
			traffic, charged := account.disk.Traffic, account.disk.Charged
			account.mu.Unlock()
			if traffic != 10 || charged != 20 {
				t.Fatal("Mux overhead billed or group rate lost", traffic, charged)
			}
			blocked, err := net.Dial(network, client.RemoteAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			blocked.SetDeadline(time.Now().Add(150 * time.Millisecond))
			blocked.Write([]byte("x"))
			b := make([]byte, 1)
			if _, err = blocked.Read(b); err == nil {
				t.Fatal("logical connection limit bypassed")
			}
			blocked.Close()
			rule.Enabled = false
			if err = entry.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			client.SetDeadline(time.Now().Add(200 * time.Millisecond))
			client.Write([]byte("stopped"))
			if _, err = client.Read(b); err == nil {
				t.Fatal("paused Mux rule kept forwarding")
			}
		})
	}
}

func muxFixture(t *testing.T, mode, target string) (*Engine, *h2Transport, *pb.ControlMessage, *pb.Rule) {
	e, h, c, r := h2Fixture(t, target)
	c.Node.TunnelProtocol = mode
	r.TunnelProtocol = mode
	r.Protocol = "tcp"
	c.Node.Mux = &pb.MuxConfig{Enabled: true, MaxStreams: 4, MaxConnections: 2, IdleTimeoutSeconds: 10}
	r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
	c.Node.DialTimeoutSeconds = 8
	c.Node.IdleTimeoutSeconds = 300
	if mode == "random_tcp" || mode == "random_udp" || mode == "dtls_udp" {
		randomFixture(t, c, r, tunnelcrypto.ChaCha20Poly1305)
	}
	if mode == "plain_udp" || mode == "dtls_udp" || mode == "random_udp" {
		r.Protocol = "udp"
		c.EgressRules[0].Protocol = "udp"
	}
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	return e, h, c, r
}
func muxExchange(t *testing.T, c net.Conn, body []byte, udp bool) {
	t.Helper()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write(body); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, maxDatagram)
	var n int
	var err error
	if udp {
		n, err = c.Read(got)
	} else {
		n, err = io.ReadFull(c, got[:len(body)])
	}
	if err != nil || !bytes.Equal(got[:n], body) {
		t.Fatalf("payload mismatch: got=%d want=%d err=%v", n, len(body), err)
	}
	c.SetDeadline(time.Time{})
}

func TestRawTCPMuxSecurityModesAndUserIsolation(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "random_tcp"} {
		t.Run(mode, func(t *testing.T) {
			target, _ := inboundEcho(t, false)
			e, h, c, r := muxFixture(t, mode, target)
			if mode == "tls_tcp" {
				c.Node.Tls.PaddingEnabled = true
				c.Node.Tls.PaddingScheme = []string{"stop=3", "0=30-30", "1=100-200", "2=400-600"}
				r.Tls.PaddingEnabled = true
				r.Tls.PaddingScheme = c.Node.Tls.PaddingScheme
				if err := e.Apply(c); err != nil {
					t.Fatal(err)
				}
			}
			grant := proto.Clone(c.EgressRules[0]).(*pb.EgressRule)
			grant.RuleId++
			grant.UserId++
			c.EgressRules = append(c.EgressRules, grant)
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			r2 := proto.Clone(r).(*pb.Rule)
			r2.Id++
			r2.UserId++
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			first, err := h.rawMux.Dial(ctx, ctx, r, target, false)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := h.rawMux.Dial(ctx, ctx, r2, target, false)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.(*rawMuxConn).budget != second.(*rawMuxConn).budget {
				t.Fatal("users did not share carrier")
			}
			muxExchange(t, first, bytes.Repeat([]byte("tcp-one"), 4096), false)
			muxExchange(t, second, []byte("independent-user"), false)
			bad := proto.Clone(r).(*pb.Rule)
			bad.UserId++
			if denied, err := h.rawMux.Dial(ctx, ctx, bad, target, false); err == nil {
				denied.Close()
				t.Fatal("cross-user metadata accepted")
			}
			c.EgressRules = c.EgressRules[1:]
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1100 * time.Millisecond)
			first.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := first.Read(make([]byte, 1)); err == nil {
				t.Fatal("revoked stream remained open")
			}
			muxExchange(t, second, []byte("remaining-user"), false)
			first.Close()
			second.Close()
			h.Close()
			if h.rawMux.queued.Load() != 0 {
				t.Fatal("Mux buffers leaked", h.rawMux.queued.Load())
			}
		})
	}
}

func TestRawTCPMuxUDPAndCapacity(t *testing.T) {
	target := randomUDPEcho(t)
	e, h, c, r := muxFixture(t, "tls_tcp", target)
	r.Protocol = "udp"
	c.EgressRules[0].Protocol = "udp"
	c.Node.Mux.MaxStreams = 1
	c.Node.Mux.MaxConnections = 1
	r.Mux = proto.Clone(c.Node.Mux).(*pb.MuxConfig)
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	first, err := dialDatagramTunnel(ctx, ctx, r, target, h, &atomic.Int64{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	muxExchange(t, first, bytes.Repeat([]byte{7}, 60000), true)
	if another, err := dialDatagramTunnel(ctx, ctx, r, target, h, &atomic.Int64{}); !errors.Is(err, errMuxCapacity) {
		if another != nil {
			another.Close()
		}
		t.Fatal("pool capacity ignored", err)
	}
	first.Close()
	next, err := dialDatagramTunnel(ctx, ctx, r, target, h, &atomic.Int64{})
	if err != nil {
		t.Fatal("capacity not returned", err)
	}
	defer next.Close()
	muxExchange(t, next, nil, true)
}

func TestRawTCPMuxHalfClose(t *testing.T) {
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
			go func() { defer c.Close(); body, _ := io.ReadAll(c); c.Write(append([]byte("reply:"), body...)) }()
		}
	}()
	_, h, _, r := muxFixture(t, "plain_tcp", target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := h.rawMux.Dial(ctx, ctx, r, target.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("after-eof"))
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil || string(body) != "reply:after-eof" {
		t.Fatal("half close truncated response", string(body), err)
	}
}

func TestNativeMuxSecurityModesAndFlowIsolation(t *testing.T) {
	for _, mode := range []string{"plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			target := randomUDPEcho(t)
			e, h, c, r := muxFixture(t, mode, target)
			if e.nativeUDP != nil {
				e.nativeUDP.conn.SetReadBuffer(1 << 20)
			}
			if e.randomUDP != nil {
				e.randomUDP.socket.SetReadBuffer(1 << 20)
			}
			grant := proto.Clone(c.EgressRules[0]).(*pb.EgressRule)
			grant.RuleId++
			grant.UserId++
			c.EgressRules = append(c.EgressRules, grant)
			if err := e.Apply(c); err != nil {
				t.Fatal(err)
			}
			r2 := proto.Clone(r).(*pb.Rule)
			r2.Id++
			r2.UserId++
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var queued atomic.Int64
			first, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := dialDatagramTunnel(ctx, ctx, r2, target, h, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if a := first.(*randomUDPFlow).association; a.socket != nil {
				a.socket.SetReadBuffer(1 << 20)
			} else if p, ok := a.datagrams.(*nativePeer); ok {
				p.conn.SetReadBuffer(1 << 20)
			}
			if first.(*randomUDPFlow).association != second.(*randomUDPFlow).association {
				t.Fatal("UDP flows did not share association")
			}
			for _, body := range [][]byte{nil, []byte("udp-small"), bytes.Repeat([]byte{9}, 65507)} {
				muxExchange(t, first, body, true)
			}
			first.Close()
			muxExchange(t, second, []byte("other flow remains alive"), true)
			bad := proto.Clone(r2).(*pb.Rule)
			bad.UserId++
			if denied, err := dialDatagramTunnel(ctx, ctx, bad, target, h, &queued); err == nil {
				denied.Close()
				t.Fatal("UDP cross-user metadata accepted")
			}
			second.Close()
			h.Close()
			if queued.Load() != 0 {
				t.Fatal("UDP Mux queues leaked", queued.Load())
			}
		})
	}
}
