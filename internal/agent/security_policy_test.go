package agent

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/networkpolicy"
)

func TestSequenceReplayWindowHasNoLifetimeBudget(t *testing.T) {
	s := &h2ServerSession{}
	for n := uint64(1); n <= 25000; n++ {
		if !s.takeSequence(n) || s.takeSequence(n) {
			t.Fatal("sequence rejected or replay accepted", n)
		}
	}
	if s.takeSequence(1) || s.takeSequence(0) {
		t.Fatal("expired/zero counter accepted")
	}
	s = &h2ServerSession{}
	if !s.takeSequence(4) || !s.takeSequence(2) || s.takeSequence(2) {
		t.Fatal("out-of-order/replay handling")
	}
	if !s.takeSequence(^uint64(0)) || s.takeSequence(^uint64(0)) {
		t.Fatal("maximum counter handling")
	}
}

func policyEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln
}

func TestH2ExhaustedSharedPoolAndLongLivedStream(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-rotation", true: "sequence"}[modern], func(t *testing.T) {
			target := policyEcho(t)
			_, transport, _, rule := h2Fixture(t, target.Addr().String())
			rule.Tls.PoolSize = 1
			rule.Tls.SequenceAuth = modern
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			held, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			pool := transport.pools[h2PoolKey(rule)]
			pool.mu.Lock()
			first := pool.peers[0]
			first.opened = 4096
			first.exhaustedAt = time.Now().Add(-31 * time.Second)
			first.sequence = 9000
			pool.mu.Unlock()
			fresh, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
			if err != nil {
				t.Fatal("pool permanently exhausted", err)
			}
			defer fresh.Close()
			pool.mu.Lock()
			same := pool.peers[0] == first
			size := len(pool.peers)
			pool.mu.Unlock()
			if size != 1 || same != modern {
				t.Fatal("incorrect rotation/cap", size, same)
			}
			if modern {
				if _, err = held.Write([]byte("still-alive")); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 11)
				if _, err = io.ReadFull(held, buf); err != nil || string(buf) != "still-alive" {
					t.Fatal("long stream disrupted", err)
				}
			}
		})
	}
}

func TestTargetDialChecksResolvedIPAndPolicyChanges(t *testing.T) {
	target := policyEcho(t)
	e := &Engine{}
	p, _ := networkpolicy.Compile(networkpolicy.Defaults())
	e.targetPolicy.Store(p)
	_, port, _ := net.SplitHostPort(target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, address := range []string{target.Addr().String(), net.JoinHostPort("localhost", port), net.JoinHostPort("::ffff:127.0.0.1", port)} {
		if c, err := e.dialTarget(ctx, "tcp", address); err == nil {
			c.Close()
			t.Fatal("private resolved target accepted", address)
		}
	}
	p, _ = networkpolicy.Compile([]string{})
	e.targetPolicy.Store(p)
	c, err := e.dialTarget(ctx, "tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, _ = networkpolicy.Compile(networkpolicy.Defaults())
	e.targetPolicy.Store(p)
	if e.targetAllowed(c) {
		t.Fatal("existing connection ignores policy changes")
	}
}

func TestTunnelExitEnforcesACLAfterDNSResolutionAndClosesLiveStreams(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		t.Run(mode, func(t *testing.T) {
			target := policyEcho(t)
			_, port, _ := net.SplitHostPort(target.Addr().String())
			address := net.JoinHostPort("localhost", port)
			e, transport, config, rule := h2Fixture(t, address)
			rule.Tls.SequenceAuth = true
			rule.TunnelProtocol = mode
			config.Node.TunnelProtocol = mode
			config.Node.SecurityConfigured = true
			if err := e.Apply(config); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			dial := func() (net.Conn, error) {
				if mode == "plain_h2" || mode == "tls_h2" {
					return transport.Dial(ctx, ctx, rule, address)
				}
				return dialTunnel(ctx, rule, address)
			}
			c, err := dial()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			config.Node.TargetDenyCidrs = networkpolicy.Defaults()
			if err = e.Apply(config); err != nil {
				t.Fatal(err)
			}
			if blocked, err := dial(); err == nil {
				blocked.Close()
				t.Fatal("exit dial bypassed ACL using a hostname")
			}
			result := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, c); result <- err }()
			select {
			case <-result:
			case <-time.After(3 * time.Second):
				t.Fatal("live private stream survived ACL change")
			}
		})
	}
}

func TestLegacyNonceLimitStillRejectsReplay(t *testing.T) {
	s := &h2ServerSession{nonces: map[string]bool{}}
	if !s.take(strings.Repeat("a", 32)) || s.take(strings.Repeat("a", 32)) {
		t.Fatal("legacy replay accepted")
	}
}
