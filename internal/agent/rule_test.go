package agent

import (
	"context"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type addressedConn struct{ net.Conn }

func (c addressedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3456}
}
func (c addressedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4567}
}
func TestProxyRoundTripPreservesPayload(t *testing.T) {
	for _, mode := range []string{"v1", "v2"} {
		for _, host := range []string{"192.0.2.3", "2001:db8::3"} {
			t.Run(mode+host, func(t *testing.T) {
				dst := "198.51.100.2"
				if host[0] == '2' {
					dst = "2001:db8::4"
				}
				want := proxyAddresses{netip.AddrPortFrom(netip.MustParseAddr(host), 1234), netip.AddrPortFrom(netip.MustParseAddr(dst), 443)}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				done := make(chan error, 1)
				go func() {
					err := writeProxy(a, mode, want)
					if err == nil {
						_, err = a.Write([]byte("payload"))
					}
					a.Close()
					done <- err
				}()
				conn, got, err := readProxy(addressedConn{b}, mode, []string{"127.0.0.0/8"})
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("got %+v want %+v", got, want)
				}
				payload, err := io.ReadAll(conn)
				if err != nil || string(payload) != "payload" {
					t.Fatalf("%q %v", payload, err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestProxyRejectsUntrustedAndMalformed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := readProxy(addressedConn{b}, "v1", []string{"192.0.2.0/24"}); err == nil {
		t.Fatal("untrusted proxy accepted")
	}
	go func() { _, _ = a.Write([]byte("PROXY TCP4 spoofed 192.0.2.1 20 30\r\n")); a.Close() }()
	if _, _, err := readProxy(addressedConn{b}, "v1", []string{"127.0.0.1/32"}); err == nil {
		t.Fatal("malformed proxy accepted")
	}
}
func TestRuleConnectionAndIPLimits(t *testing.T) {
	r := newRuleRuntime(&pb.Rule{IpLimit: 1, ConnectionLimit: 2})
	if !r.open() || !r.open() || r.open() {
		t.Fatal("connection limit")
	}
	r.close()
	if !r.open() {
		t.Fatal("connection not released")
	}
	if !r.addIP("1.1.1.1") || !r.addIP("1.1.1.1") || r.addIP("2.2.2.2") {
		t.Fatal("IP limit")
	}
	r.removeIP("1.1.1.1")
	if r.addIP("2.2.2.2") {
		t.Fatal("IP released too soon")
	}
	r.removeIP("1.1.1.1")
	if !r.addIP("2.2.2.2") {
		t.Fatal("IP not released")
	}
}
func TestTargetSelectionAndFallback(t *testing.T) {
	r := newRuleRuntime(&pb.Rule{Targets: []string{"a", "b"}, Balance: "round_robin"})
	if r.selectTarget(nil) != 0 || r.selectTarget(nil) != 1 || r.selectTarget(nil) != 0 {
		t.Fatal("round robin")
	}
	r.policy.Balance = "least_connections"
	if r.selectTarget(nil) != 1 {
		t.Fatal("least connections")
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()
	r = newRuleRuntime(&pb.Rule{Targets: []string{deadAddr, target.Addr().String()}, Balance: "round_robin"})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, release, err := r.dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	release()
	if r.targetActive[0] != 0 || r.targetActive[1] != 0 {
		t.Fatal("target connection count leaked")
	}
}
func TestRuleLimiterSharedBothDirections(t *testing.T) {
	r := newRuleRuntime(&pb.Rule{SpeedBps: 128 << 10})
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if err := r.limiter.WaitN(context.Background(), BufferSize); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("rule combined limit %v", elapsed)
	}
}
