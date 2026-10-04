package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func plainPermissionFixture(t *testing.T, target string) (*Engine, *pb.ControlMessage, *pb.Rule) {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(state, 100)
	if err != nil {
		state.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close(); state.Close() })
	key := strings.Repeat("a", 64)
	cfg := &pb.ControlMessage{Revision: 1,
		Node:        &pb.NodeConfig{NodeId: 3, Enabled: true, TunnelExitEnabled: true, TunnelProtocol: "plain_tcp", TunnelListenHost: "127.0.0.1", TunnelListenPort: int32(port), MaxConnections: 100},
		TunnelLinks: []*pb.TunnelLink{{IngressNodeId: 2, Token: key}},
		EgressRules: []*pb.EgressRule{{RuleId: 11, IngressNodeId: 2, UserId: 5, QuotaEpoch: 3, ExpiresUnix: time.Now().Add(time.Hour).Unix(), Targets: []string{target}}},
	}
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	rule := &pb.Rule{Id: 11, UserId: 5, IngressNodeId: 2, TunnelHost: "127.0.0.1", TunnelPort: int32(port), TunnelToken: key, TunnelProtocol: "plain_tcp"}
	return engine, cfg, rule
}

func TestPlainTunnelRejectsExpiredRuleBeforeTargetDial(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	engine, cfg, rule := plainPermissionFixture(t, target.Addr().String())
	cfg.EgressRules[0].ExpiresUnix = time.Now().Add(-time.Second).Unix()
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := dialTunnel(ctx, rule, target.Addr().String()); err == nil {
		c.Close()
		t.Fatal("expired rule accepted")
	}
	target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, err := target.Accept(); err == nil {
		c.Close()
		t.Fatal("expired rule reached target")
	}
}

func TestPlainTunnelRevokesExistingConnections(t *testing.T) {
	for _, mode := range []string{"rule_removed", "target_removed", "key_rotated", "link_removed", "user_changed", "epoch_changed", "expired", "offline_expiry", "node_disabled", "exit_disabled", "half_closed"} {
		t.Run(mode, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := target.Accept()
				if err == nil {
					accepted <- c
				}
			}()
			engine, cfg, rule := plainPermissionFixture(t, target.Addr().String())
			if mode == "offline_expiry" {
				cfg.EgressRules[0].ExpiresUnix = time.Now().Add(2 * time.Second).Unix()
				if err = engine.Apply(cfg); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			upstream, err := dialTunnel(ctx, rule, target.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			var peer net.Conn
			select {
			case peer = <-accepted:
			case <-ctx.Done():
				t.Fatal("target not connected")
			}
			defer peer.Close()
			if mode == "half_closed" {
				upstream.(*net.TCPConn).CloseWrite()
				peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err = io.ReadAll(peer); err != nil {
					t.Fatal("upload FIN not forwarded", err)
				}
			}
			// An unrelated revision must keep an otherwise authorized stream alive.
			cfg.Revision++
			if err = engine.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "rule_removed", "half_closed":
				cfg.EgressRules = nil
			case "target_removed":
				cfg.EgressRules[0].Targets = []string{"127.0.0.1:1"}
			case "key_rotated":
				cfg.TunnelLinks[0].Token = strings.Repeat("b", 64)
			case "link_removed":
				cfg.TunnelLinks = nil
			case "user_changed":
				cfg.EgressRules[0].UserId++
			case "epoch_changed":
				cfg.EgressRules[0].QuotaEpoch++
			case "expired":
				cfg.EgressRules[0].ExpiresUnix = time.Now().Add(-time.Second).Unix()
			case "node_disabled":
				cfg.Node.Enabled = false
			case "exit_disabled":
				cfg.Node.TunnelExitEnabled = false
			}
			if mode != "offline_expiry" {
				if err = engine.Apply(cfg); err != nil {
					t.Fatal(err)
				}
			}
			upstream.SetReadDeadline(time.Now().Add(3500 * time.Millisecond))
			_, err = upstream.Read(make([]byte, 1))
			var timeout net.Error
			if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("revoked upstream remained open")
			}
			if mode != "half_closed" {
				peer.SetReadDeadline(time.Now().Add(time.Second))
				_, err = peer.Read(make([]byte, 1))
				if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatal("revoked target remained open")
				}
			}
		})
	}
}

func TestPlainTunnelKeepsValidStreamOnRefreshAndExpiryExtension(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	engine, cfg, rule := plainPermissionFixture(t, target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialTunnel(ctx, rule, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg.Revision++
	cfg.EgressRules[0].ExpiresUnix = time.Now().Add(2 * time.Hour).Unix()
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	// Cross a watchdog check with a changed revision and expiry, but unchanged identity.
	time.Sleep(1100 * time.Millisecond)
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "ok" {
		t.Fatal("valid refresh interrupted stream", err)
	}
}
