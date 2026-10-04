package agent

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func TestPlainTunnelValidatesLinkAndRuleTarget(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	state, err := OpenState(filepath.Join(t.TempDir(), "tunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	secret := strings.Repeat("a", 64)
	rule := &pb.Rule{Id: 11, IngressNodeId: 2, EgressNodeId: 3, TunnelHost: "127.0.0.1", TunnelPort: int32(port), TunnelToken: secret, TunnelProtocol: "plain_tcp", Targets: []string{target.Addr().String()}, Balance: "random"}
	config := &pb.ControlMessage{Revision: 1, Node: &pb.NodeConfig{NodeId: 3, Enabled: true, TunnelExitEnabled: true, TunnelProtocol: "plain_tcp", TunnelListenHost: "127.0.0.1", TunnelListenPort: int32(port), MaxConnections: 100}, TunnelLinks: []*pb.TunnelLink{{IngressNodeId: 2, Token: secret}}, EgressRules: []*pb.EgressRule{{RuleId: 11, IngressNodeId: 2, Targets: []string{target.Addr().String()}}}}
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	r := newRuleRuntime(rule)
	r.configureNode(config.Node)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, release, err := r.dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatal("plain tunnel did not relay bytes", string(buf), err)
	}
	conn.Close()
	for _, change := range []func(*pb.Rule){func(r *pb.Rule) { r.TunnelToken = strings.Repeat("b", 64) }, func(r *pb.Rule) { r.IngressNodeId = 4 }, func(r *pb.Rule) { r.Targets = []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1))} }} {
		bad := proto.Clone(rule).(*pb.Rule)
		change(bad)
		if _, err = dialTunnel(ctx, bad, bad.Targets[0]); err == nil {
			t.Fatal("unauthorized tunnel request accepted")
		}
	}
	config.EgressRules = nil
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	if _, err = dialTunnel(ctx, rule, rule.Targets[0]); err == nil {
		t.Fatal("removed rule still available")
	}
}
