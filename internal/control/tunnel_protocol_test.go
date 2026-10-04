package control

import (
	"context"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"strings"
	"testing"
)

func TestOldAgentKeepsDirectRulesButCannotServeTunnel(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	var node int64
	if e := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	s := &StreamServer{Server: New(p)}
	report := &pb.AgentMessage{ProtocolVersion: 5, InstanceId: Secret()}
	if _, e := s.exchange(ctx, p, node, report); e != nil {
		t.Fatal("direct-only Agent lost compatibility", e)
	}
	if _, e := p.Exec(ctx, "UPDATE nodes SET tunnel_exit_enabled=true,tunnel_listen_port=31000,tunnel_public_host='127.0.0.1' WHERE id=$1", node); e != nil {
		t.Fatal(e)
	}
	if _, e := s.exchange(ctx, p, node, report); e == nil || !strings.Contains(e.Error(), "protocol v6") {
		t.Fatal("old Agent accepted exit configuration", e)
	}
}
