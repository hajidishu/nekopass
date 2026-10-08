package control

import (
	"context"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestRebuiltNodeRestoresHistoricalCountersWithoutReusingAllowance(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	uid, _ := testUser(t, p, 1000, 10, false)
	key := Secret()
	var node int64
	if err := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token,instance_id) VALUES($1,$2,$3,$4) RETURNING id", Secret(), Hash(key), key, Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	testAuthorize(t, p, uid, node)
	t.Cleanup(func() {
		p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", node)
		p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	})
	if _, err := p.Exec(ctx, "INSERT INTO grants(node_id,user_id,issued,spent,released,traffic,quota_epoch) VALUES($1,$2,600,200,50,150,0)", node, uid); err != nil {
		t.Fatal(err)
	}
	s := &StreamServer{Server: New(p)}
	request := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 15, RestoreState: true}
	if _, err := s.exchange(ctx, p, node, request); err == nil {
		t.Fatal("unauthenticated recovery accepted")
	}
	out, err := s.exchangeWithCredential(ctx, p, node, request, Hash(key))
	if err != nil {
		t.Fatal(err)
	}
	if out.StateRestore == nil || len(out.StateRestore.Users) != 1 {
		t.Fatal("usage baseline missing")
	}
	baseline := out.StateRestore.Users[0]
	if baseline.Spent != 550 || baseline.Released != 50 || baseline.Traffic != 150 || baseline.Issued != 600 {
		t.Fatal("lost allowance was reused or history lost", baseline)
	}
	if _, err = s.exchangeWithCredential(ctx, p, node, request, Hash(key)); err != nil {
		t.Fatal("retry after lost recovery response failed", err)
	}
	request.RestoreState = false
	request.Usage = []*pb.Usage{{UserId: uid, Spent: 550, Released: 50, Traffic: 150}}
	request.RequestUsers = []int64{uid}
	out, err = s.exchangeWithCredential(ctx, p, node, request, Hash(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Users) != 1 || out.Users[0].Issued != 1050 {
		t.Fatal("new authorization wrong", out.Users)
	} // 500 spent authorization plus 450 new bytes.
	rebuilt := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 15, RestoreState: true}
	out, err = s.exchangeWithCredential(ctx, p, node, rebuilt, Hash(key))
	if err != nil {
		t.Fatal(err)
	}
	if out.StateRestore.Users[0].Spent != 1000 || out.StateRestore.Users[0].Issued-out.StateRestore.Users[0].Spent-out.StateRestore.Users[0].Released != 0 {
		t.Fatal("repeat rebuilding refreshed finite quota")
	}
	bad := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 15, RestoreState: true, Usage: []*pb.Usage{{UserId: uid}}}
	if _, err = s.exchangeWithCredential(ctx, p, node, bad, Hash(key)); err == nil {
		t.Fatal("restore request erased existing reports")
	}
	if _, err = s.exchangeWithCredential(ctx, p, node, rebuilt, Hash(Secret())); err == nil {
		t.Fatal("wrong key recovered node")
	}
}
