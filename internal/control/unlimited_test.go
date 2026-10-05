package control

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"testing"
)

func TestUnlimitedPersonalResourcesAndLateReports(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	group := testAuthorize(t, f.p, f.user, node)
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", node)
		f.p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", node)
		f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	})
	path := fmt.Sprintf("admin/users/%d", f.user)
	edit := func(changes map[string]any, code int) {
		t.Helper()
		body := map[string]any{"username": Secret(), "enabled": true, "plan_id": f.plan}
		for k, v := range changes {
			body[k] = v
		}
		securityStatus(t, f.request(f.admin, path, "PUT", body), code)
	}
	edit(map[string]any{"quota_bytes": -1, "speed_mbps": 0, "max_connections": 0, "max_rules": 0, "expires_at": ""}, 200)
	for range 3 {
		securityStatus(t, f.request(f.admin, path+"/rules", "POST", RuleInput{NodeID: node, Targets: []string{"127.0.0.1:80"}, Enabled: true}), 200)
	}
	stream := &StreamServer{Server: f.s}
	report := &pb.AgentMessage{ProtocolVersion: 10, InstanceId: Secret(), RequestUsers: []int64{f.user}}
	out, err := stream.exchange(ctx, f.p, node, report)
	if err != nil || len(out.Users) != 1 || !out.Users[0].QuotaUnlimited || out.Users[0].Issued != 0 || out.Users[0].SpeedBps != 0 || out.Users[0].MaxConnections != 0 || out.Users[0].ExpiresUnix != 0 {
		t.Fatal("bad unlimited policy", err)
	}
	epoch := out.Users[0].QuotaEpoch
	usage := &pb.Usage{UserId: f.user, QuotaEpoch: epoch, UnlimitedSpent: 16 << 20, Traffic: 1234, QuotaUnlimited: true}
	report.Usage = []*pb.Usage{usage}
	report.RequestUsers = nil
	for range 3 {
		if _, err = stream.exchange(ctx, f.p, node, report); err != nil {
			t.Fatal(err)
		}
	}
	var events int64
	f.p.QueryRow(ctx, "SELECT sum(traffic_bytes)::bigint FROM usage_events WHERE user_id=$1", f.user).Scan(&events)
	if events != 1234 {
		t.Fatal("unlimited usage replay double-counted")
	}
	// Editing plan defaults must leave the user's unlimited entitlement intact.
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/plans/%d", f.plan), "PUT", PlanInput{Name: Secret(), Enabled: true, SpeedMbps: 1, QuotaBytes: 17 << 20, MaxRules: 1, MaxConnections: 2, NodeGroupIDs: []int64{group}}), 200)
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || !out.Users[0].QuotaUnlimited {
		t.Fatal("plan edit changed personal limits", err)
	}
	edit(map[string]any{"quota_bytes": 17 << 20, "speed_mbps": 1, "max_connections": 2}, 200)
	usage.UnlimitedSpent = 32 << 20
	usage.Traffic++
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || out.Users[0].QuotaUnlimited || !out.Users[0].Enabled || out.Users[0].QuotaEpoch == epoch {
		t.Fatal("finite transition failed", err)
	}
	usage.QuotaUnlimited = false
	if _, err = stream.exchange(ctx, f.p, node, report); err != nil {
		t.Fatal(err)
	}
	usage.UnlimitedSpent++
	if _, err = stream.exchange(ctx, f.p, node, report); err == nil {
		t.Fatal("debit accepted after old unlimited authorization closed")
	}
	usage.UnlimitedSpent--
	report.RequestUsers = []int64{f.user}
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || out.Users[0].Issued != (17<<20)-1234 {
		t.Fatal("finite budget ignored edited baseline", err)
	}
	var users []struct {
		Traffic int64 `json:"traffic_bytes"`
	}
	response := f.request(f.user, "profile", "GET", nil)
	securityStatus(t, response, 200)
	if json.Unmarshal(response.Body.Bytes(), &users) != nil || len(users) != 1 || users[0].Traffic != 1234 {
		t.Fatal("late old-epoch usage replaced current edited usage")
	}
	edit(map[string]any{"max_rules": 1}, 409)
	edit(map[string]any{"speed_mbps": -1}, 400)
	edit(map[string]any{"quota_bytes": -2}, 400)
	edit(map[string]any{"quota_bytes": 0}, 200)
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || out.Users[0].Enabled || out.Users[0].QuotaUnlimited || out.Users[0].Issued != 0 {
		t.Fatal("zero quota was treated as unlimited", err)
	}
}
