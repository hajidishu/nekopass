package control

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestPersonalResourcesAreScopedAndOldReportsCannotReplaceEditedUsage(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if e := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); e != nil {
		t.Fatal(e)
	}
	group := testAuthorize(t, f.p, f.user, node)
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", node)
		f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	})
	if _, e := f.p.Exec(ctx, "UPDATE users SET plan_id=$2 WHERE id=$1", f.other, f.plan); e != nil {
		t.Fatal(e)
	}
	stream := &StreamServer{Server: f.s}
	report := &pb.AgentMessage{ProtocolVersion: 10, InstanceId: Secret(), RequestUsers: []int64{f.user}}
	out, e := stream.exchange(ctx, f.p, node, report)
	if e != nil {
		t.Fatal(e)
	}
	old := &pb.Usage{UserId: f.user, Spent: 10, Traffic: 8, QuotaEpoch: 0}
	report.Usage = []*pb.Usage{old}
	report.RequestUsers = nil
	if _, e = stream.exchange(ctx, f.p, node, report); e != nil {
		t.Fatal(e)
	}
	path := fmt.Sprintf("admin/users/%d", f.user)
	change := map[string]any{"username": Secret(), "enabled": true, "plan_id": f.plan, "quota_bytes": 1000, "traffic_bytes": 200, "speed_mbps": 123, "max_connections": 5, "ip_limit": 2, "rule_speed_mbps": 8, "rule_ip_limit": 1, "rule_connection_limit": 4, "node_group_ids": []int64{group}, "expires_at": ""}
	securityStatus(t, f.request(f.user, path, "PUT", change), 403)
	securityStatus(t, f.request(f.user, "users/"+fmt.Sprint(f.user), "PUT", change), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", change), 200)
	old.Spent = 20
	old.Traffic = 15
	report.RequestUsers = []int64{f.user}
	out, e = stream.exchange(ctx, f.p, node, report)
	if e != nil {
		t.Fatal(e)
	}
	var own, other *pb.UserPolicy
	for _, p := range out.Users {
		if p.Id == f.user {
			own = p
		}
		if p.Id == f.other {
			other = p
		}
	}
	if own == nil || own.QuotaEpoch != 1 || own.Issued != 800 || own.SpeedBps != 123*125000 || own.IpLimit != 2 || own.MaxConnections != 5 || own.ExpiresUnix != 0 {
		t.Fatal("personal policy or remaining quota incorrect")
	}
	if other == nil || other.SpeedBps != 62500000 || other.MaxConnections != 1000 {
		t.Fatal("personal edit changed another user on the same plan")
	}
	profile := func() map[string]any {
		t.Helper()
		r := f.request(f.user, "profile", "GET", nil)
		securityStatus(t, r, 200)
		var rows []map[string]any
		if json.Unmarshal(r.Body.Bytes(), &rows) != nil || len(rows) != 1 {
			t.Fatal("invalid profile")
		}
		return rows[0]
	}
	if profile()["traffic_bytes"].(float64) != 200 {
		t.Fatal("old report overwrote administrator usage adjustment")
	}
	report.Usage = []*pb.Usage{{UserId: f.user, QuotaEpoch: 1, Spent: 100, Traffic: 90}}
	report.RequestUsers = nil
	if _, e = stream.exchange(ctx, f.p, node, report); e != nil {
		t.Fatal(e)
	}
	if profile()["traffic_bytes"].(float64) != 290 {
		t.Fatal("new usage did not accumulate from edited baseline")
	}
	// Neither metadata edits nor form retries may reset consumption.
	base := map[string]any{"username": Secret(), "enabled": true, "plan_id": f.plan, "speed_mbps": 50, "expected_resources_revision": profile()["resources_revision"]}
	securityStatus(t, f.request(f.admin, path, "PUT", base), 200)
	securityStatus(t, f.request(f.admin, path, "PUT", base), 409)
	if profile()["traffic_bytes"].(float64) != 290 || profile()["quota_epoch"].(float64) != 1 {
		t.Fatal("non-quota edit reset usage")
	}
	var events int64
	f.p.QueryRow(ctx, "SELECT sum(traffic_bytes)::bigint FROM usage_events WHERE user_id=$1", f.user).Scan(&events)
	if events != 105 {
		t.Fatal("manual usage edit corrupted actual historical events")
	}
	// Lowering quota below current usage exhausts it; blank/unlimited stays distinct.
	base["expected_resources_revision"] = profile()["resources_revision"]
	base["quota_bytes"] = 250
	securityStatus(t, f.request(f.admin, path, "PUT", base), 200)
	out, e = stream.exchange(ctx, f.p, node, report)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range out.Users {
		if p.Id == f.user && (p.Enabled || p.Issued != 0) {
			t.Fatal("exhausted quota still issued allowance")
		}
	}
	base["expected_resources_revision"] = profile()["resources_revision"]
	base["traffic_bytes"] = 0
	securityStatus(t, f.request(f.admin, path, "PUT", base), 200)
	report.RequestUsers = []int64{f.user}
	out, e = stream.exchange(ctx, f.p, node, report)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range out.Users {
		if p.Id == f.user && (!p.Enabled || p.Issued != 250) {
			t.Fatal("usage reset did not restore remaining quota")
		}
	}
	// Invalid edits are atomic and never change wallet balance or privilege.
	base["expected_resources_revision"] = profile()["resources_revision"]
	base["ip_limit"] = -1
	securityStatus(t, f.request(f.admin, path, "PUT", base), 400)
	delete(base, "ip_limit")
	base["is_admin"] = true
	securityStatus(t, f.request(f.admin, path, "PUT", base), 400)
	var logs int
	f.p.QueryRow(ctx, "SELECT count(*) FROM user_resource_changes WHERE user_id=$1 AND actor_id=$2", f.user, f.admin).Scan(&logs)
	if logs != 4 {
		t.Fatal("resource changes were not audited atomically", logs)
	}
}

func TestEditedUsageIsSubtractedFromConcurrentNodeAllocations(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var nodes [2]int64
	for i := range nodes {
		if e := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&nodes[i]); e != nil {
			t.Fatal(e)
		}
		id := nodes[i]
		t.Cleanup(func() {
			f.p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", id)
			f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
		})
	}
	group := testAuthorize(t, f.p, f.user, nodes[0])
	if _, e := f.p.Exec(ctx, "INSERT INTO node_group_members(group_id,node_id) VALUES($1,$2)", group, nodes[1]); e != nil {
		t.Fatal(e)
	}
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d", f.user), "PUT", map[string]any{"username": Secret(), "enabled": true, "plan_id": f.plan, "quota_bytes": 1000, "traffic_bytes": 900}), 200)
	stream := &StreamServer{Server: f.s}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, node := range nodes {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			_, e := stream.exchange(ctx, f.p, id, &pb.AgentMessage{ProtocolVersion: 10, InstanceId: Secret(), RequestUsers: []int64{f.user}})
			results <- e
		}(node)
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal(e)
		}
	}
	var issued int64
	if e := f.p.QueryRow(ctx, "SELECT sum(issued-released)::bigint FROM current_grants WHERE user_id=$1", f.user).Scan(&issued); e != nil || issued != 100 {
		t.Fatal("concurrent nodes exceeded the remaining personal quota", e, issued)
	}
}

func TestPlanDefaultsAndSamePlanRenewalPreservePersonalSettings(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	path := fmt.Sprintf("admin/users/%d", f.user)
	securityStatus(t, f.request(f.admin, path, "PUT", map[string]any{"username": Secret(), "enabled": true, "plan_id": f.plan, "speed_mbps": 12, "quota_bytes": 777, "traffic_bytes": 222, "max_rules": 30, "ip_limit": 3}), 200)
	defaults := PlanInput{Name: Secret(), Enabled: true, SpeedMbps: 99, QuotaBytes: 1024, MaxRules: 1, MaxConnections: 2, DurationDays: 5, Prices: map[string]*string{}}
	price := "1.00"
	defaults.Prices["annual"] = &price
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/plans/%d", f.plan), "PUT", defaults), 200)
	var quota, speed int64
	var ip, limit int
	if e := f.p.QueryRow(ctx, "SELECT quota_bytes,speed_bps,ip_limit,max_rules FROM user_entitlements WHERE id=$1", f.user).Scan(&quota, &speed, &ip, &limit); e != nil || quota != 777 || speed != 12*125000 || ip != 3 || limit != 30 {
		t.Fatal("plan defaults overwritten personal resources", e)
	}
	// New assignments get current defaults, existing assignments are immutable.
	if _, e := f.p.Exec(ctx, "UPDATE users SET plan_id=$2 WHERE id=$1", f.other, f.plan); e != nil {
		t.Fatal(e)
	}
	if e := f.p.QueryRow(ctx, "SELECT quota_bytes,speed_bps FROM users WHERE id=$1", f.other).Scan(&quota, &speed); e != nil || quota != 1024 || speed != 99*125000 {
		t.Fatal("new assignment missed defaults", e)
	}
	securityStatus(t, f.request(f.admin, path+"/recharge", "POST", map[string]any{"amount": "10.00", "request_key": Secret(), "note": "fixture-credit"}), 200)
	quote := f.request(f.user, "shop/quote", "POST", map[string]any{"plan_id": f.plan, "cycle": "annual"})
	securityStatus(t, quote, 200)
	var q struct {
		Epoch int64 `json:"epoch"`
		Price int64 `json:"amount_cents"`
	}
	json.Unmarshal(quote.Body.Bytes(), &q)
	purchase := map[string]any{"plan_id": f.plan, "cycle": "annual", "request_key": Secret(), "expected_price_cents": q.Price, "expected_epoch": q.Epoch}
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", purchase), 200)
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", purchase), 200)
	var baseline, balance int64
	if e := f.p.QueryRow(ctx, "SELECT quota_bytes,speed_bps,ip_limit,max_rules,traffic_base_bytes,(SELECT balance_cents FROM wallet_accounts WHERE user_id=$1) FROM users WHERE id=$1", f.user).Scan(&quota, &speed, &ip, &limit, &baseline, &balance); e != nil || quota != 777 || speed != 12*125000 || ip != 3 || limit != 30 || baseline != 0 || balance != 900 {
		t.Fatal("renewal changed personal limits, replayed debit or failed traffic reset", e)
	}
	// A monthly reset (including an admin-made permanent subscription) only clears usage.
	now := time.Now()
	anchor := now.AddDate(0, -2, 0)
	next := now.Add(-time.Minute)
	if _, e := f.p.Exec(ctx, "UPDATE users SET traffic_base_bytes=100,subscription_expires_at=NULL,reset_anchor_at=$2,next_reset_at=$3,reset_index=1 WHERE id=$1", f.user, anchor, next); e != nil {
		t.Fatal(e)
	}
	if e := f.s.resetDueSubscriptions(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e := f.p.QueryRow(ctx, "SELECT quota_bytes,traffic_base_bytes FROM users WHERE id=$1", f.user).Scan(&quota, &baseline); e != nil || quota != 777 || baseline != 0 {
		t.Fatal("monthly reset restored plan defaults or kept adjusted usage", e)
	}
}
