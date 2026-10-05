package control

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func testUser(t *testing.T, p *pgxpool.Pool, quota int64, limit int, isAdmin bool) (int64, int64) {
	t.Helper()
	ctx := context.Background()
	var plan, id int64
	if e := p.QueryRow(ctx, "INSERT INTO plans(name,speed_bps,quota_bytes,max_rules,max_connections) VALUES($1,62500000,$2,$3,1000) RETURNING id", Secret(), quota, limit).Scan(&plan); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(ctx, "INSERT INTO users(username,password_hash,plan_id,is_admin) VALUES($1,'unused',$2,$3) RETURNING id", Secret(), plan, isAdmin).Scan(&id); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		for _, q := range []string{"DELETE FROM wallet_entries WHERE user_id=$1 OR actor_id=$1", "DELETE FROM shop_orders WHERE user_id=$1 OR actor_id=$1", "DELETE FROM wallet_accounts WHERE user_id=$1"} {
			_, _ = p.Exec(ctx, q, id)
		}
		for _, q := range []string{"DELETE FROM rule_events WHERE user_id=$1", "DELETE FROM usage_events WHERE user_id=$1", "DELETE FROM grants WHERE user_id=$1", "DELETE FROM rule_usage WHERE user_id=$1", "DELETE FROM rules WHERE user_id=$1", "DELETE FROM rule_groups WHERE user_id=$1", "DELETE FROM sessions WHERE user_id=$1", "DELETE FROM users WHERE id=$1"} {
			_, _ = p.Exec(ctx, q, id)
		}
		_, _ = p.Exec(ctx, "DELETE FROM plans WHERE id=$1", plan)
	})
	return id, plan
}
func testAuthorize(t *testing.T, p *pgxpool.Pool, user, node int64) int64 {
	t.Helper()
	ctx := context.Background()
	var group, plan int64
	if e := p.QueryRow(ctx, "SELECT plan_id FROM users WHERE id=$1", user).Scan(&plan); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(ctx, "INSERT INTO node_groups(name) VALUES($1) RETURNING id", Secret()).Scan(&group); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, "INSERT INTO node_group_members(group_id,node_id) VALUES($1,$2)", group, node); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, "INSERT INTO plan_node_groups(plan_id,group_id) VALUES($1,$2)", plan, group); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, "INSERT INTO user_node_groups(user_id,group_id) VALUES($1,$2)", user, group); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, _ = p.Exec(ctx, "DELETE FROM plan_node_groups WHERE group_id=$1", group)
		_, _ = p.Exec(ctx, "DELETE FROM node_groups WHERE id=$1", group)
	})
	return group
}
