package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestExistingPlanEntitlementsSurvivePersonalResourceMigration(t *testing.T) {
	dsn := os.Getenv("NEKOPASS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated test database")
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil || !strings.HasSuffix(config.ConnConfig.Database, "_test") {
		t.Fatal("requires isolated *_test database")
	}
	ctx := context.Background()
	pool, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	conn, e := pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Release()
	name := pgx.Identifier{fmt.Sprintf("snapshot_migration_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, e = conn.Exec(ctx, "CREATE SCHEMA "+name); e != nil {
		t.Fatal(e)
	}
	defer func() { conn.Exec(ctx, "SET search_path TO public"); conn.Exec(ctx, "DROP SCHEMA "+name+" CASCADE") }()
	if _, e = conn.Exec(ctx, "SET search_path TO "+name); e != nil {
		t.Fatal(e)
	}
	for _, migration := range []string{schema, migration002, migration003, migration004, migration005, migration006, migration007, migration008, migration009, migration010, migration011, migration012, migration013, migration014} {
		if _, e = conn.Exec(ctx, migration); e != nil {
			t.Fatal(e)
		}
	}
	var plan, user, node, group int64
	if e = conn.QueryRow(ctx, "INSERT INTO plans(name,speed_bps,quota_bytes,max_rules,max_connections,ip_limit,rule_speed_bps,rule_ip_limit,rule_connection_limit,duration_days) VALUES('fixture-plan',1250000,123456789,20,30,4,250000,2,5,30) RETURNING id").Scan(&plan); e != nil {
		t.Fatal(e)
	}
	if e = conn.QueryRow(ctx, "INSERT INTO users(username,password_hash,plan_id,plan_started_at,quota_epoch) VALUES('fixture-user','fixture-unused',$1,now()-interval '2 days',7) RETURNING id", plan).Scan(&user); e != nil {
		t.Fatal(e)
	}
	conn.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES('fixture-node','fixture-hash') RETURNING id").Scan(&node)
	conn.QueryRow(ctx, "INSERT INTO node_groups(name) VALUES('fixture-group') RETURNING id").Scan(&group)
	for _, query := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO node_group_members(group_id,node_id) VALUES($1,$2)", []any{group, node}},
		{"INSERT INTO plan_node_groups(plan_id,group_id) VALUES($1,$2)", []any{plan, group}},
		{"INSERT INTO grants(node_id,user_id,quota_epoch,issued,spent,traffic) VALUES($1,$2,7,1000,100,90)", []any{node, user}},
	} {
		if _, e = conn.Exec(ctx, query.sql, query.args...); e != nil {
			t.Fatal(e)
		}
	}
	var expires time.Time
	conn.QueryRow(ctx, "SELECT expires_at FROM user_entitlements WHERE id=$1", user).Scan(&expires)
	if _, e = conn.Exec(ctx, migration015); e != nil {
		t.Fatal(e)
	}
	var quota, speed, epoch, traffic, baseline int64
	var limits []int
	var after time.Time
	if e = conn.QueryRow(ctx, "SELECT quota_bytes,speed_bps,quota_epoch,traffic_base_bytes,expires_at,ARRAY[max_rules,max_connections::integer,ip_limit,rule_ip_limit,rule_connection_limit] FROM user_entitlements WHERE id=$1", user).Scan(&quota, &speed, &epoch, &baseline, &after, &limits); e != nil || quota != 123456789 || speed != 1250000 || epoch != 7 || baseline != 0 || !expires.Equal(after) || fmt.Sprint(limits) != "[20 30 4 2 5]" {
		t.Fatal("migration altered active personal resources", e)
	}
	if e = conn.QueryRow(ctx, "SELECT traffic FROM current_grants WHERE node_id=$1 AND user_id=$2", node, user).Scan(&traffic); e != nil || traffic != 90 {
		t.Fatal("migration reset active usage", e)
	}
	if _, e = conn.Exec(ctx, "UPDATE plans SET speed_bps=0,quota_bytes=0 WHERE id=$1", plan); e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, "DELETE FROM plan_node_groups WHERE plan_id=$1", plan); e != nil {
		t.Fatal(e)
	}
	var authorized bool
	if e = conn.QueryRow(ctx, "SELECT quota_bytes,speed_bps,EXISTS(SELECT 1 FROM user_nodes WHERE user_id=$1 AND node_id=$2) FROM user_entitlements WHERE id=$1", user, node).Scan(&quota, &speed, &authorized); e != nil || quota != 123456789 || speed != 1250000 || !authorized {
		t.Fatal("later plan edit changed migrated user", e)
	}
}
