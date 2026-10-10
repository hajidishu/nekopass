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

func TestCombinedRuleMigrationPreservesConfigurationAndUsage(t *testing.T) {
	dsn := os.Getenv("NEKOPASS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires isolated *_test database")
	}
	ctx := context.Background()
	pool, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	name := pgx.Identifier{fmt.Sprintf("rule_split_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { conn.Exec(ctx, "SET search_path TO public"); conn.Exec(ctx, "DROP SCHEMA "+name+" CASCADE") }()
	if _, err = conn.Exec(ctx, "SET search_path TO "+name); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{schema, migration002, migration003, migration004, migration005, migration006, migration007, migration008, migration009, migration010, migration011, migration012, migration013, migration014, migration015, migration016, migration017, migration018, migration019, migration020, migration021} {
		if _, err = conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	var user, node, exit, group, original int64
	for _, item := range []struct {
		sql  string
		dest *int64
	}{
		{"INSERT INTO users(username,password_hash,max_rules,quota_epoch,traffic_base_bytes) VALUES('fixture-user','fixture-unused',1,7,100) RETURNING id", &user},
		{"INSERT INTO nodes(name,token_hash) VALUES('fixture-entry','fixture-entry-token') RETURNING id", &node},
		{"INSERT INTO nodes(name,token_hash) VALUES('fixture-exit','fixture-exit-token') RETURNING id", &exit},
	} {
		if err = conn.QueryRow(ctx, item.sql).Scan(item.dest); err != nil {
			t.Fatal(err)
		}
	}
	if err = conn.QueryRow(ctx, "INSERT INTO rule_groups(user_id,name) VALUES($1,'fixture-group') RETURNING id", user).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "INSERT INTO wallet_accounts(user_id,balance_cents) VALUES($1,12345)", user); err != nil {
		t.Fatal(err)
	}
	if err = conn.QueryRow(ctx, `INSERT INTO rules(user_id,node_id,egress_node_id,group_id,listen_host,listen_port,target_host,target_port,name,targets,balance,enabled,traffic_baseline,protocol) VALUES($1,$2,$3,$4,'127.0.0.1',24001,'8.8.8.8',53,'fixture-combined','["8.8.8.8:53","1.1.1.1:53"]','round_robin',false,20,'tcp_udp') RETURNING id`, user, node, exit, group).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "INSERT INTO rule_usage(node_id,rule_id,user_id,traffic) VALUES($1,$2,$3,123)", node, original, user); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "INSERT INTO grants(node_id,user_id,quota_epoch,issued,spent,traffic) VALUES($1,$2,7,1000,77,77)", node, user); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, migration022); err != nil {
		t.Fatal(err)
	}
	var total, ports, version int
	var epoch, base, balance, traffic int64
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM rules").Scan(&total); err != nil || total != 2 {
		t.Fatal("combined rule not split", err, total)
	}
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM rule_ports WHERE node_id=$1 AND listen_port=24001", node).Scan(&ports); err != nil || ports != 2 {
		t.Fatal("same-port reservations not preserved", err, ports)
	}
	if err = conn.QueryRow(ctx, "SELECT max(version) FROM schema_version").Scan(&version); err != nil || version != CurrentSchemaVersion {
		t.Fatal(err, version)
	}
	if err = conn.QueryRow(ctx, "SELECT quota_epoch,traffic_base_bytes,(SELECT balance_cents FROM wallet_accounts WHERE user_id=$1) FROM users WHERE id=$1", user).Scan(&epoch, &base, &balance); err != nil || epoch != 7 || base != 100 || balance != 12345 {
		t.Fatal("user accounting changed", err)
	}
	if err = conn.QueryRow(ctx, "SELECT traffic FROM grants WHERE node_id=$1 AND user_id=$2", node, user).Scan(&traffic); err != nil || traffic != 77 {
		t.Fatal("grant accounting reset", err)
	}
	for _, protocol := range []string{"tcp", "udp"} {
		var id, baseline, used int64
		var correct bool
		if err = conn.QueryRow(ctx, `SELECT r.id,r.traffic_baseline,COALESCE(ru.traffic,0),r.user_id=$1 AND r.node_id=$2 AND r.egress_node_id=$3 AND r.group_id=$4 AND r.listen_host='127.0.0.1' AND r.listen_port=24001 AND r.targets='["8.8.8.8:53","1.1.1.1:53"]'::jsonb AND r.balance='round_robin' AND NOT r.enabled AND r.name='fixture-combined' AND r.proxy_accept='off' AND r.proxy_send='off' FROM rules r LEFT JOIN rule_usage ru ON ru.rule_id=r.id AND ru.node_id=r.node_id WHERE r.protocol=$5`, user, node, exit, group, protocol).Scan(&id, &baseline, &used, &correct); err != nil || !correct {
			t.Fatal("split lost configuration", err, protocol)
		}
		if protocol == "tcp" && (id != original || baseline != 20 || used != 123) {
			t.Fatal("historical usage lost or reassigned")
		}
		if protocol == "udp" && (id == original || baseline != 0 || used != 0) {
			t.Fatal("UDP duplicated historical usage")
		}
	}
	if _, err = conn.Exec(ctx, "UPDATE rules SET protocol='tcp_udp' WHERE id=$1", original); err == nil {
		t.Fatal("database still permits combined rules")
	}
}
