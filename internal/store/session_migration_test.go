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

func TestLongSessionMigrationKeepsValidLoginsAndDoesNotReviveExpiredOnes(t *testing.T) {
	dsn := os.Getenv("NEKOPASS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires *_test database")
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
	name := pgx.Identifier{fmt.Sprintf("session_migration_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { conn.Exec(ctx, "SET search_path TO public"); conn.Exec(ctx, "DROP SCHEMA "+name+" CASCADE") }()
	if _, err = conn.Exec(ctx, "SET search_path TO "+name); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `CREATE TABLE schema_version(version integer PRIMARY KEY);
 CREATE TABLE sessions(token_hash text PRIMARY KEY,user_id bigint,expires_at timestamptz NOT NULL);
 INSERT INTO schema_version VALUES(19);
 INSERT INTO sessions VALUES('fixture-valid',1,now()+interval '1 hour'),('fixture-expired',1,now()-interval '1 hour');`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, migration020); err != nil {
		t.Fatal(err)
	}
	var validPermanent, expiredStillInvalid, renewalDue bool
	if err = conn.QueryRow(ctx, "SELECT expires_at IS NULL,cookie_renewed_at<=now()-interval '24 hours' FROM sessions WHERE token_hash='fixture-valid'").Scan(&validPermanent, &renewalDue); err != nil || !validPermanent || !renewalDue {
		t.Fatal("valid old session not migrated or first cookie renewal delayed", err)
	}
	if err = conn.QueryRow(ctx, "SELECT expires_at IS NOT NULL AND expires_at<=now() FROM sessions WHERE token_hash='fixture-expired'").Scan(&expiredStillInvalid); err != nil || !expiredStillInvalid {
		t.Fatal("expired session revived", err)
	}
}
