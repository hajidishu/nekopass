package store

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTelegramEnableMigrationPreservesExistingBotState(t *testing.T) {
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
	name := pgx.Identifier{fmt.Sprintf("telegram_migration_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { conn.Exec(ctx, "SET search_path TO public"); conn.Exec(ctx, "DROP SCHEMA "+name+" CASCADE") }()
	if _, err = conn.Exec(ctx, "SET search_path TO "+name); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `CREATE TABLE schema_version(version integer PRIMARY KEY);
 CREATE TABLE site_settings(id integer PRIMARY KEY,config jsonb NOT NULL);
 INSERT INTO schema_version VALUES(23);
 INSERT INTO site_settings VALUES(1,'{"telegram":{"token":"fixture-token"}}'),(2,'{"telegram":{"token":""}}'),(3,'{"telegram":{"token":"fixture-token","enabled":false}}'),(4,'{}');`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, migration024); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int]string{1: "true", 2: "false", 3: "false", 4: "missing"} {
		var state string
		var generation int64
		if err = conn.QueryRow(ctx, "SELECT COALESCE(config#>>'{telegram,enabled}','missing'),telegram_generation FROM site_settings WHERE id=$1", id).Scan(&state, &generation); err != nil || state != want || generation != 0 {
			t.Fatal("incorrect migration", id, state, generation, err)
		}
	}
}
