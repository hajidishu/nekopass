package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nekopass/nekopass/internal/control"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/store"
	"google.golang.org/grpc"
)

func TestRebuiltMachineReconnectsUsingOriginalNodeKey(t *testing.T) {
	dsn := os.Getenv("NEKOPASS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("requires *_test database")
	}
	ctx := context.Background()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var node int64
	key := control.Secret()
	old := control.Secret()
	if err = pool.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token,instance_id) VALUES($1,$2,$3,$4) RETURNING id", control.Secret(), control.Hash(key), key, old).Scan(&node); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterControlServer(server, &control.StreamServer{Server: control.New(pool)})
	go server.Serve(ln)
	defer server.Stop()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	e, err := NewEngine(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, e, "http://"+ln.Addr().String(), key) }()
	defer func() { cancel(); <-done; e.Close() }()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var identity string
		pool.QueryRow(ctx, "SELECT instance_id FROM nodes WHERE id=$1", node).Scan(&identity)
		pending, _ := state.RestorePending()
		if identity == state.Instance && !pending {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("new machine failed to restore and rebind its original node")
}
