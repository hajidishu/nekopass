package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestEachSelectedExitOwnsItsTLSConnectionOptions(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	create := func(cfg TunnelTLSConfig) int64 {
		t.Helper()
		data, _ := json.Marshal(cfg)
		var id int64
		if err := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,tls_config,tls_ca,tls_private_key) VALUES($1,$2,$3,'fixture-public-trust','fixture-private-key-not-forwarded') RETURNING id", Secret(), Secret(), data).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
		return id
	}
	entryConfig := DefaultTunnelTLS()
	entryConfig.Fingerprint = "chrome"
	entryConfig.ClientSNI = "entry.example.test"
	entryConfig.PoolSize = 1
	entry := create(entryConfig)
	one := DefaultTunnelTLS()
	one.ServerName = "one.example.test"
	one.ClientSNI = "override.one.example.test"
	one.Fingerprint = "firefox"
	one.PoolSize = 3
	one.StreamWindowMiB = 8
	one.ConnectionWindowMiB = 64
	one.Host = "one.example.test"
	one.Path = "/one"
	one.DNSCredentials = map[string]string{"api_token": "fixture-dns-secret-not-forwarded"}
	two := DefaultTunnelTLS()
	two.ServerName = "two.example.test"
	two.Fingerprint = "off"
	two.PoolSize = 6
	two.StreamWindowMiB = 32
	two.ConnectionWindowMiB = 128
	two.Path = "/two"
	first, second := create(one), create(two)
	out := &pb.ControlMessage{Node: &pb.NodeConfig{}, Rules: []*pb.Rule{{Id: 1, EgressNodeId: first, TunnelProtocol: "tls_h2"}, {Id: 2, EgressNodeId: second, TunnelProtocol: "tls_h2"}, {Id: 3, EgressNodeId: first, TunnelProtocol: "plain_tcp"}}}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := appendTLSControl(ctx, tx, entry, out); err != nil {
		t.Fatal(err)
	}
	a, b := out.Rules[0].Tls, out.Rules[1].Tls
	if a == nil || a.ServerName != one.ClientSNI || a.Fingerprint != one.Fingerprint || a.PoolSize != 3 || a.StreamWindowMib != 8 || a.ConnectionWindowMib != 64 || a.Path != "/one" {
		t.Fatal("first exit options not applied")
	}
	if b == nil || b.ServerName != two.ServerName || b.Fingerprint != "off" || b.PoolSize != 6 || b.StreamWindowMib != 32 || b.ConnectionWindowMib != 128 || b.Path != "/two" {
		t.Fatal("second exit reused ingress or another exit options")
	}
	if out.Rules[2].Tls != nil {
		t.Fatal("plaintext forwarding received TLS parameters")
	}
	for _, r := range out.Rules {
		data, _ := protojson.Marshal(r)
		if strings.Contains(string(data), "fixture-private-key-not-forwarded") || strings.Contains(string(data), "fixture-dns-secret-not-forwarded") {
			t.Fatal("exit secret leaked in ingress policy")
		}
	}
}
