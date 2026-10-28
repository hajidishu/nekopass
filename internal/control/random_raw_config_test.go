package control

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestRandomRawKeepsUDPStreamOpenParameters(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	tls := DefaultTunnelTLS()
	tls.Path = "/custom/udp"
	tls.Host = "stream.example.test"
	tls.Fingerprint = "chrome"
	tls.PaddingEnabled = true
	data, _ := json.Marshal(tls)
	var id int64
	if err = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,tunnel_protocol,tls_config) VALUES($1,$2,'random_tcp',$3) RETURNING id", Secret(), Secret(), data).Scan(&id); err != nil {
		t.Fatal(err)
	}
	input := NodeInput{TunnelProtocol: "random_tcp"}
	if err = prepareNodeRandom(ctx, tx, id, &input); err != nil {
		t.Fatal(err)
	}
	out := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: "random_tcp"}, Rules: []*pb.Rule{{EgressNodeId: id, TunnelProtocol: "random_tcp", Protocol: "udp"}}}
	if err = appendTLSControl(ctx, tx, id, out); err != nil {
		t.Fatal(err)
	}
	if err = appendRandomControl(ctx, tx, id, out); err != nil {
		t.Fatal(err)
	}
	r := out.Rules[0]
	if r.Tls == nil || r.Tls.Path != tls.Path || r.Tls.Host != tls.Host || r.Tls.Fingerprint != "off" || r.Tls.PaddingEnabled || r.Random.GetKey() == "" {
		t.Fatal("raw UDP open parameters missing or TLS security active")
	}
}
