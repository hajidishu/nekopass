package control

import (
	"context"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

func TestEncryptedWireCapabilityNeverDowngrades(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "plain_h2", "plain_udp", "tls_tcp", "tls_h2", "tls_h3", "dtls_udp", "random_tcp", "random_h2", "random_udp"} {
		for _, mux := range []bool{false, true} {
			for _, pad := range []bool{false, true} {
				r := &pb.Rule{TunnelProtocol: mode, Tls: &pb.TLSClientConfig{PaddingEnabled: pad}, Mux: &pb.MuxConfig{Enabled: mux}}
				requires := mode == "dtls_udp" || mode == "random_tcp" || mode == "random_h2" || mode == "random_udp" || mode == "tls_tcp" && pad && mux
				for _, v := range [][2]int32{{34, 34}, {35, 34}, {34, 35}, {35, 35}} {
					want := !requires || v == [2]int32{35, 35}
					if got := encryptedRuleSupported(r, v[0], v[1]); got != want {
						t.Fatal(mode, mux, pad, v, got, want)
					}
				}
			}
		}
	}
}

func TestDTLSOpaqueEnvelopeKeyIsStableAndOnlySentWhereUsed(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var exit int64
	if err = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,tunnel_protocol) VALUES($1,$2,'dtls_udp') RETURNING id", Secret(), Hash(Secret())).Scan(&exit); err != nil {
		t.Fatal(err)
	}
	out := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: "dtls_udp"}, Rules: []*pb.Rule{{EgressNodeId: exit, TunnelProtocol: "dtls_udp"}, {EgressNodeId: exit, TunnelProtocol: "plain_udp"}}}
	if err = appendRandomControl(ctx, tx, exit, out); err != nil {
		t.Fatal(err)
	}
	key := out.Node.Random.GetKey()
	if _, err = tunnelcrypto.DecodeKey(key); err != nil {
		t.Fatal("DTLS key not generated", err)
	}
	if out.Rules[0].Random.GetKey() != key || out.Rules[1].Random != nil {
		t.Fatal("envelope key sent to wrong transport")
	}
	if err = appendRandomControl(ctx, tx, exit, out); err != nil || out.Node.Random.GetKey() != key {
		t.Fatal("configuration refresh rotated envelope key", err)
	}
	group := &pb.Rule{Id: 1, EgressGroupId: 1, Enabled: true}
	peer := out.Rules[0]
	peer.Enabled = true
	grouped := &pb.ControlMessage{Rules: []*pb.Rule{group, peer}}
	finishGroupDrafts(grouped, []groupRuleDraft{{rule: group, peer: peer, weight: 1}}, pb.CurrentVersion, 1)
	if len(group.EgressPeers) != 1 || group.EgressPeers[0].Random.GetKey() != key {
		t.Fatal("group candidate lost DTLS envelope key")
	}
	var pending int64
	if err = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,tunnel_protocol) VALUES($1,$2,'dtls_udp') RETURNING id", Secret(), Hash(Secret())).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	waiting := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: "plain_tcp"}, Rules: []*pb.Rule{{Enabled: true, EgressNodeId: pending, TunnelProtocol: "dtls_udp"}}}
	if err = appendRandomControl(ctx, tx, exit, waiting); err != nil || waiting.Rules[0].Enabled || waiting.Rules[0].Random != nil {
		t.Fatal("missing peer key did not fail closed", err)
	}
	var peerKey string
	if err = tx.QueryRow(ctx, "SELECT COALESCE(random_config->>'key','') FROM nodes WHERE id=$1", pending).Scan(&peerKey); err != nil || peerKey != "" {
		t.Fatal("ingress pull initialized another node", err)
	}
}
