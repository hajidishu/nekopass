package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func TestMuxAdminSettingsAndPartialPreservation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var id int64
	key := Secret()
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
	node, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	if node.Mux == nil || node.Mux.Enabled || node.Mux.MaxStreams != 128 {
		t.Fatal("unsafe defaults", node.Mux)
	}
	node.Mux.Enabled = true
	node.Mux.MaxConnections = 3
	node.Mux.MaxStreams = 32
	path := fmt.Sprintf("admin/nodes/%d", id)
	securityStatus(t, f.request(f.user, path, "PUT", node), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", node), 200)
	loaded, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil || *loaded.Mux != *node.Mux {
		t.Fatal("Mux settings not saved", loaded.Mux, err)
	}
	body, _ := json.Marshal(loaded)
	var basic NodeBasicInput
	var protocols NodeProtocolsInput
	json.Unmarshal(body, &basic)
	json.Unmarshal(body, &protocols)
	loaded.Mux = nil
	protocols.Mux = nil
	for _, v := range []struct {
		path string
		body any
	}{{path, loaded}, {path + "/basic", basic}, {path + "/protocols", protocols}} {
		securityStatus(t, f.request(f.admin, v.path, "PUT", v.body), 200)
		current, _, err := loadNodeInput(ctx, f.p, id)
		if err != nil || *current.Mux != *node.Mux {
			t.Fatal("omitted field erased Mux", err)
		}
	}
	loaded.Mux = &tunnel.MuxConfig{Enabled: true, MaxStreams: 4097, IdleTimeoutSeconds: 60}
	securityStatus(t, f.request(f.admin, path, "PUT", loaded), 400)
	loaded.Mux = &tunnel.MuxConfig{Enabled: false, MaxStreams: 128, IdleTimeoutSeconds: 60}
	securityStatus(t, f.request(f.admin, path, "PUT", loaded), 200)
}

func TestMuxControlCapabilityAndGroupDrafts(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var ingress, exit int64
	for i, dst := range []*int64{&ingress, &exit} {
		key := Secret()
		if err = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token,protocol_version,mux_config) VALUES($1,$2,$3,$4,$5) RETURNING id", fmt.Sprint(Secret(), i), Hash(key), key, pb.CurrentVersion, []byte(`{"enabled":true,"max_connections":2,"max_streams":16,"idle_timeout_seconds":60}`)).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	out := &pb.ControlMessage{Node: &pb.NodeConfig{NodeId: ingress, TunnelProtocol: "plain_tcp", TunnelExitEnabled: true}, Rules: []*pb.Rule{{Id: 1, Enabled: true, EgressNodeId: exit, TunnelProtocol: "tls_tcp"}}}
	if err = appendMuxControl(ctx, tx, pb.CurrentVersion, out); err != nil || !out.Rules[0].Enabled || !out.Rules[0].Mux.GetEnabled() {
		t.Fatal("Mux was not delivered", err)
	}
	if err = appendMuxControl(ctx, tx, pb.MuxVersion-1, out); err != nil || out.Rules[0].Enabled || out.Node.TunnelExitEnabled {
		t.Fatal("old agent received enabled Mux", err)
	}
	out = &pb.ControlMessage{Node: &pb.NodeConfig{NodeId: ingress, TunnelProtocol: "plain_tcp"}, Rules: []*pb.Rule{{Id: 2, Enabled: true, EgressNodeId: exit, TunnelProtocol: "plain_udp"}}}
	if _, err = tx.Exec(ctx, "UPDATE nodes SET protocol_version=$2 WHERE id=$1", exit, pb.MuxVersion-1); err != nil {
		t.Fatal(err)
	}
	if err = appendMuxControl(ctx, tx, pb.CurrentVersion, out); err != nil || out.Rules[0].Enabled {
		t.Fatal("old exit accepted Mux", err)
	}
	parent := &pb.Rule{Id: 3, EgressGroupId: 1, Enabled: true}
	peer := &pb.Rule{Id: 3, Enabled: true, EgressNodeId: exit, Mux: &pb.MuxConfig{Enabled: true, MaxStreams: 16}}
	grouped := &pb.ControlMessage{Rules: []*pb.Rule{parent, peer}}
	finishGroupDrafts(grouped, []groupRuleDraft{{rule: parent, peer: peer, weight: 1}}, pb.CurrentVersion, 1)
	if len(parent.EgressPeers) != 1 || !parent.EgressPeers[0].Mux.GetEnabled() {
		t.Fatal("group lost Mux configuration")
	}
}
