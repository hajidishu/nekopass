package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestBrutalNodeSettingsValidationAndPreservation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var id int64
	key := Secret()
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
	path := fmt.Sprintf("admin/nodes/%d", id)
	v, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	if *v.BandwidthUpMbps != 0 || *v.BandwidthDownMbps != 0 || *v.BrutalEnabled {
		t.Fatal("old node default changed")
	}
	up, down, on := int64(200), int64(1000), true
	v.NodeBandwidth = NodeBandwidth{BandwidthUpMbps: &up, BandwidthDownMbps: &down, BrutalEnabled: &on}
	v.TunnelTransport = "raw_udp"
	v.TunnelSecurity = "none"
	securityStatus(t, f.request(f.user, path, "PUT", v), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", v), 200)
	check := func() {
		t.Helper()
		loaded, _, err := loadNodeInput(ctx, f.p, id)
		if err != nil || *loaded.BandwidthUpMbps != up || *loaded.BandwidthDownMbps != down || !*loaded.BrutalEnabled {
			t.Fatal("node bandwidth changed", err)
		}
	}
	check()
	for _, value := range []int64{-1, 1000001} {
		bad := v
		bad.NodeBandwidth = NodeBandwidth{BandwidthUpMbps: &value, BandwidthDownMbps: &down, BrutalEnabled: &on}
		securityStatus(t, f.request(f.admin, path, "PUT", bad), 400)
		check()
	}
	zero := int64(0)
	bad := v
	bad.NodeBandwidth = NodeBandwidth{BandwidthUpMbps: &zero, BandwidthDownMbps: &down, BrutalEnabled: &on}
	securityStatus(t, f.request(f.admin, path, "PUT", bad), 400)
	check()
	// Omission by older clients preserves all three settings, in all save routes.
	data, _ := json.Marshal(v)
	var basic NodeBasicInput
	var protocols NodeProtocolsInput
	json.Unmarshal(data, &basic)
	json.Unmarshal(data, &protocols)
	v.NodeBandwidth = NodeBandwidth{}
	basic.NodeBandwidth = NodeBandwidth{}
	protocols.NodeBandwidth = NodeBandwidth{}
	for _, request := range []struct {
		path string
		body any
	}{{path, v}, {path + "/basic", basic}, {path + "/protocols", protocols}} {
		securityStatus(t, f.request(f.admin, request.path, "PUT", request.body), 200)
		check()
	}
	// Dormant settings survive switching to TCP, but do not turn TCP into Brutal.
	v.TunnelTransport = "raw_tcp"
	securityStatus(t, f.request(f.admin, path, "PUT", v), 200)
	check()
	got := f.request(f.admin, "admin/nodes", "GET", nil)
	securityStatus(t, got, 200)
	var nodes []map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range nodes {
		if n["id"] == float64(id) {
			found = n["bandwidth_up_mbps"] == float64(up) && n["bandwidth_down_mbps"] == float64(down) && n["brutal_enabled"] == true
		}
	}
	if !found {
		t.Fatal("administrator cannot read saved bandwidth")
	}
	off := false
	v.BrutalEnabled = &off
	securityStatus(t, f.request(f.admin, path, "PUT", v), 200)
	loaded, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil || *loaded.BrutalEnabled {
		t.Fatal("cannot turn off Brutal", err)
	}
}

func TestBrutalControlDirectionsCapabilitiesAndGroups(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var entry, exit int64
	for _, id := range []*int64{&entry, &exit} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,protocol_version) VALUES($1,$2,32) RETURNING id", Secret(), Hash(Secret())).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{entry, exit})
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET bandwidth_up_mbps=200,bandwidth_down_mbps=1000 WHERE id=$1", entry); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET bandwidth_up_mbps=300,bandwidth_down_mbps=500,brutal_enabled=true WHERE id=$1", exit); err != nil {
		t.Fatal(err)
	}
	apply := func(node int64, version int32, out *pb.ControlMessage) {
		t.Helper()
		tx, err := f.p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		out.Node.NodeId = node
		if err := appendBrutalControl(ctx, tx, version, out); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"tls_h3", "plain_udp", "dtls_udp", "random_udp"} {
		r := &pb.Rule{Enabled: true, EgressNodeId: exit, TunnelProtocol: mode}
		out := &pb.ControlMessage{Node: &pb.NodeConfig{}, Rules: []*pb.Rule{r}}
		apply(entry, 32, out)
		if !r.Enabled || r.Congestion.GetSendBps() != 25000000 || r.Congestion.GetReceiveBps() != 37500000 {
			t.Fatal("direction or Mbps conversion wrong", r.Congestion)
		}
		if out.Node.BandwidthUpBps != 25000000 || out.Node.BrutalEnabled {
			t.Fatal("ingress node capacity or feature scope wrong")
		}
		parent := &pb.Rule{EgressGroupId: 99, Enabled: true}
		draft := groupRuleDraft{rule: parent, peer: r, weight: 1}
		group := &pb.ControlMessage{Rules: []*pb.Rule{parent, r}}
		finishGroupDrafts(group, []groupRuleDraft{draft}, 32, 1)
		if len(parent.EgressPeers) != 1 || parent.EgressPeers[0].Congestion.GetSendBps() != 25000000 {
			t.Fatal("node group lost Brutal settings")
		}
		server := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: mode, TunnelExitEnabled: true}, TunnelLinks: []*pb.TunnelLink{{IngressNodeId: entry}}}
		apply(exit, 32, server)
		if !server.Node.BrutalEnabled || len(server.TunnelLinks) != 1 || server.TunnelLinks[0].Congestion.GetSendBps() != 37500000 || server.TunnelLinks[0].Congestion.GetReceiveBps() != 25000000 {
			t.Fatal("server direction negotiation wrong")
		}
		legacy := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: mode, TunnelExitEnabled: true}, TunnelLinks: []*pb.TunnelLink{{IngressNodeId: entry}}}
		apply(exit, 31, legacy)
		if legacy.Node.TunnelExitEnabled || len(legacy.TunnelLinks) != 0 {
			t.Fatal("legacy exit could bypass Brutal")
		}
		oldRule := &pb.Rule{Enabled: true, EgressNodeId: exit, TunnelProtocol: mode}
		apply(entry, 31, &pb.ControlMessage{Node: &pb.NodeConfig{}, Rules: []*pb.Rule{oldRule}})
		if oldRule.Enabled {
			t.Fatal("legacy ingress received incompatible rules")
		}
	}
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "random_h2"} {
		r := &pb.Rule{Enabled: true, EgressNodeId: exit, TunnelProtocol: mode}
		out := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: mode}, Rules: []*pb.Rule{r}}
		apply(entry, 32, out)
		if !r.Enabled || r.Congestion != nil || out.Node.BrutalEnabled {
			t.Fatal("TCP was modified")
		}
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET bandwidth_down_mbps=0 WHERE id=$1", entry); err != nil {
		t.Fatal(err)
	}
	r := &pb.Rule{Enabled: true, EgressNodeId: exit, TunnelProtocol: "plain_udp"}
	apply(entry, 32, &pb.ControlMessage{Node: &pb.NodeConfig{}, Rules: []*pb.Rule{r}})
	if r.Enabled {
		t.Fatal("missing receive capacity was ignored")
	}
}
