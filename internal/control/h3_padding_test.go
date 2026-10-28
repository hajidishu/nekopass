package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestH3PaddingConfigurationDistributionAndOldAgentGate(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var entry, exit int64
	for _, id := range []*int64{&entry, &exit} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,protocol_version) VALUES($1,$2,29) RETURNING id", Secret(), Hash(Secret())).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, id := range []int64{entry, exit} {
			for _, q := range []string{"DELETE FROM grants WHERE node_id=$1", "DELETE FROM rule_usage WHERE node_id=$1", "DELETE FROM rules WHERE node_id=$1 OR egress_node_id=$1", "DELETE FROM nodes WHERE id=$1"} {
				f.p.Exec(ctx, q, id)
			}
		}
	})
	for _, id := range []int64{entry, exit} {
		testAuthorize(t, f.p, f.user, id)
	}
	base := fmt.Sprintf("admin/nodes/%d/protocols", exit)
	w := f.request(f.admin, base, "GET", nil)
	securityStatus(t, w, 200)
	var details struct {
		Config NodeProtocolsInput `json:"config"`
	}
	json.Unmarshal(w.Body.Bytes(), &details)
	cfg := details.Config
	cfg.TunnelTransport = "h3"
	cfg.TunnelSecurity = "tls"
	cfg.TunnelProtocol = "tls_h3"
	cfg.TunnelExitEnabled = true
	cfg.TunnelListenPort = 27443
	cfg.TunnelPublicHost = "exit.example.test"
	cfg.AllowedIngressIDs = []int64{entry}
	cfg.TLS.ServerName = "exit.example.test"
	cfg.TLS.QUICPadding.Enabled = true
	cfg.TLS.QUICPadding.MaxPadding = 320
	securityStatus(t, f.request(f.user, base, "PUT", cfg), 403)
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 200)
	loaded, _, err := loadNodeInput(ctx, f.p, exit)
	if err != nil || !loaded.TLS.QUICPadding.Enabled || loaded.TLS.QUICPadding.MaxPadding != 320 {
		t.Fatal("QUIC padding not saved", err)
	}
	cfg.TLS.QUICPadding.MaxPadding = -1
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 400)
	cfg.TLS.QUICPadding.MaxPadding = 320
	w = f.request(f.user, "rules", "POST", RuleInput{NodeID: entry, EgressNodeID: exit, Protocol: "tcp", Targets: []string{"127.0.0.1:8080"}, Enabled: true})
	securityStatus(t, w, 200)
	stream := &StreamServer{Server: f.s}
	instance := Secret()
	for _, version := range []int32{28, 29, 30} {
		out, err := stream.exchange(ctx, f.p, entry, &pb.AgentMessage{ProtocolVersion: version, InstanceId: instance})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Rules) != 1 || out.Rules[0].Enabled != (version >= 29) || !out.Rules[0].Tls.GetQuicPadding().GetEnabled() || out.Rules[0].Tls.QuicPadding.MaxPadding != 320 {
			t.Fatal("ingress capability gate or padding policy missing")
		}
	}
	exitInstance := Secret()
	for _, version := range []int32{28, 29, 30} {
		out, err := stream.exchange(ctx, f.p, exit, &pb.AgentMessage{ProtocolVersion: version, InstanceId: exitInstance})
		if err != nil {
			t.Fatal(err)
		}
		if out.Node.TunnelExitEnabled != (version >= 29) || !out.Node.Tls.GetQuicPadding().GetEnabled() {
			t.Fatal("old exit accepted incompatible framing")
		}
	}
	// Preserve the optional settings when changing mode, but do not activate them.
	cfg.TunnelTransport = "h2"
	cfg.TunnelProtocol = "tls_h2"
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 200)
	out, err := stream.exchange(ctx, f.p, entry, &pb.AgentMessage{ProtocolVersion: 29, InstanceId: instance})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Tls.GetQuicPadding().GetEnabled() {
		t.Fatal("padding activated for h2")
	}
	loaded, _, err = loadNodeInput(ctx, f.p, exit)
	if err != nil || !loaded.TLS.QUICPadding.Enabled {
		t.Fatal("hidden settings were erased", err)
	}
}
