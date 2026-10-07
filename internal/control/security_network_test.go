package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nekopass/nekopass/internal/networkpolicy"
	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestAdministratorNetworkSettingsCannotBeOverriddenByTenant(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	settings := defaultSettings()
	settings.ProxyTrustedCIDRs = []string{"192.0.2.10/32"}
	securityStatus(t, f.request(f.user, "admin/settings", "PUT", settings), 403)
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 200)
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", node)
		f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	})
	testAuthorize(t, f.p, f.user, node)
	input := RuleInput{NodeID: node, Targets: []string{"8.8.8.8:443"}, ProxyAccept: "auto", ProxyTrustedCIDRs: []string{"0.0.0.0/0", "::/0"}, Enabled: true}
	securityStatus(t, f.request(f.user, "rules", "POST", input), 200)
	var trusted []byte
	if err := f.p.QueryRow(ctx, "SELECT proxy_trusted_cidrs FROM rules WHERE node_id=$1", node).Scan(&trusted); err != nil {
		t.Fatal(err)
	}
	var values []string
	json.Unmarshal(trusted, &values)
	if len(values) != 1 || values[0] != "192.0.2.10/32" {
		t.Fatal("tenant changed trust boundary", values)
	}
	stream := &StreamServer{Server: f.s}
	report := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 14}
	out, err := stream.exchange(ctx, f.p, node, report)
	if err != nil || !out.Node.SecurityConfigured || !out.Node.Enabled || len(out.Node.TargetDenyCidrs) != len(networkpolicy.Defaults()) || len(out.Rules) != 1 || !out.Rules[0].Enabled {
		t.Fatal("security policy not delivered", err)
	}
	input.ProxyAccept = "off"
	for _, address := range []string{"127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80", "[::ffff:127.0.0.1]:80", "[fd00::1]:80"} {
		input.Targets = []string{address}
		securityStatus(t, f.request(f.user, "rules", "POST", input), 400)
	}
	report.ProtocolVersion = 13
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || out.Node.Enabled || out.Rules[0].Enabled {
		t.Fatal("old agent bypassed required ACL", err)
	}
	settings.TargetDenyCIDRs = []string{}
	settings.ProxyTrustedCIDRs = []string{}
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", settings), 200)
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || !out.Node.Enabled || out.Rules[0].Enabled || len(out.Rules[0].ProxyTrustedCidrs) != 0 {
		t.Fatal("admin override/trust removal ignored", err)
	}
	input.Targets = []string{"127.0.0.1:80"}
	securityStatus(t, f.request(f.user, "rules", "POST", input), 200)
}
