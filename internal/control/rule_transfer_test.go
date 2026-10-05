package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestImportedAutoProxyRuleIsAtomicScopedAndSafeForOlderAgents(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node, other int64
	for _, id := range []*int64{&node, &other} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
		value := *id
		t.Cleanup(func() {
			_, _ = f.p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", value)
			_, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", value)
		})
	}
	testAuthorize(t, f.p, f.user, node)
	rule := RuleInput{UserID: f.other, NodeID: node, Name: "imported", ListenPort: 29001, Targets: []string{"example.com:443", "[2001:db8::1]:443"}, ProxyAccept: "auto", ProxySend: "v2", ProxyTrustedCIDRs: []string{"192.0.2.0/24"}, Enabled: true}
	count := func() int {
		t.Helper()
		var count int
		if err := f.p.QueryRow(ctx, "SELECT count(*) FROM rules WHERE node_id=$1", node).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	post := func(actor int64, path string, values ...RuleInput) int {
		return f.request(actor, path, "POST", map[string]any{"rules": values}).Code
	}
	invalid := rule
	invalid.ProxyTrustedCIDRs = nil
	if post(f.user, "rules/import", rule, invalid) != 400 || count() != 0 {
		t.Fatal("invalid receiver partially saved a batch")
	}
	invalid = rule
	invalid.ListenPort++
	invalid.NodeID = other
	if post(f.user, "rules/import", rule, invalid) != 400 || count() != 0 {
		t.Fatal("unauthorized ingress partially saved a batch")
	}
	if post(f.user, "rules/import", rule, rule) != 400 || count() != 0 {
		t.Fatal("duplicate ports partially saved a batch")
	}
	if post(f.user, fmt.Sprintf("admin/users/%d/rules/import", f.other), rule) != 403 {
		t.Fatal("non-admin imported into another account")
	}
	if post(f.user, "rules/import", rule) != 200 || count() != 1 {
		t.Fatal("valid auto receiver was not saved")
	}
	var owner int64
	var accept, send string
	if err := f.p.QueryRow(ctx, "SELECT user_id,proxy_accept,proxy_send FROM rules WHERE node_id=$1", node).Scan(&owner, &accept, &send); err != nil || owner != f.user || accept != "auto" || send != "v2" {
		t.Fatal("import changed owner or Proxy Protocol configuration", err)
	}
	stream := &StreamServer{Server: f.s}
	report := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 9, UpdateSupported: true}
	out, err := stream.exchange(ctx, f.p, node, report)
	if err != nil || len(out.Rules) != 1 || out.Rules[0].Enabled {
		t.Fatal("old Agent cannot stay connected or auto receiver was downgraded", err)
	}
	response := f.request(f.user, "rules", "GET", nil)
	securityStatus(t, response, 200)
	var rules []struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &rules); err != nil || len(rules) != 1 || rules[0].Status != "upgrade_required" {
		t.Fatal("old Agent rule status does not explain required upgrade", err)
	}
	report.ProtocolVersion = 10
	out, err = stream.exchange(ctx, f.p, node, report)
	if err != nil || len(out.Rules) != 1 || !out.Rules[0].Enabled || out.Rules[0].ProxyAccept != "auto" || out.Rules[0].ProxySend != "v2" {
		t.Fatal("new Agent did not receive imported settings", err)
	}
}
