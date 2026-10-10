package control

import (
	"context"
	"encoding/json"
	"testing"
)

func TestLegacyCombinedImportSplitsAtomically(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	testAuthorize(t, f.p, f.user, node)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	input := RuleInput{Protocol: "tcp_udp", UserID: f.other, NodeID: node, ListenPort: 24020, Targets: []string{"8.8.8.8:53"}, Name: "fixture-split", Enabled: false}
	if _, err := f.p.Exec(ctx, "UPDATE users SET max_rules=1 WHERE id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.user, "rules/import", "POST", map[string]any{"rules": []RuleInput{input}}), 400)
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM rules WHERE node_id=$1", node).Scan(&count); err != nil || count != 0 {
		t.Fatal("limit failure partially saved pair", err, count)
	}
	if _, err := f.p.Exec(ctx, "UPDATE users SET max_rules=2 WHERE id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{24020, 0} {
		input.ListenPort = port
		w := f.request(f.user, "rules/import", "POST", map[string]any{"rules": []RuleInput{input}})
		securityStatus(t, w, 200)
		var result struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.IDs) != 2 {
			t.Fatal("import did not produce two rules", err)
		}
		var same bool
		if err := f.p.QueryRow(ctx, `SELECT count(*)=2 AND count(DISTINCT protocol)=2 AND count(DISTINCT listen_port)=1 AND bool_and(user_id=$2 AND NOT enabled) FROM rules WHERE id=ANY($1)`, result.IDs, f.user).Scan(&same); err != nil || !same {
			t.Fatal("pair lost port, owner or pause state", err)
		}
		if _, err := f.p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", node); err != nil {
			t.Fatal(err)
		}
	}
}
