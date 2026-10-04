package control

import (
	"context"
	"net/http"
	"testing"
)

func TestInvalidResourcePathsDoNotCreateDatabaseRows(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	password, err := RandomAdministratorPassword()
	if err != nil {
		t.Fatal(err)
	}
	var node int64
	if err = f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	testAuthorize(t, f.p, f.user, node)
	cases := []struct {
		path, table string
		actor       int64
		payload     any
	}{
		{"admin/users/bad", "users", f.admin, UserInput{Username: Secret(), Password: password, Enabled: true}},
		{"admin/plans/bad", "plans", f.admin, PlanInput{Name: Secret(), Enabled: true}},
		{"admin/nodes/bad", "nodes", f.admin, map[string]any{"name": Secret()}},
		{"admin/node-groups/bad", "node_groups", f.admin, map[string]any{"name": Secret()}},
		{"rule-groups/bad", "rule_groups", f.user, map[string]any{"name": "fixture-group"}},
		{"rules/bad", "rules", f.user, RuleInput{NodeID: node, Targets: []string{"example.com:443"}, Enabled: true}},
	}
	for _, c := range cases {
		var before, after int64
		if err = f.p.QueryRow(ctx, "SELECT count(*) FROM "+c.table).Scan(&before); err != nil {
			t.Fatal(err)
		}
		w := f.request(c.actor, c.path, http.MethodPut, c.payload)
		securityStatus(t, w, 400)
		if err = f.p.QueryRow(ctx, "SELECT count(*) FROM "+c.table).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatalf("invalid update created a %s record", c.table)
		}
	}
}
