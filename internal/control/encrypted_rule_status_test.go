package control

import (
	"context"
	"encoding/json"
	"testing"
)

func TestEncryptedRuleStatusMatchesSingleAndGroupCapabilities(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var entry, exit, other int64
	for _, id := range []*int64{&entry, &exit, &other} {
		if err := f.p.QueryRow(ctx, `INSERT INTO nodes(name,token_hash,tunnel_exit_enabled,tunnel_public_host,tunnel_listen_port,protocol_version,last_seen,applied_revision) VALUES($1,$2,true,'exit.example.test',24443,35,now(),1000000) RETURNING id`, Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
		testAuthorize(t, f.p, f.user, *id)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM rule_usage WHERE node_id=$1", entry)
		f.p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", entry)
		f.p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{entry, exit, other})
	})
	for _, id := range []int64{exit, other} {
		if _, err := f.p.Exec(ctx, "INSERT INTO node_tunnel_links(ingress_node_id,egress_node_id,token) VALUES($1,$2,$3)", entry, id, Secret()); err != nil {
			t.Fatal(err)
		}
	}
	var group int64
	if err := f.p.QueryRow(ctx, "INSERT INTO node_groups(name) VALUES($1) RETURNING id", Secret()).Scan(&group); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, "DELETE FROM rules WHERE egress_group_id=$1", group)
		f.p.Exec(ctx, "DELETE FROM user_node_groups WHERE group_id=$1", group)
		f.p.Exec(ctx, "DELETE FROM node_groups WHERE id=$1", group)
	})
	if _, err := f.p.Exec(ctx, "INSERT INTO node_group_members(group_id,node_id,role,weight) VALUES($1,$2,'active',1),($1,$3,'disabled',1)", group, exit, other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "INSERT INTO user_node_groups(user_id,group_id) VALUES($1,$2)", f.user, group); err != nil {
		t.Fatal(err)
	}
	ids := map[string][2]int64{}
	for _, network := range []string{"tcp", "udp"} {
		for i := 0; i < 2; i++ {
			in := RuleInput{NodeID: entry, Targets: []string{"1.1.1.1:443"}, Protocol: network, Enabled: true}
			if i == 0 {
				in.EgressNodeID = exit
			} else {
				in.EgressGroupID = group
			}
			w := f.request(f.user, "rules", "POST", in)
			securityStatus(t, w, 200)
			var created struct {
				ID int64 `json:"id"`
			}
			json.Unmarshal(w.Body.Bytes(), &created)
			v := ids[network]
			v[i] = created.ID
			ids[network] = v
		}
	}
	statuses := func() map[int64]string {
		t.Helper()
		w := f.request(f.user, "rules", "GET", nil)
		securityStatus(t, w, 200)
		var rows []struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		result := map[int64]string{}
		for _, r := range rows {
			result[r.ID] = r.Status
		}
		return result
	}
	for _, mode := range []string{"random_tcp", "random_h2", "random_udp", "dtls_udp", "tls_tcp"} {
		network := "tcp"
		if mode == "random_udp" || mode == "dtls_udp" {
			network = "udp"
		}
		if _, err := f.p.Exec(ctx, `UPDATE nodes SET tunnel_protocol=$2,tls_config='{"padding_enabled":true}',mux_config='{"enabled":true}' WHERE id=$1`, exit, mode); err != nil {
			t.Fatal(err)
		}
		for _, versions := range [][2]int{{34, 34}, {35, 34}, {34, 35}, {35, 35}} {
			if _, err := f.p.Exec(ctx, "UPDATE nodes SET protocol_version=CASE WHEN id=$1 THEN $3::int ELSE $4::int END,last_seen=now(),applied_revision=1000000,sync_error='' WHERE id=ANY($2)", entry, []int64{entry, exit}, versions[0], versions[1]); err != nil {
				t.Fatal(err)
			}
			want := "upgrade_required"
			if versions == [2]int{35, 35} {
				want = "active"
			}
			got := statuses()
			for _, id := range ids[network] {
				if got[id] != want {
					t.Fatal(mode, versions, id, got[id], want)
				}
			}
		}
	}
	// A compatible standby can keep the group usable while the single exit
	// requires an upgrade. Capabilities must hold on one candidate together.
	if _, err := f.p.Exec(ctx, "UPDATE node_group_members SET role='standby' WHERE group_id=$1 AND node_id=$2", group, other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET protocol_version=34 WHERE id=$1", exit); err != nil {
		t.Fatal(err)
	}
	got := statuses()
	if got[ids["tcp"][0]] != "upgrade_required" || got[ids["tcp"][1]] != "active" {
		t.Fatal("usable candidate not respected", got)
	}
	if _, err := f.p.Exec(ctx, `UPDATE nodes SET tunnel_protocol='dtls_udp',protocol_version=35,brutal_enabled=true,bandwidth_up_mbps=0,bandwidth_down_mbps=0,mux_config='{"enabled":false}' WHERE id=$1`, exit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, `UPDATE nodes SET tunnel_protocol='plain_udp',protocol_version=33,mux_config='{"enabled":true}' WHERE id=$1`, other); err != nil {
		t.Fatal(err)
	}
	if got := statuses(); got[ids["udp"][1]] != "bandwidth_required" {
		t.Fatal("capabilities from different unusable candidates combined", got)
	}
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET last_seen=now()-interval '1 minute' WHERE id=$1", exit); err != nil {
		t.Fatal(err)
	}
	if got := statuses(); got[ids["udp"][1]] != "offline" {
		t.Fatal("offline compatible exit hidden by bandwidth configuration", got)
	}
}
