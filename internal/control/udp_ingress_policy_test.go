package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestUDPIngressCreationPolicy(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var restricted, open, exit int64
	for _, id := range []*int64{&restricted, &open, &exit} {
		key := Secret()
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(id); err != nil {
			t.Fatal(err)
		}
		testAuthorize(t, f.p, f.user, *id)
	}
	defer func() {
		f.p.Exec(ctx, "DELETE FROM rules WHERE user_id=$1", f.user)
		f.p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{restricted, open, exit})
	}()
	makeRule := func(node int64, protocol string, port int) RuleInput {
		return RuleInput{NodeID: node, Protocol: protocol, ListenPort: port, Targets: []string{"8.8.8.8:53"}, Enabled: true}
	}
	create := func(in RuleInput) int64 {
		t.Helper()
		w := f.request(f.user, "rules", "POST", in)
		securityStatus(t, w, 200)
		var out struct{ ID int64 }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ID == 0 {
			t.Fatal("missing created rule ID", err)
		}
		return out.ID
	}
	udp := makeRule(restricted, "udp", 24001)
	udpID := create(udp) // The default permits UDP; this rule is grandfathered.
	tcp := makeRule(restricted, "tcp", 24002)
	tcpID := create(tcp)
	remoteUDP := makeRule(open, "udp", 24003)
	remoteID := create(remoteUDP)
	setPolicy := func(node int64, value bool) {
		t.Helper()
		v, _, err := loadNodeInput(ctx, f.p, node)
		if err != nil {
			t.Fatal(err)
		}
		v.DenyUDPIngressCreation = &value
		securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/nodes/%d", node), "PUT", v), 200)
	}
	setPolicy(restricted, true)
	assertBlocked := func(path, method string, body any) {
		t.Helper()
		w := f.request(f.user, path, method, body)
		securityStatus(t, w, 400)
		if !strings.Contains(w.Body.String(), "此节点禁止创建新的 UDP 入站规则") {
			t.Fatalf("unexpected rejection: %s", w.Body.String())
		}
	}
	assertBlocked("rules", "POST", makeRule(restricted, "udp", 24004))
	converted := tcp
	converted.Protocol = "udp"
	assertBlocked(fmt.Sprintf("rules/%d", tcpID), "PUT", converted)
	moved := remoteUDP
	moved.NodeID = restricted
	assertBlocked(fmt.Sprintf("rules/%d", remoteID), "PUT", moved)
	for _, action := range []string{"edit", "switch"} {
		assertBlocked("rules/batch", "POST", map[string]any{"ids": []int64{tcpID, remoteID}, "action": action, "node_id": restricted, "patch": map[string]any{"node_id": restricted}})
		var actual int64
		if err := f.p.QueryRow(ctx, "SELECT node_id FROM rules WHERE id=$1", remoteID).Scan(&actual); err != nil || actual != open {
			t.Fatal("failed batch moved a UDP rule", err)
		}
	}
	var before, after int
	f.p.QueryRow(ctx, "SELECT count(*) FROM rules WHERE user_id=$1", f.user).Scan(&before)
	for _, entries := range [][]RuleInput{
		{makeRule(restricted, "tcp", 24005), makeRule(restricted, "udp", 24006)},
		{makeRule(restricted, "tcp_udp", 24007)},
	} {
		assertBlocked("rules/import", "POST", map[string]any{"rules": entries})
		if err := f.p.QueryRow(ctx, "SELECT count(*) FROM rules WHERE user_id=$1", f.user).Scan(&after); err != nil || after != before {
			t.Fatal("failed import committed partial rules", err)
		}
	}
	// Copying is also a new admission, even when the original rule is allowed.
	copy := udp
	copy.ListenPort = 24008
	assertBlocked("rules", "POST", copy)
	create(makeRule(restricted, "tcp", 24009))
	udp.Name = "edited existing UDP"
	udp.Targets = []string{"1.1.1.1:53"}
	securityStatus(t, f.request(f.user, fmt.Sprintf("rules/%d", udpID), "PUT", udp), 200)
	securityStatus(t, f.request(f.user, "rules/batch", "POST", map[string]any{"ids": []int64{udpID}, "action": "edit", "patch": map[string]any{"node_id": restricted, "balance": "round_robin"}}), 200)
	for _, action := range []string{"disable", "enable"} {
		securityStatus(t, f.request(f.user, "rules/batch", "POST", map[string]any{"ids": []int64{udpID}, "action": action}), 200)
	}
	// Restricting ingress must not prohibit using the same node as an exit.
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET tunnel_exit_enabled=true,tunnel_protocol='plain_udp',tunnel_listen_port=25000,tunnel_public_host='exit.example.test',deny_udp_ingress_creation=true WHERE id=$1", exit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "INSERT INTO node_tunnel_links(ingress_node_id,egress_node_id,token) VALUES($1,$2,$3)", open, exit, Secret()); err != nil {
		t.Fatal(err)
	}
	viaExit := makeRule(open, "udp", 24010)
	viaExit.EgressNodeID = exit
	create(viaExit)
	// Moving away is allowed. Once it leaves, it cannot move back.
	udp.NodeID = open
	securityStatus(t, f.request(f.user, fmt.Sprintf("rules/%d", udpID), "PUT", udp), 200)
	udp.NodeID = restricted
	assertBlocked(fmt.Sprintf("rules/%d", udpID), "PUT", udp)
	// Admins managing a user's rules use the same policy, without bypassing it.
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/rules", f.user), "POST", copy), 400)
	securityStatus(t, f.request(f.other, fmt.Sprintf("rules/%d", udpID), "PUT", udp), 400)
	setPolicy(restricted, false)
	create(makeRule(restricted, "udp", 24011))
}

func TestUDPIngressPolicySettingsPersistenceAndPermissions(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var id int64
	key := Secret()
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
	testAuthorize(t, f.p, f.user, id)
	base := fmt.Sprintf("admin/nodes/%d", id)
	value, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil || value.DenyUDPIngressCreation == nil || *value.DenyUDPIngressCreation {
		t.Fatal("UDP ingress should be permitted by default", err)
	}
	deny := true
	value.DenyUDPIngressCreation = &deny
	securityStatus(t, f.request(f.user, base, "PUT", value), 403)
	securityStatus(t, f.request(f.admin, base, "PUT", value), 200)
	for _, endpoint := range []string{"admin/nodes", "rule-nodes"} {
		w := f.request(map[bool]int64{true: f.admin, false: f.user}[endpoint == "admin/nodes"], endpoint, "GET", nil)
		securityStatus(t, w, 200)
		var nodes []struct {
			ID   int64
			Deny bool `json:"deny_udp_ingress_creation"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, node := range nodes {
			if node.ID == id {
				found = node.Deny
			}
		}
		if !found {
			t.Fatal("node policy was not exposed to its authorized UI", endpoint)
		}
	}
	// Older full/partial clients must not erase a policy field they don't send.
	data, _ := json.Marshal(value)
	var basic NodeBasicInput
	var protocols NodeProtocolsInput
	json.Unmarshal(data, &basic)
	json.Unmarshal(data, &protocols)
	value.DenyUDPIngressCreation = nil
	protocols.DenyUDPIngressCreation = nil
	for _, request := range []struct {
		path string
		body any
	}{{base, value}, {base + "/basic", basic}, {base + "/protocols", protocols}} {
		securityStatus(t, f.request(f.admin, request.path, "PUT", request.body), 200)
		loaded, _, err := loadNodeInput(ctx, f.p, id)
		if err != nil || loaded.DenyUDPIngressCreation == nil || !*loaded.DenyUDPIngressCreation {
			t.Fatal("omitting policy erased restriction", request.path, err)
		}
	}
	deny = false
	protocols.DenyUDPIngressCreation = &deny
	securityStatus(t, f.request(f.user, base+"/protocols", "PUT", protocols), 403)
	securityStatus(t, f.request(f.admin, base+"/protocols", "PUT", protocols), 200)
	loaded, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil || loaded.DenyUDPIngressCreation == nil || *loaded.DenyUDPIngressCreation {
		t.Fatal("explicitly clearing restriction failed", err)
	}
}
