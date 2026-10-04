package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTunnelRuleScopeAndDirectPermission(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1<<30, 10, true)
	uid, _ := testUser(t, p, 1<<30, 10, false)
	sessions := map[int64]string{}
	for _, id := range []int64{adminID, uid} {
		sessions[id] = Secret()
		if _, e := p.Exec(ctx, "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour')", Hash(sessions[id]), id); e != nil {
			t.Fatal(e)
		}
	}
	h := New(p).Handler(http.NotFoundHandler())
	request := func(actor int64, path, method string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: sessions[actor]})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
	}
	node := func(name string) NodeInput {
		return NodeInput{Name: name, Enabled: true, IngressEnabled: true, AllowDirect: true, TunnelProtocol: "plain_tcp", TunnelListenHost: "0.0.0.0", ListenHost: "0.0.0.0", PortMin: 1024, PortMax: 65535, MaxConnections: 1000, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, ProbeIntervalSeconds: 5, DiskPath: "/"}
	}
	created := func(v NodeInput) int64 {
		w := request(adminID, "admin/nodes", "POST", v)
		check(w, 200)
		var id struct {
			ID int64 `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &id)
		return id.ID
	}
	a := node("tunnel-ingress-" + Secret())
	ingress := created(a)
	if e := p.QueryRow(ctx, "SELECT token FROM nodes WHERE id=$1", ingress).Scan(&a.Token); e != nil {
		t.Fatal(e)
	}
	exit := node("tunnel-egress-" + Secret())
	exit.IngressEnabled = false
	exit.TunnelExitEnabled = true
	exit.TunnelPublicHost = "127.0.0.1"
	exit.TunnelListenPort = 32133
	exit.AllowedIngressIDs = []int64{ingress}
	egress := created(exit)
	if e := p.QueryRow(ctx, "SELECT token FROM nodes WHERE id=$1", egress).Scan(&exit.Token); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		p.Exec(ctx, "DELETE FROM rule_usage WHERE node_id=ANY($1)", []int64{ingress, egress})
		p.Exec(ctx, "DELETE FROM rules WHERE node_id=ANY($1)", []int64{ingress, egress})
		p.Exec(ctx, "DELETE FROM grants WHERE node_id=ANY($1)", []int64{ingress, egress})
		p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{ingress, egress})
	})
	a.GroupIDs = []int64{testAuthorize(t, p, uid, ingress)}
	rule := RuleInput{NodeID: ingress, Name: "tunnel-check", Targets: []string{"127.0.0.1:80"}, Enabled: true, Balance: "random", ProxyAccept: "off", ProxySend: "off"}
	makeRule := func(v RuleInput) int64 {
		w := request(uid, "rules", "POST", v)
		check(w, 200)
		var result struct {
			ID int64 `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &result)
		return result.ID
	}
	rule.EgressNodeID = egress
	check(request(uid, "rules", "POST", rule), 400) // Exit group is not in this user's plan.
	exit.GroupIDs = []int64{testAuthorize(t, p, uid, egress)}
	ruleID := makeRule(rule)
	// Exit-only nodes remain usable as exits, but cannot become an ingress.
	invalidIngress := rule
	invalidIngress.NodeID = egress
	invalidIngress.EgressNodeID = 0
	check(request(uid, "rules", "POST", invalidIngress), 400)
	check(request(uid, "rules/import", "POST", map[string]any{"rules": []RuleInput{invalidIngress}}), 400)
	a.IngressEnabled = false
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", ingress), "PUT", a), 409)
	a.IngressEnabled = true
	// Even inconsistent legacy data must not create a client-facing listener on
	// an exit-only node, while its authorized exit routes are still delivered.
	if _, e := p.Exec(ctx, `INSERT INTO rules(user_id,node_id,listen_port,target_host,target_port,targets) VALUES($1,$2,32001,'127.0.0.1',80,'["127.0.0.1:80"]')`, uid, egress); e != nil {
		t.Fatal(e)
	}
	stream := &StreamServer{Server: New(p)}
	config, e := stream.exchange(ctx, p, egress, &pb.AgentMessage{ProtocolVersion: 6, InstanceId: Secret()})
	if e != nil {
		t.Fatal(e)
	}
	if !config.Node.TunnelExitEnabled || len(config.Rules) != 0 || len(config.EgressRules) != 1 {
		t.Fatal("exit-only configuration lost exit routes or includes ingress listeners")
	}
	if _, e = p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1", egress); e != nil {
		t.Fatal(e)
	}
	if w := request(uid, "rules", "GET", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"egress_node_id":`)) {
		t.Fatal("user rule omits exit selection")
	}
	if w := request(uid, "rule-nodes", "GET", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"allowed_ingress_ids":`)) {
		t.Fatal("exit choices missing")
	}
	if w := request(uid, "admin/nodes", "GET", nil); w.Code != 403 {
		t.Fatal("admin tunnel secrets exposed")
	}
	var key string
	if e := p.QueryRow(ctx, "SELECT token FROM node_tunnel_links WHERE ingress_node_id=$1 AND egress_node_id=$2", ingress, egress).Scan(&key); e != nil || len(key) != 64 {
		t.Fatal("link credential missing", e)
	}
	if w := request(uid, "rule-nodes", "GET", nil); bytes.Contains(w.Body.Bytes(), []byte(key)) {
		t.Fatal("link credential leaked to user")
	}
	exit.AllowedIngressIDs = []int64{}
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", egress), "PUT", exit), 409)
	exit.AllowedIngressIDs = []int64{ingress}
	exit.TunnelExitEnabled = false
	exit.AllowedIngressIDs = []int64{}
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", egress), "PUT", exit), 409)
	rule.EgressNodeID = 0
	check(request(uid, fmt.Sprintf("rules/%d", ruleID), "PUT", rule), 200)
	check(request(uid, "rules/batch", "POST", BatchInput{IDs: []int64{ruleID}, Action: "switch", NodeID: egress}), 400)
	a.AllowDirect = false
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", ingress), "PUT", a), 409)
	check(request(uid, fmt.Sprintf("rules/%d", ruleID), "DELETE", map[string]any{}), 200)
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", ingress), "PUT", a), 200)
	check(request(uid, "rules", "POST", rule), 400)
	rule.EgressNodeID = egress
	lastRule := makeRule(rule)
	if w := request(adminID, "admin/nodes", "GET", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"tunnel_protocol":"plain_tcp"`)) {
		t.Fatal("exit node protocol not configurable")
	}
	check(request(uid, fmt.Sprintf("rules/%d", lastRule), "DELETE", map[string]any{}), 200)
	a.IngressEnabled = false
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", ingress), "PUT", a), 200)
	var links int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM node_tunnel_links WHERE ingress_node_id=$1", ingress).Scan(&links); e != nil || links != 0 {
		t.Fatal("unused ingress associations were not removed", links, e)
	}
	exit.TunnelExitEnabled = true
	exit.AllowedIngressIDs = []int64{ingress}
	check(request(adminID, fmt.Sprintf("admin/nodes/%d", egress), "PUT", exit), 400)
}
