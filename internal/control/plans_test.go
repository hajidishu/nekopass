package control

import (
	"bytes"
	"context"
	"encoding/json"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPlansScopesAndProbePrivacy(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1<<30, 10, true)
	uid, pid := testUser(t, p, 1<<30, 10, false)
	other, _ := testUser(t, p, 1<<30, 10, false)
	var node int64
	if e := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,public_address,notes) VALUES($1,$2,'203.0.113.91','private-admin-note') RETURNING id", Secret(), Secret()).Scan(&node); e != nil {
		t.Fatal(e)
	}
	gid := testAuthorize(t, p, uid, node)
	testAuthorize(t, p, adminID, node)
	defer p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	sessions := map[int64]string{}
	for _, id := range []int64{uid, adminID, other} {
		token := Secret()
		if _, e := p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(token), id); e != nil {
			t.Fatal(e)
		}
		sessions[id] = token
	}
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	request := func(actor int64, path, method string, data any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(data)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: sessions[actor]})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	mustOK := func(w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("HTTP %d %s", w.Code, w.Body.String())
		}
	}
	in := RuleInput{UserID: uid, NodeID: node, Targets: []string{"127.0.0.1:80"}, Enabled: true}
	w := request(adminID, "rules", "POST", in)
	mustOK(w)
	w = request(uid, "rules", "POST", in)
	mustOK(w)
	for _, actor := range []int64{uid, adminID} {
		w = request(actor, "rules?user_id="+strconv.FormatInt(other, 10), "GET", nil)
		mustOK(w)
		var rows []map[string]any
		json.Unmarshal(w.Body.Bytes(), &rows)
		if len(rows) != 1 || int64(rows[0]["user_id"].(float64)) != actor {
			t.Fatalf("rules scope leak %s", w.Body.String())
		}
	}
	prefix := "admin/users/" + strconv.FormatInt(uid, 10) + "/"
	mustOK(request(adminID, prefix+"rules", "GET", nil))
	for _, path := range []string{prefix + "rules", "admin/plans", "admin/nodes", "admin/node-groups", "nodes"} {
		if w = request(uid, path, "GET", nil); w.Code != 403 {
			t.Fatalf("admin endpoint leaked %s: %d", path, w.Code)
		}
	}
	plan := PlanInput{Name: Secret(), Enabled: true, SpeedMbps: 100, QuotaBytes: 1 << 30, MaxRules: 10, MaxConnections: 50, IPLimit: 2, RuleSpeedMbps: 8, RuleIPLimit: 1, RuleConnectionLimit: 4, NodeGroupIDs: []int64{gid}}
	mustOK(request(adminID, "admin/plans/"+strconv.FormatInt(pid, 10), "PUT", plan))
	c, e := p.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Release()
	ss := &StreamServer{Server: s}
	report := &pb.AgentMessage{InstanceId: Secret(), RequestUsers: []int64{uid}, Probe: &pb.Probe{SampledAt: 100, MemoryTotal: 100, MemoryUsed: 50, MemoryReady: true, CpuPercent: 25, CpuReady: true}}
	out, e := ss.exchange(ctx, c, node, report)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, u := range out.Users {
		if u.Id == uid {
			found = true
			if u.SpeedBps != 12500000 || u.MaxConnections != 50 || u.IpLimit != 2 {
				t.Fatal("plan not applied", u)
			}
		}
	}
	if !found {
		t.Fatal("missing plan user")
	}
	for _, r := range out.Rules {
		if r.UserId == uid && (r.SpeedBps != 1000000 || r.IpLimit != 1 || r.ConnectionLimit != 4) {
			t.Fatal("rule limits not centralized", r)
		}
	}
	w = request(uid, "node-status", "GET", nil)
	mustOK(w)
	if !strings.Contains(w.Body.String(), "memory_used") {
		t.Fatal("probe missing")
	}
	for _, secret := range []string{"203.0.113.91", "public_address", "listen_host", "token", "sync_error", "disk_path", "private-admin-note"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("probe leaked %s", secret)
		}
	}
	w = request(other, "node-status", "GET", nil)
	mustOK(w)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("unauthorized probe nodes", w.Body.String())
	}
	var issued int64
	p.QueryRow(ctx, "SELECT issued FROM grants WHERE user_id=$1 AND node_id=$2", uid, node).Scan(&issued)
	plan.QuotaBytes = issued - 1
	if w = request(adminID, "admin/plans/"+strconv.FormatInt(pid, 10), "PUT", plan); w.Code != 409 {
		t.Fatal("quota downgrade could replay/overspend")
	}
	plan.QuotaBytes = 1 << 30
	plan.Enabled = false
	mustOK(request(adminID, "admin/plans/"+strconv.FormatInt(pid, 10), "PUT", plan))
	out, e = ss.exchange(ctx, c, node, report)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range out.Rules {
		if r.UserId == uid {
			t.Fatal("disabled plan still authorized")
		}
	}
	if w = request(adminID, "users/"+strconv.FormatInt(uid, 10), "PUT", map[string]any{"username": "x", "enabled": true, "plan_id": pid, "speed_mbps": 999}); w.Code != 400 {
		t.Fatal("user-specific limit override accepted")
	}
	// Cleanup node-associated rows before helper cleanup removes identities.
	for _, q := range []string{"DELETE FROM grants WHERE node_id=$1", "DELETE FROM rule_usage WHERE node_id=$1", "DELETE FROM rules WHERE node_id=$1"} {
		p.Exec(ctx, q, node)
	}
}
