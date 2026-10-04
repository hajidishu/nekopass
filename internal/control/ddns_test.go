package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestDDNSAdminScopeConfigAndReports(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node, other int64
	for _, id := range []*int64{&node, &other} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
		value := *id
		t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", value) })
	}
	path := fmt.Sprintf("admin/nodes/%d/ddns", node)
	testAuthorize(t, f.p, f.user, node)
	cfg := ddns.DefaultConfig()
	cfg.Enabled = true
	cfg.RecordName = "dynamic.example.test"
	cfg.Token = "fixture-private-cloudflare-token"
	for _, method := range []string{"GET", "PUT", "POST"} {
		endpoint := path
		if method == "POST" {
			endpoint += "/run"
		}
		securityStatus(t, f.request(0, endpoint, method, cfg), 401)
		securityStatus(t, f.request(f.user, endpoint, method, cfg), 403)
	}
	securityStatus(t, f.request(f.admin, path, "GET", nil), 200)
	securityStatus(t, f.request(f.admin, path, "PUT", cfg), 200)
	var public, exit string
	if err := f.p.QueryRow(ctx, "SELECT public_address,tunnel_public_host FROM nodes WHERE id=$1", node).Scan(&public, &exit); err != nil || public != cfg.RecordName || exit != cfg.RecordName {
		t.Fatal("domain binding failed")
	}
	stream := &StreamServer{Server: f.s}
	out, err := stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 8})
	if err != nil || out.Node.Ddns == nil || out.Node.Ddns.Token != cfg.Token || out.Node.Ddns.Generation != 1 {
		t.Fatalf("own node did not receive DDNS: %v", err)
	}
	otherOut, err := stream.exchange(ctx, f.p, other, &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 8})
	if err != nil || otherOut.Node.Ddns != nil {
		t.Fatal("DDNS config crossed node boundary")
	}
	securityStatus(t, f.request(f.admin, path+"/run", "POST", map[string]any{}), 200)
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = acceptDDNSReport(ctx, tx, node, &pb.DDNSStatus{Generation: 1, State: "ok", Ipv4: "203.0.113.7", CheckedUnix: 100, UpdatedUnix: 100}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = tx.QueryRow(ctx, "SELECT status->>'state' FROM node_ddns WHERE node_id=$1", node).Scan(&state); err != nil || state != "pending" {
		t.Fatal("stale report overwrote pending generation")
	}
	if err = acceptDDNSReport(ctx, tx, other, &pb.DDNSStatus{Generation: 2, State: "error"}); err != nil {
		t.Fatal(err)
	}
	if err = acceptDDNSReport(ctx, tx, node, &pb.DDNSStatus{Generation: 2, State: "ok", Ipv4: "203.0.113.7", CheckedUnix: 101, UpdatedUnix: 100}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	w := f.request(f.admin, path, "GET", nil)
	securityStatus(t, w, 200)
	var details struct {
		Config   ddns.Config
		Status   map[string]any
		Received any `json:"status_received_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &details) != nil || details.Config.Token != cfg.Token || details.Status["state"] != "ok" || details.Received == nil {
		t.Fatal("admin status/config unreadable")
	}
	for _, endpoint := range []string{"rule-nodes", "node-status", "shop/plans"} {
		w = f.request(f.user, endpoint, "GET", nil)
		securityStatus(t, w, 200)
		if strings.Contains(w.Body.String(), cfg.Token) {
			t.Fatal("DDNS credential leaked into user API")
		}
	}
	// Changing forwarding settings cannot erase separately stored DNS settings.
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/nodes/%d", node), "PUT", map[string]any{"name": "fixture-renamed", "enabled": true}), 200)
	w = f.request(f.admin, path, "GET", nil)
	securityStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), cfg.Token) {
		t.Fatal("basic node edit erased DNS settings")
	}
	cfg.Enabled = false
	securityStatus(t, f.request(f.admin, path, "PUT", cfg), 200)
	securityStatus(t, f.request(f.admin, path+"/run", "POST", map[string]any{}), 409)
	// Separate HTML page is protected by the same administrator session check.
	h := f.s.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Path) }))
	for actor, want := range map[int64]int{0: 303, f.user: 403, f.admin: 200} {
		r := httptest.NewRequest("GET", fmt.Sprintf("/admin/nodes/%d/ddns", node), nil)
		if actor != 0 {
			r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: f.tokens[actor]})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		securityStatus(t, w, want)
		if actor == f.admin && w.Body.String() != "/pages/admin_node_ddns.html" {
			t.Fatal("wrong DDNS HTML artifact")
		}
	}
}

func TestDDNSRejectsInvalidResourceAndConfiguration(t *testing.T) {
	f := newSecurityFixture(t)
	for _, path := range []string{"admin/nodes/bad/ddns", "admin/nodes/0/ddns", "admin/nodes/-1/ddns"} {
		securityStatus(t, f.request(f.admin, path, "PUT", ddns.DefaultConfig()), 400)
	}
	securityStatus(t, f.request(f.admin, "admin/nodes/999999999/ddns", "GET", nil), 404)
	cfg := ddns.DefaultConfig()
	cfg.Enabled = true
	cfg.RecordName = "node.example.test"
	cfg.Token = "fixture-token"
	cfg.IPv4URL = "http://insecure.example.test"
	securityStatus(t, f.request(f.admin, "admin/nodes/1/ddns", "PUT", cfg), 400)
	for _, status := range []*pb.DDNSStatus{{Generation: 1, State: "invented"}, {Generation: 1, State: "ok", Ipv4: "127.0.0.1"}, {Generation: 1, State: "ok", CheckedUnix: 1, UpdatedUnix: 2}} {
		tx, err := f.p.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if acceptDDNSReport(context.Background(), tx, 1, status) == nil {
			t.Error("invalid status accepted")
		}
		tx.Rollback(context.Background())
	}
}
