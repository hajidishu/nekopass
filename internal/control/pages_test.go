package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPageRoutesAndSafeReturns(t *testing.T) {
	if route, ok := resolvePage("/admin/nodes/123/protocols"); !ok || route.file != "admin_node_protocols" || !route.admin || route.nodeID != 123 {
		t.Fatal("protocol page route invalid")
	}
	for _, path := range []string{"/admin/nodes/0/protocols", "/admin/nodes/01/protocols", "/admin/nodes/-1/protocols"} {
		if _, ok := resolvePage(path); ok {
			t.Fatal("invalid protocol page accepted")
		}
	}
	if safeNext("/admin/nodes/123/protocols", false) != "/" || safeNext("/admin/nodes/123/protocols", true) != "/admin/nodes/123/protocols" {
		t.Fatal("protocol page return scope invalid")
	}
	if route, ok := resolvePage("/admin/nodes/123/ddns"); !ok || route.file != "admin_node_ddns" || !route.admin || route.nodeID != 123 {
		t.Fatal("DDNS page route invalid")
	}
	for _, path := range []string{"/admin/nodes/0/ddns", "/admin/nodes/01/ddns", "/admin/nodes/-1/ddns", "/admin/nodes/999999999999999999999/ddns"} {
		if _, ok := resolvePage(path); ok {
			t.Fatal("invalid DDNS page route accepted")
		}
	}
	if safeNext("/admin/nodes/123/ddns", false) != "/" || safeNext("/admin/nodes/123/ddns", true) != "/admin/nodes/123/ddns" {
		t.Fatal("DDNS return scope invalid")
	}
	for path, file := range map[string]string{"/": "home", "/login": "login", "/profile": "profile", "/forward_rules": "forward_rules", "/node_status": "node_status", "/admin": "admin", "/admin/announcements": "admin_announcements", "/admin/users": "admin_users", "/admin/plans": "admin_plans", "/admin/nodes": "admin_nodes", "/admin/node_groups": "admin_node_groups", "/admin/users/123/forward_rules": "admin_user_rules"} {
		p, ok := resolvePage(path)
		if !ok || p.file != file {
			t.Fatalf("bad page %s: %+v", path, p)
		}
	}
	for _, path := range []string{"/unknown", "/pages/admin.html", "/admin/users/0/forward_rules", "/admin/users/-1/forward_rules", "/admin/users/01/forward_rules", "/admin/users/999999999999999999999999/forward_rules"} {
		if _, ok := resolvePage(path); ok {
			t.Fatalf("unexpected route %s", path)
		}
	}
	for _, raw := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "/login", "/unknown", "/admin#fragment", "/admin\r\nLocation: https://evil.example"} {
		if got := safeNext(raw, true); got != "/" {
			t.Fatalf("unsafe redirect %q => %q", raw, got)
		}
	}
	if safeNext("/admin/users/123/forward_rules", false) != "/" {
		t.Fatal("regular user can return to admin")
	}
	if safeNext("/admin/users/123/forward_rules?test=1", true) != "/admin/users/123/forward_rules?test=1" {
		t.Fatal("valid deep return rejected")
	}
	if safeNext("/forward_rules", false) != "/forward_rules" {
		t.Fatal("valid user return rejected")
	}
}

func TestPageAccessAndProfileScope(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1<<20, 10, true)
	uid, _ := testUser(t, p, 1<<20, 10, false)
	tokens := map[int64]string{}
	for _, id := range []int64{adminID, uid} {
		token := Secret()
		if _, err := p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(token), id); err != nil {
			t.Fatal(err)
		}
		tokens[id] = token
	}
	s := New(p)
	h := s.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method != "HEAD" {
			fmt.Fprint(w, "document:"+r.URL.Path)
		}
	}))
	request := func(actor int64, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if actor != 0 {
			r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: tokens[actor]})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/", "/profile", "/forward_rules", "/node_status", "/admin", "/admin/users"} {
		w := request(0, path)
		if w.Code != 303 {
			t.Fatalf("anonymous %s: %d", path, w.Code)
		}
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil || location.Path != "/login" || location.Query().Get("next") != path {
			t.Fatal("return destination lost", w.Header())
		}
	}
	if w := request(0, "/login"); w.Code != 200 || !strings.Contains(w.Body.String(), "/pages/login.html") {
		t.Fatal("login document missing")
	}
	for path, file := range map[string]string{"/": "home", "/profile": "profile", "/forward_rules": "forward_rules", "/node_status": "node_status"} {
		w := request(uid, path)
		if w.Code != 200 || w.Body.String() != "document:/pages/"+file+".html" {
			t.Fatalf("user page %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/admin", "/admin/users", "/admin/plans", "/admin/nodes", "/admin/node_groups", "/admin/announcements", fmt.Sprintf("/admin/users/%d/forward_rules", uid)} {
		if w := request(uid, path); w.Code != 403 || strings.Contains(w.Body.String(), "document:") {
			t.Fatalf("admin HTML exposed: %s", path)
		}
		if w := request(adminID, path); w.Code != 200 || !strings.Contains(w.Body.String(), "document:/pages/admin") {
			t.Fatalf("admin page unavailable %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/pages/admin_users.html", "/pages/home.html", "/not-found", "/admin/users/9223372036854775807/forward_rules"} {
		if w := request(adminID, path); w.Code != 404 {
			t.Fatalf("unexpected fallback %s: %d", path, w.Code)
		}
	}
	if w := request(adminID, "/login?next=%2Fadmin%2Fplans"); w.Code != 303 || w.Header().Get("Location") != "/admin/plans" {
		t.Fatal("logged-in redirect failed")
	}
	if w := request(uid, "/admin/"); w.Code != 308 || w.Header().Get("Location") != "/admin" {
		t.Fatal("canonical route missing")
	}
	if w := request(0, "/assets/test.js"); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("shared static assets unavailable")
	}
	if w := request(uid, "/api/v1/admin/users"); w.Code != 403 {
		t.Fatal("admin user API leaked")
	}
	if w := request(uid, "/api/v1/admin/announcement"); w.Code != 403 {
		t.Fatal("admin announcement API leaked")
	}
	w := request(adminID, "/api/v1/profile")
	if w.Code != 200 || strings.Count(w.Body.String(), "\"username\"") != 1 {
		t.Fatalf("user-facing profile loads other users: %s", w.Body.String())
	}
	if w = request(adminID, fmt.Sprintf("/api/v1/admin/users/%d", uid)); w.Code != 200 || !strings.Contains(w.Body.String(), fmt.Sprintf("\"id\":%d", uid)) {
		t.Fatal("managed profile unavailable", w.Body.String())
	}
}
