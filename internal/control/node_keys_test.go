package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeKeyVisibleToAdminAndStable(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	aid, _ := testUser(t, p, 1024, 5, true)
	uid, _ := testUser(t, p, 1024, 5, false)
	sessions := map[int64]string{}
	for _, id := range []int64{aid, uid} {
		sessions[id] = Secret()
		if _, e := p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(sessions[id]), id); e != nil {
			t.Fatal(e)
		}
	}
	s := New(p)
	request := func(actor int64, path, method string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if actor > 0 {
			r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: sessions[actor]})
		}
		w := httptest.NewRecorder()
		s.Handler(http.NotFoundHandler()).ServeHTTP(w, r)
		return w
	}
	created := request(aid, "admin/nodes", "POST", map[string]string{"name": Secret()})
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var node struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	json.Unmarshal(created.Body.Bytes(), &node)
	defer p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node.ID)
	if !hashOK(node.Token) {
		t.Fatal("node token missing")
	}
	s = New(p) // Reload from the database, not a one-time response or server memory.
	listed := request(aid, "admin/nodes", "GET", nil)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), node.Token) {
		t.Fatal("admin cannot retrieve key")
	}
	if strings.Contains(listed.Body.String(), Hash(node.Token)) {
		t.Fatal("hash unnecessarily exposed")
	}
	testAuthorize(t, p, uid, node.ID)
	for _, path := range []string{"admin/nodes", "nodes"} {
		if got := request(uid, path, "GET", nil); got.Code != 403 {
			t.Fatal("non-admin node management access", got.Code)
		}
	}
	for _, path := range []string{"rule-nodes", "node-status", "site"} {
		got := request(uid, path, "GET", nil)
		if got.Code != 200 || strings.Contains(got.Body.String(), node.Token) {
			t.Fatal("user-facing node data includes key")
		}
	}
	if got := request(0, "admin/nodes", "GET", nil); got.Code != 401 {
		t.Fatal("anonymous key access")
	}
	// Existing hash-only records recover the original key on authentication.
	if _, e := p.Exec(ctx, "UPDATE nodes SET token='' WHERE id=$1", node.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.nodeForToken(ctx, Secret()); e == nil {
		t.Fatal("invalid key accepted")
	}
	var saved string
	p.QueryRow(ctx, "SELECT token FROM nodes WHERE id=$1", node.ID).Scan(&saved)
	if saved != "" {
		t.Fatal("bad authentication wrote key")
	}
	recovered, e := s.nodeForToken(ctx, node.Token)
	if e != nil || recovered.Token != node.Token {
		t.Fatal("legacy key recovery failed", e)
	}
	var digest string
	p.QueryRow(ctx, "SELECT token,token_hash FROM nodes WHERE id=$1", node.ID).Scan(&saved, &digest)
	if saved != node.Token || digest != Hash(node.Token) {
		t.Fatal("legacy recovery rotated key")
	}
}
