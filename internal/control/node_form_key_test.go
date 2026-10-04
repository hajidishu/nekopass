package control

import (
	"bytes"
	"context"
	"encoding/json"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestNodeEditKeyEmptyGeneratesAndKeepsInstance(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1024, 3, true)
	ordinaryID, _ := testUser(t, p, 1024, 3, false)
	sessions := map[int64]string{}
	for _, id := range []int64{adminID, ordinaryID} {
		sessions[id] = Secret()
		p.Exec(ctx, "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour')", Hash(sessions[id]), id)
	}
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	req := func(actor int64, path, method string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: sessions[actor]})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	form := NodeInput{Name: Secret(), Token: "my-node-key-2026", Enabled: true, IngressEnabled: true, AllowDirect: true, TunnelProtocol: "plain_tcp", TunnelListenHost: "0.0.0.0", ListenHost: "0.0.0.0", PortMin: 1024, PortMax: 65535, MaxConnections: 1000, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, ProbeIntervalSeconds: 5, DiskPath: "/"}
	created := req(adminID, "admin/nodes", "POST", form)
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body.String())
	}
	var result struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	json.Unmarshal(created.Body.Bytes(), &result)
	if result.Token != form.Token {
		t.Fatal("custom node key changed at creation")
	}
	t.Cleanup(func() { p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", result.ID) })
	path := "admin/nodes/" + strconv.FormatInt(result.ID, 10)
	if w := req(ordinaryID, path, "PUT", form); w.Code != 403 {
		t.Fatal("regular user may edit node")
	}
	same := req(adminID, path, "PUT", form)
	if same.Code != 200 {
		t.Fatal(same.Body.String())
	}
	var unchanged string
	p.QueryRow(ctx, "SELECT token FROM nodes WHERE id=$1", result.ID).Scan(&unchanged)
	if unchanged != form.Token {
		t.Fatal("ordinary node edit rotated key")
	}
	instance := Secret()
	p.Exec(ctx, "UPDATE nodes SET instance_id=$2 WHERE id=$1", result.ID, instance)
	p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()+interval '1 hour','{}')", Hash(Secret()), result.ID)
	form.Token = ""
	changed := req(adminID, path, "PUT", form)
	if changed.Code != 200 {
		t.Fatal(changed.Code, changed.Body.String())
	}
	json.Unmarshal(changed.Body.Bytes(), &result)
	if !hashOK(result.Token) || result.Token == unchanged {
		t.Fatal("blank field did not generate new node key")
	}
	var stored, hash, identity string
	p.QueryRow(ctx, "SELECT token,token_hash,instance_id FROM nodes WHERE id=$1", result.ID).Scan(&stored, &hash, &identity)
	if stored != result.Token || hash != Hash(result.Token) || identity != instance {
		t.Fatal("node identity or new key not preserved")
	}
	var pending int
	p.QueryRow(ctx, "SELECT count(*) FROM node_install_tickets WHERE node_id=$1 AND used_at IS NULL", result.ID).Scan(&pending)
	if pending != 0 {
		t.Fatal("old installer ticket survived key change")
	}
	if _, e := s.nodeForToken(ctx, unchanged); e == nil {
		t.Fatal("old key still authenticates")
	}
	if _, e := s.nodeForToken(ctx, result.Token); e != nil {
		t.Fatal("new key cannot authenticate", e)
	}
	stream := &StreamServer{Server: s}
	report := &pb.AgentMessage{ProtocolVersion: 6, InstanceId: instance}
	if _, e := stream.exchangeWithCredential(ctx, p, result.ID, report, Hash(unchanged)); e == nil {
		t.Fatal("old gRPC stream still allowed after key change")
	}
	if _, e := stream.exchangeWithCredential(ctx, p, result.ID, report, Hash(result.Token)); e != nil {
		t.Fatal("new gRPC stream rejected", e)
	}
	form.Token = "too short"
	if w := req(adminID, path, "PUT", form); w.Code != 400 {
		t.Fatal("unsafe key accepted")
	}
}
