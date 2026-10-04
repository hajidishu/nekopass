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

func TestUnlimitedPlanLedgerTransitions(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1<<30, 10, true)
	uid, pid := testUser(t, p, 0, 1, false)
	var node int64
	if err := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	gid := testAuthorize(t, p, uid, node)
	token := Secret()
	p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(token), adminID)
	s := New(p)
	handler := s.Handler(http.NotFoundHandler())
	request := func(path, method string, data any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(data)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	plan := PlanInput{Name: Secret(), Enabled: true, SpeedMbps: 0, QuotaBytes: -1, MaxRules: 0, MaxConnections: 0, DurationDays: 0, NodeGroupIDs: []int64{gid}}
	path := "admin/plans/" + strconv.FormatInt(pid, 10)
	check(request(path, "PUT", plan), 200)
	prefix := "admin/users/" + strconv.FormatInt(uid, 10) + "/"
	for i := 0; i < 3; i++ {
		check(request(prefix+"rules", "POST", RuleInput{NodeID: node, Enabled: true, Targets: []string{"127.0.0.1:80"}}), 200)
	}
	var expires bool
	p.Exec(ctx, "UPDATE users SET plan_started_at=now()-interval '10 years' WHERE id=$1", uid)
	p.QueryRow(ctx, "SELECT expires_at IS NULL FROM user_entitlements WHERE id=$1", uid).Scan(&expires)
	if !expires {
		t.Fatal("forever plan expired")
	}
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	stream := &StreamServer{Server: s}
	r := &pb.AgentMessage{InstanceId: Secret(), RequestUsers: []int64{uid}}
	out, err := stream.exchange(ctx, c, node, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Users) != 1 || !out.Users[0].QuotaUnlimited || out.Users[0].Issued != 0 || out.Users[0].SpeedBps != 0 || out.Users[0].MaxConnections != 0 || out.Users[0].ExpiresUnix != 0 {
		t.Fatalf("bad unlimited policy: %v", out.Users)
	}
	usage := &pb.Usage{UserId: uid, UnlimitedSpent: 16 << 20, Traffic: 1234, QuotaUnlimited: true}
	r.Usage = []*pb.Usage{usage}
	r.RequestUsers = nil
	for i := 0; i < 3; i++ {
		if _, err = stream.exchange(ctx, c, node, r); err != nil {
			t.Fatal(err)
		}
	}
	var traffic, issued int64
	p.QueryRow(ctx, "SELECT traffic,issued FROM grants WHERE user_id=$1 AND node_id=$2", uid, node).Scan(&traffic, &issued)
	if traffic != 1234 || issued != 0 {
		t.Fatal("unlimited counted twice or created fake allowance", traffic, issued)
	}
	var events int64
	p.QueryRow(ctx, "SELECT sum(traffic_bytes)::bigint FROM usage_events WHERE user_id=$1", uid).Scan(&events)
	if events != 1234 {
		t.Fatal("unlimited reports not idempotent")
	}
	plan.QuotaBytes = (16 << 20) - 1
	check(request(path, "PUT", plan), 409)
	plan.QuotaBytes = 17 << 20
	plan.SpeedMbps = 1
	plan.MaxConnections = 2
	check(request(path, "PUT", plan), 200)
	// Late traffic was authorized before the finite policy reached the node.
	usage.UnlimitedSpent = 32 << 20
	usage.Traffic++
	out, err = stream.exchange(ctx, c, node, r)
	if err != nil {
		t.Fatal(err)
	}
	if out.Users[0].QuotaUnlimited || out.Users[0].Enabled {
		t.Fatal("late unlimited consumption did not stop over-budget finite policy")
	}
	usage.QuotaUnlimited = false
	if _, err = stream.exchange(ctx, c, node, r); err != nil {
		t.Fatal(err)
	}
	usage.UnlimitedSpent++
	if _, err = stream.exchange(ctx, c, node, r); err == nil {
		t.Fatal("unlimited debit accepted after finite acknowledgement")
	}
	usage.UnlimitedSpent--
	plan.QuotaBytes = 34 << 20
	check(request(path, "PUT", plan), 200)
	r.RequestUsers = []int64{uid}
	out, err = stream.exchange(ctx, c, node, r)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Users[0].Enabled || out.Users[0].Issued != 2<<20 || out.Users[0].QuotaUnlimited {
		t.Fatalf("finite budget did not subtract unlimited history: %v", out.Users)
	}
	plan.MaxRules = 1
	check(request(path, "PUT", plan), 409)
	plan.MaxRules = 0
	plan.SpeedMbps = -1
	check(request(path, "PUT", plan), 400)
	plan.SpeedMbps = 0
	plan.QuotaBytes = -2
	check(request(path, "PUT", plan), 400)
	// A zero-byte quota must remain distinct from unlimited.
	var zeroPlan int64
	p.QueryRow(ctx, "INSERT INTO plans(name,speed_bps,quota_bytes,max_rules,max_connections) VALUES($1,0,0,0,0) RETURNING id", Secret()).Scan(&zeroPlan)
	defer p.Exec(ctx, "DELETE FROM plans WHERE id=$1", zeroPlan)
	check(request("users/"+strconv.FormatInt(uid, 10), "PUT", UserInput{Username: Secret(), Enabled: true, PlanID: zeroPlan}), 409)
}
