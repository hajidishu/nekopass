package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWalletPurchaseIdempotencyAndCycleIsolation(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	aid, _ := testUser(t, p, 1024, 10, true)
	uid, pid := testUser(t, p, 1024, 10, false)
	other, _ := testUser(t, p, 1024, 10, false)
	if _, e := p.Exec(ctx, `UPDATE plans SET prices='{"monthly":5000,"annual":50000}' WHERE id=$1`, pid); e != nil {
		t.Fatal(e)
	}
	tokens := map[int64]string{}
	for _, id := range []int64{aid, uid, other} {
		tokens[id] = Secret()
		if _, e := p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(tokens[id]), id); e != nil {
			t.Fatal(e)
		}
	}
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	req := func(actor int64, path, method string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: tokens[actor]})
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
	recharge := map[string]any{"amount": "100.00", "note": "wallet fixture", "request_key": Secret()}
	check(req(uid, fmt.Sprintf("admin/users/%d/recharge", uid), "POST", recharge), 403)
	check(req(aid, fmt.Sprintf("admin/users/%d/recharge", uid), "POST", recharge), 200)
	check(req(aid, fmt.Sprintf("admin/users/%d/recharge", uid), "POST", recharge), 200)
	var balance int64
	p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", uid).Scan(&balance)
	if balance != 10000 {
		t.Fatal("duplicate recharge", balance)
	}
	quote := req(uid, "shop/quote", "POST", map[string]any{"plan_id": pid, "cycle": "monthly"})
	check(quote, 200)
	var q struct {
		Epoch int64 `json:"epoch"`
		Price int64 `json:"amount_cents"`
	}
	json.Unmarshal(quote.Body.Bytes(), &q)
	pay := map[string]any{"plan_id": pid, "cycle": "monthly", "expected_price_cents": q.Price, "expected_epoch": q.Epoch, "request_key": Secret()}
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 5)
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- req(uid, "shop/purchase", "POST", pay) }()
	}
	wg.Wait()
	close(results)
	for w := range results {
		check(w, 200)
	}
	p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", uid).Scan(&balance)
	if balance != 5000 {
		t.Fatal("purchase double charged", balance)
	}
	var epoch int64
	p.QueryRow(ctx, "SELECT quota_epoch FROM users WHERE id=$1", uid).Scan(&epoch)
	if epoch != 1 {
		t.Fatal("purchase double reset", epoch)
	}
	var count int
	p.QueryRow(ctx, "SELECT count(*) FROM wallet_entries WHERE user_id=$1", uid).Scan(&count)
	if count != 2 {
		t.Fatal("incorrect ledger", count)
	}
	check(req(other, "orders", "GET", nil), 200)
	if got := req(other, "orders", "GET", nil).Body.String(); bytes.Contains([]byte(got), []byte("wallet fixture")) {
		t.Fatal("order scope leak")
	}
	// Old page prices and old-period confirmations cannot silently debit again.
	pay["request_key"] = Secret()
	check(req(uid, "shop/purchase", "POST", pay), 409)
	pay["expected_epoch"] = epoch
	pay["expected_price_cents"] = 1
	check(req(uid, "shop/purchase", "POST", pay), 409)
	// Concurrent independent confirmations for the same period: one success.
	pay["expected_price_cents"] = int64(5000)
	results = make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		copy := map[string]any{}
		for k, v := range pay {
			copy[k] = v
		}
		copy["request_key"] = Secret()
		wg.Add(1)
		go func(body any) { defer wg.Done(); results <- req(uid, "shop/purchase", "POST", body) }(copy)
	}
	wg.Wait()
	close(results)
	success := 0
	for w := range results {
		if w.Code == 200 {
			success++
		} else {
			check(w, 409)
		}
	}
	if success != 1 {
		t.Fatal("stale concurrent checkout accepted", success)
	}
	p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", uid).Scan(&balance)
	if balance != 0 {
		t.Fatal(balance)
	}
	p.QueryRow(ctx, "SELECT quota_epoch FROM users WHERE id=$1", uid).Scan(&epoch)
	pay["request_key"] = Secret()
	pay["expected_epoch"] = epoch
	check(req(uid, "shop/purchase", "POST", pay), 409)
	// Allowances from the retired epoch remain auditable, but do not consume the new quota.
	var node int64
	if e := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); e != nil {
		t.Fatal(e)
	}
	testAuthorize(t, p, uid, node)
	defer p.Exec(ctx, "DELETE FROM rule_usage WHERE node_id=$1", node)
	t.Cleanup(func() {
		p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", node)
		p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	})
	if _, e := p.Exec(ctx, "INSERT INTO grants(node_id,user_id,issued,quota_epoch) VALUES($1,$2,1024,0)", node, uid); e != nil {
		t.Fatal(e)
	}
	stream := &StreamServer{Server: s}
	report := &pb.AgentMessage{InstanceId: Secret(), Usage: []*pb.Usage{{UserId: uid, Spent: 1024, Traffic: 900, QuotaEpoch: 0}}, RequestUsers: []int64{uid}}
	out, e := stream.exchange(ctx, p, node, report)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Users) != 1 || out.Users[0].QuotaEpoch != epoch || out.Users[0].Issued != 1024 {
		t.Fatal("new allowance contaminated by old epoch", out.Users)
	}
	var traffic int64
	p.QueryRow(ctx, "SELECT COALESCE(sum(traffic),0) FROM current_grants WHERE user_id=$1", uid).Scan(&traffic)
	if traffic != 0 {
		t.Fatal("old upload counted as new traffic")
	}
	if _, e = stream.exchange(ctx, p, node, report); e != nil {
		t.Fatal("late report replay rejected", e)
	}
	// Automatic monthly reset is idempotent, and missed months never accumulate quota.
	now := time.Now()
	anchor := addBillingMonths(now, -3)
	next := addBillingMonths(anchor, 1)
	end := addBillingMonths(now, 9)
	if _, e = p.Exec(ctx, "UPDATE users SET reset_anchor_at=$2,next_reset_at=$3,subscription_expires_at=$4,reset_index=1 WHERE id=$1", uid, anchor, next, end); e != nil {
		t.Fatal(e)
	}
	if e = s.resetDueSubscriptions(ctx, now); e != nil {
		t.Fatal(e)
	}
	if e = s.resetDueSubscriptions(ctx, now); e != nil {
		t.Fatal(e)
	}
	var after int64
	p.QueryRow(ctx, "SELECT quota_epoch FROM users WHERE id=$1", uid).Scan(&after)
	if after != epoch+1 {
		t.Fatal("automatic reset ran more than once", after)
	}
}
