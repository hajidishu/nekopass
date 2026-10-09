package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nekopass/nekopass/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type securityFixture struct {
	p                  *pgxpool.Pool
	s                  *Server
	h                  http.Handler
	admin, user, other int64
	plan, otherPlan    int64
	tokens             map[int64]string
}

func newSecurityFixture(t *testing.T) *securityFixture {
	t.Helper()
	p := testDB(t)
	f := &securityFixture{p: p, s: New(p), tokens: map[int64]string{}}
	f.admin, _ = testUser(t, p, 1<<20, 20, true)
	f.user, f.plan = testUser(t, p, 1<<20, 20, false)
	f.other, f.otherPlan = testUser(t, p, 1<<20, 20, false)
	for _, id := range []int64{f.admin, f.user, f.other} {
		f.tokens[id] = Secret()
		if _, err := p.Exec(context.Background(), "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(f.tokens[id]), id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(context.Background(), `UPDATE plans SET prices='{"monthly":1000,"annual":10000}' WHERE id=$1`, f.plan); err != nil {
		t.Fatal(err)
	}
	f.h = f.s.Handler(http.NotFoundHandler())
	return f
}

func (f *securityFixture) raw(actor int64, path, method, body string, customize ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://panel.example.test/api/v1/"+path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.10:40000"
	r.Header.Set("Content-Type", "application/json")
	if actor != 0 {
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: f.tokens[actor]})
	}
	for _, change := range customize {
		change(r)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *securityFixture) request(actor int64, path, method string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	return f.raw(actor, path, method, string(b))
}

func securityStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if w.Code != expected {
		t.Fatalf("unexpected HTTP status: got %d, want %d", w.Code, expected)
	}
}

// Pause immediately after the real database lookup, reproducing a password
// reset between reading the password hash and creating a session without sleeps.
type securityLookupDB struct {
	store.DBTX
	captured, resume chan struct{}
}
type securityLookupRow struct {
	pgx.Row
	captured, resume chan struct{}
}

func (db securityLookupDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := db.DBTX.QueryRow(ctx, sql, args...)
	if strings.Contains(sql, "WHERE username = $1") {
		return securityLookupRow{Row: row, captured: db.captured, resume: db.resume}
	}
	return row
}
func (row securityLookupRow) Scan(dest ...any) error {
	err := row.Row.Scan(dest...)
	if err == nil {
		close(row.captured)
		<-row.resume
	}
	return err
}

func TestSecurityPasswordResetRejectsInflightOldLogin(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	name, oldPassword, newPassword := Secret(), Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)
	if _, err := f.p.Exec(ctx, "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", f.admin, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	captured, resume := make(chan struct{}), make(chan struct{})
	f.s.query = store.New(securityLookupDB{DBTX: f.p, captured: captured, resume: resume})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- f.request(0, "login", "POST", map[string]string{"username": name, "password": oldPassword})
	}()
	select {
	case <-captured:
	case <-time.After(10 * time.Second):
		t.Fatal("login did not reach the password lookup")
	}
	var plan int64
	if err := f.p.QueryRow(ctx, "SELECT plan_id FROM users WHERE id=$1", f.admin).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	w := f.request(f.admin, fmt.Sprintf("admin/users/%d", f.admin), "PUT", UserInput{Username: name, Password: newPassword, Enabled: true, PlanID: plan})
	securityStatus(t, w, 200)
	release()
	select {
	case w = <-result:
		securityStatus(t, w, 401)
	case <-time.After(10 * time.Second):
		t.Fatal("inflight login failed to finish")
	}
	securityStatus(t, f.request(f.admin, "admin/users", "GET", nil), 401)
	var sessions int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id=$1", f.admin).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("old credentials created a session after password reset")
	}
	f.s.query = store.New(f.p)
	securityStatus(t, f.request(0, "login", "POST", map[string]string{"username": name, "password": newPassword}), 200)
}

func TestSecurityLoginAccountFloodAcrossIPs(t *testing.T) {
	f := newSecurityFixture(t)
	name, password := Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, err := f.p.Exec(context.Background(), "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", f.admin, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"username": name, "password": Secret()})
	limited := false
	for i := range 24 {
		w := f.raw(0, "login", "POST", string(b), func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("198.51.100.%d:40000", i+1) })
		if w.Code == 429 {
			limited = true
		} else {
			securityStatus(t, w, 401)
		}
	}
	if !limited {
		t.Fatal("changing source IP bypassed all account brute-force protection")
	}
}

func TestSecurityAdminEndpointsAndCredentialConfusion(t *testing.T) {
	f := newSecurityFixture(t)
	routes := []struct{ method, path string }{
		{"GET", "admin/users"}, {"POST", "admin/users"}, {"PUT", fmt.Sprintf("admin/users/%d", f.admin)},
		{"GET", fmt.Sprintf("admin/users/%d", f.other)}, {"POST", fmt.Sprintf("admin/users/%d/recharge", f.user)},
		{"GET", "admin/settings"}, {"PUT", "admin/settings"}, {"POST", "admin/settings/api-key"}, {"DELETE", "admin/settings/api-key"},
		{"GET", "admin/announcement"}, {"PUT", "admin/announcement"}, {"PUT", "announcement"},
		{"GET", "admin/plans"}, {"POST", "admin/plans"}, {"PUT", fmt.Sprintf("admin/plans/%d", f.plan)}, {"DELETE", fmt.Sprintf("admin/plans/%d", f.plan)},
		{"GET", "admin/nodes"}, {"POST", "admin/nodes"}, {"PUT", "admin/nodes/1"}, {"DELETE", "admin/nodes/1"}, {"POST", "admin/nodes/1/install-command"},
		{"GET", "admin/node-groups"}, {"POST", "admin/node-groups"}, {"PUT", "admin/node-groups/1"}, {"DELETE", "admin/node-groups/1"},
		{"GET", "users"}, {"POST", "users"}, {"PUT", fmt.Sprintf("users/%d", f.admin)}, {"GET", "nodes"}, {"POST", "nodes"}, {"PUT", "nodes/1"},
		{"GET", fmt.Sprintf("admin/users/%d/rules", f.other)}, {"POST", fmt.Sprintf("admin/users/%d/rules", f.other)},
		{"POST", fmt.Sprintf("admin/users/%d/rules/batch", f.other)}, {"POST", fmt.Sprintf("admin/users/%d/rules/import", f.other)},
		{"GET", fmt.Sprintf("admin/users/%d/rule-groups", f.other)},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := f.raw(f.user, route.path, route.method, `{}`, func(r *http.Request) {
				r.Header.Set("X-Is-Admin", "true")
				r.Header.Set("X-User-ID", fmt.Sprint(f.admin))
			})
			if route.path == "users" && route.method == "GET" {
				securityStatus(t, w, 200)
				var users []map[string]any
				if json.Unmarshal(w.Body.Bytes(), &users) != nil || len(users) != 1 || int64(users[0]["id"].(float64)) != f.user {
					t.Fatal("legacy user listing escaped owner scope")
				}
			} else {
				securityStatus(t, w, 403)
			}
			securityStatus(t, f.raw(0, route.path, route.method, `{}`), 401)
		})
	}
	for _, credential := range []string{Secret(), f.tokens[f.other], "admin", "1"} {
		w := f.raw(0, "admin/users", "GET", "", func(r *http.Request) {
			// A user session cannot become a management API key just by changing transport.
			r.Header.Set("Authorization", "Bearer "+credential)
		})
		securityStatus(t, w, 401)
	}
	securityStatus(t, f.raw(f.admin, "admin/users", "POST", `{"username":"fixture","password":"fixture-password-only","enabled":true,"is_admin":true}`), 400)
	securityStatus(t, f.raw(f.user, "shop/purchase", "POST", fmt.Sprintf(`{"plan_id":%d,"cycle":"monthly","balance_cents":999999,"is_admin":true}`, f.plan)), 400)
}

func TestSecurityPurchaseTamperingCannotCreateEntitlementOrMoney(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	if _, err := f.p.Exec(ctx, "UPDATE users SET plan_id=NULL WHERE id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	for _, price := range []int64{-1, 0, 1, 999, 1001, maxMoneyCents} {
		w := f.request(f.user, "shop/purchase", "POST", checkoutInput{PlanID: f.plan, Cycle: "monthly", ExpectedPrice: price, RequestKey: Secret()})
		securityStatus(t, w, 409)
	}
	// Even the correct price cannot create a subscription without sufficient balance.
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", checkoutInput{PlanID: f.plan, Cycle: "monthly", ExpectedPrice: 1000, RequestKey: Secret()}), 409)
	for _, cycle := range []string{"onetime", "reset", "monthly;UPDATE users SET is_admin=true", "MONTHLY"} {
		securityStatus(t, f.request(f.user, "shop/purchase", "POST", checkoutInput{PlanID: f.plan, Cycle: cycle, RequestKey: Secret()}), 400)
	}
	securityStatus(t, f.raw(f.user, "shop/purchase", "POST", fmt.Sprintf(`{"plan_id":%d,"cycle":"monthly","expected_price_cents":9223372036854775808}`, f.plan)), 400)
	securityStatus(t, f.raw(f.user, "shop/purchase", "POST", `{} {}`), 400)
	securityStatus(t, f.raw(f.user, "shop/purchase", "POST", `[]`), 400)
	var plan, epoch, orders, entries, balance int64
	var isAdmin bool
	if err := f.p.QueryRow(ctx, `SELECT COALESCE(plan_id,0),quota_epoch,is_admin,(SELECT count(*) FROM shop_orders WHERE user_id=$1),(SELECT count(*) FROM wallet_entries WHERE user_id=$1),COALESCE((SELECT balance_cents FROM wallet_accounts WHERE user_id=$1),0) FROM users WHERE id=$1`, f.user).Scan(&plan, &epoch, &isAdmin, &orders, &entries, &balance); err != nil {
		t.Fatal(err)
	}
	if plan != 0 || epoch != 0 || isAdmin || orders != 0 || entries != 0 || balance != 0 {
		t.Fatal("rejected requests changed entitlements, balance, privilege or ledger")
	}
}

func TestSecurityConcurrentRechargeAndPurchaseConserveMoney(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	recharge := map[string]string{"amount": "10.00", "note": "security fixture", "request_key": Secret()}
	path := fmt.Sprintf("admin/users/%d/recharge", f.user)
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 24)
	for range 24 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.request(f.admin, path, "POST", recharge) }()
	}
	wg.Wait()
	for range 24 {
		securityStatus(t, <-results, 200)
	}
	var balance, orders, entries int64
	if err := f.p.QueryRow(ctx, `SELECT balance_cents,(SELECT count(*) FROM shop_orders WHERE user_id=$1),(SELECT count(*) FROM wallet_entries WHERE user_id=$1) FROM wallet_accounts WHERE user_id=$1`, f.user).Scan(&balance, &orders, &entries); err != nil || balance != 1000 || orders != 1 || entries != 1 {
		t.Fatal("concurrent replay multiplied a recharge")
	}
	// An ordinary user cannot reuse an administrator's key to credit another wallet.
	securityStatus(t, f.request(f.user, fmt.Sprintf("admin/users/%d/recharge", f.other), "POST", recharge), 403)
	key := Secret()
	for i := range 24 {
		requestKey := key
		if i >= 12 {
			requestKey = Secret()
		}
		pay := checkoutInput{PlanID: f.plan, Cycle: "monthly", ExpectedPrice: 1000, RequestKey: requestKey}
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.request(f.user, "shop/purchase", "POST", pay) }()
	}
	wg.Wait()
	for range 24 {
		w := <-results
		if w.Code != 200 && w.Code != 409 {
			t.Fatalf("concurrent purchase status: %d", w.Code)
		}
	}
	var epoch, ledgerSum int64
	if err := f.p.QueryRow(ctx, `SELECT balance_cents,(SELECT count(*) FROM shop_orders WHERE user_id=$1),(SELECT count(*) FROM wallet_entries WHERE user_id=$1),(SELECT quota_epoch FROM users WHERE id=$1),(SELECT COALESCE(sum(amount_cents),0) FROM wallet_entries WHERE user_id=$1) FROM wallet_accounts WHERE user_id=$1`, f.user).Scan(&balance, &orders, &entries, &epoch, &ledgerSum); err != nil {
		t.Fatal(err)
	}
	if balance != 0 || orders != 2 || entries != 2 || epoch != 1 || ledgerSum != balance {
		t.Fatal("purchase race violated balance/order/ledger/period conservation")
	}
	// Neither unknown fields nor browser Origin forgery can trigger another recharge.
	securityStatus(t, f.raw(f.user, path, "POST", `{}`, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }), 403)
	for _, endpoint := range []string{"wallet", "orders", "profile", "users"} {
		w := f.request(f.other, endpoint, "GET", nil)
		securityStatus(t, w, 200)
		if bytes.Contains(w.Body.Bytes(), []byte("security fixture")) {
			t.Fatal("other user could read the recharge or purchase ledger")
		}
	}
}

func TestSecurityRuleOwnershipAndDisplayResetCannotBypassQuota(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node, forbidden int64
	for _, id := range []*int64{&node, &forbidden} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, id := range []int64{node, forbidden} {
			for _, sql := range []string{"DELETE FROM grants WHERE node_id=$1", "DELETE FROM rule_usage WHERE node_id=$1", "DELETE FROM rules WHERE node_id=$1", "DELETE FROM nodes WHERE id=$1"} {
				f.p.Exec(ctx, sql, id)
			}
		}
	})
	testAuthorize(t, f.p, f.user, node)
	testAuthorize(t, f.p, f.other, node)
	testAuthorize(t, f.p, f.other, forbidden)
	makeRule := func(actor int64) int64 {
		w := f.request(actor, "rules", "POST", RuleInput{UserID: f.admin, NodeID: node, Targets: []string{"127.0.0.1:12345"}, Enabled: true})
		securityStatus(t, w, 200)
		var result struct {
			ID int64 `json:"id"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ID <= 0 {
			t.Fatal("rule was not created")
		}
		var owner int64
		if err := f.p.QueryRow(ctx, "SELECT user_id FROM rules WHERE id=$1", result.ID).Scan(&owner); err != nil || owner != actor {
			t.Fatal("forged user_id changed the owner")
		}
		return result.ID
	}
	own, otherRule := makeRule(f.user), makeRule(f.other)
	w := f.request(f.user, "rules", "GET", nil)
	securityStatus(t, w, 200)
	var rules []map[string]any
	if json.Unmarshal(w.Body.Bytes(), &rules) != nil || len(rules) != 1 || int64(rules[0]["id"].(float64)) != own {
		t.Fatal("rule list exposed another user's rule")
	}
	securityStatus(t, f.request(f.user, fmt.Sprintf("rules/%d", otherRule), "PUT", RuleInput{NodeID: node, Targets: []string{"127.0.0.1:12346"}, Enabled: true}), 400)
	securityStatus(t, f.request(f.user, fmt.Sprintf("rules/%d", otherRule), "DELETE", nil), 403)
	for _, action := range []string{"delete", "enable", "disable", "clear", "group", "switch"} {
		securityStatus(t, f.request(f.user, "rules/batch", "POST", BatchInput{Action: action, IDs: []int64{own, otherRule}, NodeID: forbidden}), 403)
	}
	securityStatus(t, f.request(f.user, "rules", "POST", RuleInput{NodeID: forbidden, Targets: []string{"127.0.0.1:12345"}, Enabled: true}), 400)
	securityStatus(t, f.request(f.user, "rules/batch", "POST", BatchInput{Action: "switch", IDs: []int64{own}, NodeID: forbidden}), 400)
	// Import is atomic: an allowed row followed by an unauthorized one cannot leave a partial rule.
	securityStatus(t, f.request(f.user, "rules/import", "POST", map[string]any{"rules": []RuleInput{
		{NodeID: node, Targets: []string{"127.0.0.1:12345"}, Enabled: true},
		{NodeID: forbidden, Targets: []string{"127.0.0.1:12345"}, Enabled: true},
	}}), 400)
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM rules WHERE user_id=$1", f.user).Scan(&count); err != nil || count != 1 {
		t.Fatal("unauthorized batch/import changed existing rules")
	}
	groupReply := f.request(f.other, "rule-groups", "POST", map[string]any{"name": Secret()})
	securityStatus(t, groupReply, 200)
	var group struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(groupReply.Body.Bytes(), &group)
	securityStatus(t, f.request(f.user, fmt.Sprintf("rule-groups/%d", group.ID), "PUT", map[string]any{"name": Secret()}), 409)
	securityStatus(t, f.request(f.user, fmt.Sprintf("rule-groups/%d", group.ID), "DELETE", nil), 404)
	securityStatus(t, f.request(f.user, "rules/batch", "POST", BatchInput{Action: "group", IDs: []int64{own}, GroupID: group.ID}), 400)
	if _, err := f.p.Exec(ctx, "INSERT INTO grants(node_id,user_id,issued,spent,traffic) VALUES($1,$2,1024,512,400)", node, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE rule_usage SET traffic=400 WHERE node_id=$1 AND rule_id=$2", node, own); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.user, "rules/batch", "POST", BatchInput{Action: "clear", IDs: []int64{own}}), 200)
	var traffic, spent, epoch int64
	if err := f.p.QueryRow(ctx, "SELECT traffic,spent,(SELECT quota_epoch FROM users WHERE id=$2) FROM current_grants WHERE node_id=$1 AND user_id=$2", node, f.user).Scan(&traffic, &spent, &epoch); err != nil || traffic != 400 || spent != 512 || epoch != 0 {
		t.Fatal("display traffic reset removed billed usage or renewed the period")
	}
}

type securityDeleteFailure struct{ store.DBTX }

func (db securityDeleteFailure) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "DELETE FROM sessions") {
		return pgconn.CommandTag{}, errors.New("simulated session storage unavailable")
	}
	return db.DBTX.Exec(ctx, sql, args...)
}

func TestSecurityLogoutFailureIsNotReportedAsSuccess(t *testing.T) {
	f := newSecurityFixture(t)
	f.s.query = store.New(securityDeleteFailure{DBTX: f.p})
	w := f.request(f.user, "logout", "POST", nil)
	securityStatus(t, w, 409)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("logout cleared the browser cookie while the server session remained active")
	}
	securityStatus(t, f.request(f.user, "me", "GET", nil), 200)
	f.s.query = store.New(f.p)
	securityStatus(t, f.request(f.user, "logout", "POST", nil), 200)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 401)
}

func TestSecurityDisableAndPrivilegeRevocationInvalidateAccess(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var name string
	if err := f.p.QueryRow(ctx, "SELECT username FROM users WHERE id=$1", f.user).Scan(&name); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d", f.user), "PUT", UserInput{Username: name, PlanID: f.plan, Enabled: false}), 200)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 401)
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d", f.user), "PUT", UserInput{Username: name, PlanID: f.plan, Enabled: true}), 200)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 401)
	// Fresh requests derive role from the database, not a browser flag or an old login response.
	if _, err := f.p.Exec(ctx, "UPDATE users SET is_admin=false WHERE id=$1", f.admin); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.admin, "admin/users", "GET", nil), 403)
	securityStatus(t, f.request(f.admin, "admin/settings/api-key", "POST", map[string]string{}), 403)
	if _, err := f.p.Exec(ctx, "UPDATE sessions SET expires_at=now()-interval '1 second' WHERE user_id=$1", f.other); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.other, "me", "GET", nil), 401)
}

func TestSecurityCrossSiteMutationsAreRejected(t *testing.T) {
	f := newSecurityFixture(t)
	path := fmt.Sprintf("admin/users/%d/recharge", f.user)
	body, _ := json.Marshal(map[string]string{"amount": "100.00", "request_key": Secret(), "note": "security fixture"})
	for _, origin := range []string{"https://attacker.example", "null", "http://panel.example.test.attacker.example"} {
		securityStatus(t, f.raw(f.admin, path, "POST", string(body), func(r *http.Request) { r.Header.Set("Origin", origin) }), 403)
	}
	for _, site := range []string{"cross-site", "same-site"} {
		securityStatus(t, f.raw(f.admin, path, "POST", string(body), func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", site) }), 403)
	}
	securityStatus(t, f.raw(f.admin, path, "POST", string(body), func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }), 415)
	var count int
	if err := f.p.QueryRow(context.Background(), "SELECT count(*) FROM shop_orders WHERE user_id=$1", f.user).Scan(&count); err != nil || count != 0 {
		t.Fatal("cross-site requests credited the wallet")
	}
}

func TestSecurityLoginForwardedSpoofAndWorkLimits(t *testing.T) {
	f := newSecurityFixture(t)
	name, password := Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, err := f.p.Exec(context.Background(), "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", f.user, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": name, "password": Secret()})
	for i := range 6 {
		w := f.raw(0, "login", "POST", string(body), func(r *http.Request) { r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1)) })
		status := 401
		if i == 5 {
			status = 429
		}
		securityStatus(t, w, status)
	}
	f.s = New(f.p)
	f.h = f.s.Handler(http.NotFoundHandler())
	for range cap(f.s.loginWorkers) {
		f.s.loginWorkers <- struct{}{}
	}
	securityStatus(t, f.raw(0, "login", "POST", string(body)), 429)
	for range cap(f.s.loginWorkers) {
		<-f.s.loginWorkers
	}
	// Bucket storage is bounded even if attackers vary both accounts and source addresses.
	now := time.Now()
	for i := range maxLoginBuckets {
		f.s.allowLogin(fmt.Sprintf("fixture:%d", i), now, 1)
	}
	if len(f.s.loginBuckets) > maxLoginBuckets {
		t.Fatal("login bucket storage is unbounded")
	}
	if !f.s.allowLogin("fixture:after-expiry", now.Add(11*time.Minute), 1) {
		t.Fatal("expired attack buckets continued blocking logins")
	}
}

func TestSecurityNodeAndInstallCredentialsCannotBecomeAdmin(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	nodeReply := f.request(f.admin, "admin/nodes", "POST", map[string]string{"name": Secret()})
	securityStatus(t, nodeReply, 200)
	var node struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(nodeReply.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node.ID) })
	ticket, apiKey := Secret(), Secret()
	settings := SystemSettings{PanelURL: "http://panel.example.test", AgentHost: "control.example.test", AgentPort: 9443, AgentVersion: "v0.7.0", InstallTokenMinutes: 30}
	data, _ := json.Marshal(settings)
	if _, err := f.p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()+interval '1 hour',$3)", Hash(ticket), node.ID, data); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE site_settings SET api_key_hash=$1,api_key_user_id=$2 WHERE id=1", Hash(apiKey), f.admin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "UPDATE site_settings SET api_key_hash='',api_key_user_id=NULL WHERE id=1") })
	for _, key := range []string{node.Token, ticket, f.tokens[f.user]} {
		securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+key) }), 401)
		status := 401
		if key == f.tokens[f.user] {
			status = 403 // This is a real ordinary session, with no administrator authority.
		}
		securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: key}) }), status)
	}
	securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 200)
	securityStatus(t, f.raw(0, "me", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 401)
	securityStatus(t, f.request(f.admin, "admin/settings/api-key", "POST", map[string]string{"key": node.Token}), 400)
	securityStatus(t, f.request(f.admin, "admin/nodes", "POST", map[string]string{"name": Secret(), "token": apiKey}), 400)
	for attempt := range 2 {
		w := f.raw(0, "node-install/redeem", "POST", `{}`, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+ticket) })
		if attempt == 0 {
			securityStatus(t, w, 200)
			var credentials struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(w.Body.Bytes(), &credentials) != nil || credentials.Token != node.Token {
				t.Fatal("installation ticket did not return its own node identity")
			}
		} else {
			securityStatus(t, w, 401)
		}
	}
	// A legacy database can contain an overlap from older versions. Authentication
	// must reject it even if it was not created through the new validation guard.
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET token_hash=$2,token=$3 WHERE id=$1", node.ID, Hash(apiKey), apiKey); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 401)
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET token_hash=$2,token=$3 WHERE id=$1", node.ID, Hash(node.Token), node.Token); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 401)
	// Editing/deleting the node must revoke the old shared management key even
	// when no management-key authentication attempt has yet detected the overlap.
	for _, action := range []string{"edit", "delete"} {
		if _, err := f.p.Exec(ctx, "UPDATE site_settings SET api_key_hash=$1,api_key_user_id=$2 WHERE id=1", Hash(apiKey), f.admin); err != nil {
			t.Fatal(err)
		}
		if _, err := f.p.Exec(ctx, "UPDATE nodes SET token_hash=$2,token=$3,enabled=false WHERE id=$1", node.ID, Hash(apiKey), apiKey); err != nil {
			t.Fatal(err)
		}
		path := fmt.Sprintf("admin/nodes/%d", node.ID)
		if action == "edit" {
			securityStatus(t, f.request(f.admin, path, "PUT", map[string]string{"name": Secret(), "token": Secret()}), 200)
		} else {
			securityStatus(t, f.request(f.admin, path, "DELETE", nil), 200)
		}
		securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 401)
	}
	if _, err := f.p.Exec(ctx, "UPDATE site_settings SET api_key_hash=$1,api_key_user_id=$2 WHERE id=1", Hash(apiKey), f.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Exec(ctx, "UPDATE users SET is_admin=false WHERE id=$1", f.admin); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.raw(0, "admin/users", "GET", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+apiKey) }), 401)
}

func TestSecurityConcurrentCredentialCreationKeepsPrivilegesSeparated(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	key := Secret()
	start := make(chan struct{})
	results := make(chan struct {
		kind string
		w    *httptest.ResponseRecorder
	}, 2)
	for _, kind := range []string{"node", "management"} {
		go func() {
			<-start
			path, body := "admin/settings/api-key", map[string]string{"key": key}
			if kind == "node" {
				path, body = "admin/nodes", map[string]string{"name": Secret(), "token": key}
			}
			results <- struct {
				kind string
				w    *httptest.ResponseRecorder
			}{kind, f.request(f.admin, path, "POST", body)}
		}()
	}
	close(start)
	var nodeID int64
	t.Cleanup(func() {
		f.p.Exec(ctx, "UPDATE site_settings SET api_key_hash='',api_key_user_id=NULL WHERE id=1")
		if nodeID != 0 {
			f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", nodeID)
		}
	})
	winners := 0
	for range 2 {
		result := <-results
		if result.w.Code == 200 {
			winners++
			if result.kind == "node" {
				var node struct {
					ID int64 `json:"id"`
				}
				json.Unmarshal(result.w.Body.Bytes(), &node)
				nodeID = node.ID
			}
		} else {
			securityStatus(t, result.w, 400)
		}
	}
	var overlap bool
	if err := f.p.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes n JOIN site_settings s ON n.token_hash=s.api_key_hash WHERE s.api_key_hash<>'')").Scan(&overlap); err != nil || overlap || winners != 1 {
		t.Fatal("concurrent credential changes produced shared administrator/node privileges")
	}
}

func TestSecurityPurchaseFailureRollsBackEverySideEffect(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	if _, err := f.p.Exec(ctx, "UPDATE users SET plan_id=NULL WHERE id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/recharge", f.user), "POST", map[string]string{"amount": "10.00", "note": "rollback fixture", "request_key": Secret()}), 200)
	// Force a genuine PostgreSQL failure after order creation and wallet debit,
	// scoped to this fixture user. This is never run against a business database.
	name := "security_failure_" + Secret()[:12]
	if _, err := f.p.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated ledger failure'; END $$`, name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON wallet_entries", name))
		f.p.Exec(ctx, fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", name))
	})
	if _, err := f.p.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON wallet_entries FOR EACH ROW WHEN (NEW.user_id=%d AND NEW.kind='purchase') EXECUTE FUNCTION %s()`, name, f.user, name)); err != nil {
		t.Fatal(err)
	}
	body := checkoutInput{PlanID: f.plan, Cycle: "monthly", ExpectedPrice: 1000, RequestKey: Secret()}
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", body), 409)
	var balance, plan, epoch, orders, entries int64
	if err := f.p.QueryRow(ctx, `SELECT balance_cents,(SELECT COALESCE(plan_id,0) FROM users WHERE id=$1),(SELECT quota_epoch FROM users WHERE id=$1),(SELECT count(*) FROM shop_orders WHERE user_id=$1),(SELECT count(*) FROM wallet_entries WHERE user_id=$1) FROM wallet_accounts WHERE user_id=$1`, f.user).Scan(&balance, &plan, &epoch, &orders, &entries); err != nil {
		t.Fatal(err)
	}
	if balance != 1000 || plan != 0 || epoch != 0 || orders != 1 || entries != 1 {
		t.Fatal("failed payment partially charged, granted a plan or consumed an idempotency key")
	}
	if _, err := f.p.Exec(ctx, fmt.Sprintf("DROP TRIGGER %s ON wallet_entries", name)); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", body), 200)
	if err := f.p.QueryRow(ctx, "SELECT balance_cents,(SELECT quota_epoch FROM users WHERE id=$1),(SELECT plan_id FROM users WHERE id=$1) FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance, &epoch, &plan); err != nil || balance != 0 || epoch != 1 || plan != f.plan {
		t.Fatal("retry after rollback did not perform exactly one paid purchase")
	}
}

func TestSecurityPurchaseLimitCannotBeBypassedByRenewalSwitchOrReplay(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	if _, err := f.p.Exec(ctx, `UPDATE plans SET prices='{"monthly":0,"annual":0}',purchase_limit=1 WHERE id=ANY($1::bigint[])`, []int64{f.plan, f.otherPlan}); err != nil {
		t.Fatal(err)
	}
	buy := func(actor, plan, epoch, price int64, cycle, key string) *httptest.ResponseRecorder {
		return f.request(actor, "shop/purchase", "POST", checkoutInput{PlanID: plan, Cycle: cycle, ExpectedEpoch: epoch, ExpectedPrice: price, RequestKey: key})
	}
	first := Secret()
	securityStatus(t, buy(f.user, f.plan, 0, 0, "monthly", first), 200)
	securityStatus(t, buy(f.user, f.plan, 0, 0, "monthly", first), 200) // Replay creates nothing.
	securityStatus(t, buy(f.user, f.plan, 1, 0, "monthly", Secret()), 409)
	securityStatus(t, buy(f.user, f.plan, 1, 0, "annual", Secret()), 409)
	securityStatus(t, f.request(f.user, "shop/quote", "POST", checkoutInput{PlanID: f.plan, Cycle: "monthly"}), 409)
	securityStatus(t, buy(f.user, f.otherPlan, 1, 0, "monthly", Secret()), 200)
	securityStatus(t, buy(f.user, f.plan, 2, 0, "monthly", Secret()), 409) // Switching back retains its count.
	securityStatus(t, buy(f.user, f.plan, 0, 0, "monthly", first), 200)
	securityStatus(t, buy(f.other, f.plan, 0, 0, "monthly", Secret()), 200) // Limits are per user.
	for _, status := range []string{"pending", "cancelled"} {
		key := Secret()
		if _, err := f.p.Exec(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,plan_id,cycle,amount_cents,status,request_key) VALUES($1,$2,'purchase',$3,'monthly',1000,$4,$5)`, Secret(), f.user, f.plan, status, key); err != nil {
			t.Fatal(err)
		}
		securityStatus(t, buy(f.user, f.plan, 2, 1000, "monthly", key), 409)
	}
	w := f.request(f.user, "shop/plans", "GET", nil)
	securityStatus(t, w, 200)
	var plans []struct {
		ID    int64 `json:"id"`
		Limit int   `json:"purchase_limit"`
		Count int   `json:"purchase_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &plans); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, plan := range plans {
		if plan.ID == f.plan {
			found = true
			if plan.Limit != 1 || plan.Count != 1 {
				t.Fatal("pending/cancelled/replayed/other-user orders changed the count")
			}
		}
	}
	if !found {
		t.Fatal("shop did not expose the configured limit")
	}
	var current, epoch int64
	if err := f.p.QueryRow(ctx, "SELECT plan_id,quota_epoch FROM users WHERE id=$1", f.user).Scan(&current, &epoch); err != nil || current != f.otherPlan || epoch != 2 {
		t.Fatal("replayed or rejected purchase changed the active plan or traffic period")
	}
	setLimit := func(limit int) {
		t.Helper()
		monthly, annual := "10.00", "20.00"
		input := PlanInput{Name: Secret(), Enabled: true, QuotaBytes: 1 << 20, MaxRules: 20, MaxConnections: 1000,
			PurchaseLimit: limit, Prices: map[string]*string{"monthly": &monthly, "annual": &annual}}
		securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/plans/%d", f.plan), "PUT", input), 200)
	}
	setLimit(2)
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/recharge", f.user), "POST", map[string]string{"amount": "100.00", "note": "purchase cap fixture", "request_key": Secret()}), 200)
	securityStatus(t, buy(f.user, f.plan, 2, 1000, "monthly", Secret()), 200)
	securityStatus(t, buy(f.user, f.plan, 3, 2000, "annual", Secret()), 409)
	setLimit(0) // Blank/unlimited preserves existing successful order counts.
	securityStatus(t, buy(f.user, f.plan, 3, 1000, "monthly", Secret()), 200)
	securityStatus(t, buy(f.user, f.plan, 4, 2000, "annual", Secret()), 200)
	var balance int64
	if err := f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance); err != nil || balance != 6000 {
		t.Fatal("limit rejection/replay consumed or created wallet funds")
	}
}

func TestSecurityConcurrentFreeClaimRespectsPurchaseLimit(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	if _, err := f.p.Exec(ctx, `UPDATE plans SET prices='{"monthly":0}',purchase_limit=1 WHERE id=$1`, f.plan); err != nil {
		t.Fatal(err)
	}
	results := make(chan *httptest.ResponseRecorder, 24)
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- f.request(f.user, "shop/purchase", "POST", checkoutInput{PlanID: f.plan, Cycle: "monthly", RequestKey: Secret()})
		}()
	}
	wg.Wait()
	winners := 0
	for range 24 {
		w := <-results
		if w.Code == 200 {
			winners++
		} else {
			securityStatus(t, w, 409)
		}
	}
	var epoch, orders int64
	if err := f.p.QueryRow(ctx, "SELECT quota_epoch,(SELECT count(*) FROM shop_orders WHERE user_id=$1 AND plan_id=$2) FROM users WHERE id=$1", f.user, f.plan).Scan(&epoch, &orders); err != nil || epoch != 1 || orders != 1 || winners != 1 {
		t.Fatal("concurrent free requests exceeded the per-user purchase limit")
	}
}
