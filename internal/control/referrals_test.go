package control

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

func TestFirstReferralExcludesFreeOrdersAndRechargeAndIsIdempotent(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.ReferralEnabled = true
	v.ReferralRate = "15"
	v.ReferralMode = "first"
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	f.p.Exec(ctx, "UPDATE users SET inviter_id=$2 WHERE id=$1", f.user, f.other)
	f.p.Exec(ctx, `UPDATE plans SET prices='{"monthly":0}' WHERE id=$1`, f.plan)
	purchase := func(key string) map[string]any {
		t.Helper()
		w := f.request(f.user, "shop/quote", "POST", map[string]any{"plan_id": f.plan, "cycle": "monthly"})
		securityStatus(t, w, 200)
		var q struct {
			Epoch int64 `json:"epoch"`
			Price int64 `json:"amount_cents"`
		}
		json.Unmarshal(w.Body.Bytes(), &q)
		return map[string]any{"plan_id": f.plan, "cycle": "monthly", "expected_epoch": q.Epoch, "expected_price_cents": q.Price, "request_key": key}
	}
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", purchase(Secret())), 200)
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/recharge", f.user), "POST", map[string]string{"amount": "300.00", "note": "referral fixture", "request_key": Secret()}), 200)
	f.p.Exec(ctx, `UPDATE plans SET prices='{"monthly":10000}' WHERE id=$1`, f.plan)
	body := purchase(Secret())
	var wg sync.WaitGroup
	results := make(chan int, 5)
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.request(f.user, "shop/purchase", "POST", body).Code }()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result != 200 {
			t.Fatal("idempotent checkout failed", result)
		}
	}
	var balance, count int64
	f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.other).Scan(&balance)
	f.p.QueryRow(ctx, "SELECT count(*) FROM referral_rewards WHERE invitee_id=$1", f.user).Scan(&count)
	if balance != 1500 || count != 1 {
		t.Fatal("free/recharge counted or repeated rebate", balance, count)
	}
	securityStatus(t, f.request(f.user, "shop/purchase", "POST", purchase(Secret())), 200)
	f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.other).Scan(&balance)
	if balance != 1500 {
		t.Fatal("first-mode paid twice")
	}
	w := f.request(f.other, "orders", "GET", nil)
	securityStatus(t, w, 200)
	var orders struct {
		Items []struct {
			Kind   string `json:"kind"`
			Amount int64  `json:"amount_cents"`
		} `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &orders)
	if len(orders.Items) != 1 || orders.Items[0].Kind != "rebate" || orders.Items[0].Amount != 1500 {
		t.Fatal("rebate not mixed into orders")
	}
}

func TestReferralIndividualOverridesAndGlobalSwitch(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	v := defaultSettings()
	v.ReferralEnabled = true
	v.ReferralMode = "first"
	v.ReferralRate = "15"
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	f.p.Exec(ctx, "UPDATE users SET inviter_id=$2 WHERE id=$1", f.user, f.other)
	f.p.Exec(ctx, "UPDATE users SET referral_mode='recurring',referral_rate_bps=2500 WHERE id=$1", f.other)
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/recharge", f.user), "POST", map[string]string{"amount": "100.00", "note": "referral fixture", "request_key": Secret()}), 200)
	buy := func() {
		w := f.request(f.user, "shop/quote", "POST", map[string]any{"plan_id": f.plan, "cycle": "monthly"})
		securityStatus(t, w, 200)
		var q map[string]any
		json.Unmarshal(w.Body.Bytes(), &q)
		securityStatus(t, f.request(f.user, "shop/purchase", "POST", map[string]any{"plan_id": f.plan, "cycle": "monthly", "expected_epoch": q["epoch"], "expected_price_cents": q["amount_cents"], "request_key": Secret()}), 200)
	}
	buy()
	buy()
	var balance int64
	f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.other).Scan(&balance)
	if balance != 500 {
		t.Fatal("personal rate/mode ignored", balance)
	}
	f.p.Exec(ctx, "UPDATE users SET referral_enabled=false WHERE id=$1", f.other)
	buy()
	f.p.Exec(ctx, "UPDATE users SET referral_enabled=true WHERE id=$1", f.other)
	v.ReferralEnabled = false
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	buy()
	f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.other).Scan(&balance)
	if balance != 500 {
		t.Fatal("disabled referral paid")
	}
	w := f.request(f.other, "referrals", "GET", nil)
	securityStatus(t, w, 200)
	var data map[string]any
	json.Unmarshal(w.Body.Bytes(), &data)
	if data["enabled"] != false || data["message"] != "此站点未开启邀请返利功能" {
		t.Fatal("global disabled UI response")
	}
	if _, ok := data["smtp"]; ok {
		t.Fatal("settings secrets exposed")
	}
}
