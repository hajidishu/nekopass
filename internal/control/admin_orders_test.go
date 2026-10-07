package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdministratorOrderFiltersPermissionsAndPrivatePaymentConfig(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	prefix := Secret()[:12]
	mail := "buyer-" + prefix + "@example.test"
	f.p.Exec(ctx, "UPDATE users SET username=$2 WHERE id=$1", f.user, mail)
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, billingZone)
	ids := []int64{}
	types := []string{"purchase", "renewal", "recharge", "rebate", "recharge"}
	statuses := []string{"paid", "paid", "pending", "paid", "cancelled"}
	for i, kind := range types {
		uid := f.user
		if i >= 3 {
			uid = f.other
		}
		var paid *time.Time
		if statuses[i] == "paid" {
			value := base.Add(time.Duration(i+1) * 24 * time.Hour)
			paid = &value
		}
		var id int64
		err := f.p.QueryRow(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,amount_cents,status,request_key,snapshot,created_at,paid_at) VALUES($1,$2,$3,10000,$4,$5,'{"note":"order-query-fixture"}',$6,$7) RETURNING id`, prefix+fmt.Sprint(i), uid, kind, statuses[i], Secret(), base.Add(time.Duration(i)*24*time.Hour), paid).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	privateKey := Secret()
	config, _ := json.Marshal(map[string]string{"key": privateKey})
	if _, err := f.p.Exec(ctx, "INSERT INTO payment_attempts(order_id,method_id,interface,config,account_scope,create_context,gateway_trade_no) VALUES($1,1,'epay',$2,$3,'{}',$4)", ids[2], config, Secret(), "gateway-"+prefix); err != nil {
		t.Fatal(err)
	}
	query := func(values url.Values) ([]map[string]any, int64) {
		t.Helper()
		w := f.request(f.admin, "admin/orders?"+values.Encode(), "GET", nil)
		securityStatus(t, w, 200)
		if strings.Contains(w.Body.String(), privateKey) {
			t.Fatal("payment credentials leaked")
		}
		var result struct {
			Items []map[string]any `json:"items"`
			Total int64            `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Items, result.Total
	}
	items, total := query(url.Values{"order_no": {prefix}})
	if total != 5 || len(items) != 5 {
		t.Fatal("all-order query wrong", total, len(items))
	}
	items, total = query(url.Values{"email": {strings.ToUpper(mail)}, "kind": {"recharge"}, "status": {"pending"}})
	if total != 1 || int64(items[0]["id"].(float64)) != ids[2] {
		t.Fatal("combined email/type/status query wrong")
	}
	items, total = query(url.Values{"order_no": {prefix}, "time_field": {"created"}, "from": {base.Add(24 * time.Hour).Format(time.RFC3339)}, "to": {base.Add(24 * time.Hour).Format(time.RFC3339)}})
	if total != 1 || int64(items[0]["id"].(float64)) != ids[1] {
		t.Fatal("creation time/boundaries wrong")
	}
	items, total = query(url.Values{"order_no": {prefix}, "time_field": {"paid"}, "from": {base.Add(24 * time.Hour).UTC().Format(time.RFC3339)}, "to": {base.Add(24 * time.Hour).UTC().Format(time.RFC3339)}})
	if total != 1 || int64(items[0]["id"].(float64)) != ids[0] {
		t.Fatal("paid time/timezone wrong")
	}
	_, total = query(url.Values{"gateway_trade_no": {"gateway-" + prefix}})
	if total != 1 {
		t.Fatal("provider transaction query wrong")
	}
	f.p.Exec(ctx, "UPDATE users SET username=$2 WHERE id=$1", f.user, "renamed-"+prefix+"@example.test")
	_, total = query(url.Values{"user_id": {formatID(f.user)}})
	if total != 3 {
		t.Fatal("user ID filter lost renamed account")
	}
	_, total = query(url.Values{"order_no": {"' OR 1=1 --"}})
	if total != 0 {
		t.Fatal("SQL injection widened search")
	}
	_, total = query(url.Values{"email": {"%"}})
	if total != 0 {
		t.Fatal("search wildcard expanded unexpectedly")
	}
	items, total = query(url.Values{"order_no": {prefix}, "page": {"2"}})
	if total != 5 || len(items) != 0 {
		t.Fatal("pagination not bounded")
	}
	for _, id := range ids {
		w := f.request(f.admin, "admin/orders/"+formatID(id), "GET", nil)
		securityStatus(t, w, 200)
		if strings.Contains(w.Body.String(), privateKey) || strings.Contains(w.Body.String(), "create_context") || strings.Contains(w.Body.String(), "account_scope") {
			t.Fatal("order detail includes private provider metadata")
		}
	}
	securityStatus(t, f.request(f.user, "admin/orders", "GET", nil), 403)
	securityStatus(t, f.request(f.user, "admin/orders/"+formatID(ids[3]), "GET", nil), 403)
	securityStatus(t, f.request(0, "admin/orders", "GET", nil), 401)
	securityStatus(t, f.request(f.admin, "admin/orders/9999999999", "GET", nil), 404)
	w := f.request(f.user, "orders?user_id="+formatID(f.other), "GET", nil)
	securityStatus(t, w, 200)
	var own struct {
		Total int64 `json:"total"`
	}
	json.Unmarshal(w.Body.Bytes(), &own)
	if own.Total != 3 {
		t.Fatal("user endpoint adopted administrator filter")
	}
}

func TestAdministratorOrderFilterValidation(t *testing.T) {
	for _, query := range []string{"user_id=-1", "user_id=0", "user_id=bad", "kind=other", "status=unknown", "time_field=invalid", "from=bad", "page=0", "page=100001", "page=bad", "from=2026-09-02T00%3A00%3A00Z&to=2026-09-01T00%3A00%3A00Z", "email=" + strings.Repeat("a", 255)} {
		if _, err := parseAdminOrderFilter(httptest.NewRequest("GET", "http://example.test/api/v1/admin/orders?"+query, nil)); err == nil {
			t.Fatal("invalid filter accepted", query)
		}
	}
}
