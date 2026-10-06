package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nekopass/nekopass/internal/payment"
	"github.com/nekopass/nekopass/internal/payment/epay"
)

func paymentFixture(t *testing.T) (*securityFixture, int64, payment.Config) {
	t.Helper()
	f := newSecurityFixture(t)
	ctx := context.Background()
	var old []byte
	if e := f.p.QueryRow(ctx, "SELECT config FROM site_settings WHERE id=1").Scan(&old); e != nil {
		t.Fatal(e)
	}
	if _, e := f.p.Exec(ctx, `UPDATE site_settings SET config=config||'{"panel_url":"https://panel.example.test"}'::jsonb WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", old) })
	config := payment.Config{"url": "https://payment.example.test/", "pid": "1001", "key": "fixture-epay-key-not-real", "type": "alipay"}
	response := f.request(f.admin, "admin/payment-methods", "POST", map[string]any{"name": "fixture online payment", "interface": "epay", "config": config, "enabled": true, "sort_order": 0})
	securityStatus(t, response, 200)
	var result struct{ ID int64 }
	if e := json.Unmarshal(response.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM payment_methods WHERE id=$1", result.ID) })
	return f, result.ID, config
}

type rechargeResult struct {
	ID       int64
	OrderNo  string `json:"order_no"`
	Status   string
	Checkout payment.Checkout
}

func createPayment(t *testing.T, f *securityFixture, method int64, amount, key string) rechargeResult {
	t.Helper()
	response := f.request(f.user, "wallet/recharge", "POST", map[string]any{"payment_method_id": method, "amount": amount, "request_key": key})
	securityStatus(t, response, 200)
	var result rechargeResult
	if e := json.Unmarshal(response.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	return result
}
func paymentValues(config payment.Config, order rechargeResult, trade string) url.Values {
	v := url.Values{"pid": {config["pid"]}, "type": {config["type"]}, "out_trade_no": {order.OrderNo}, "trade_no": {trade}, "name": {"Nekopass 余额充值"}, "money": {"10.00"}, "trade_status": {"TRADE_SUCCESS"}, "sign_type": {"MD5"}}
	v.Set("sign", epay.Sign(config, v))
	return v
}
func notifyPayment(f *securityFixture, method int64, v url.Values, post bool) *httptest.ResponseRecorder {
	endpoint := fmt.Sprintf("http://panel.example.test/api/v1/payments/notify/epay/%d", method)
	var r *http.Request
	if post {
		r = httptest.NewRequest("POST", endpoint, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://payment.example.test")
	} else {
		r = httptest.NewRequest("GET", endpoint+"?"+v.Encode(), nil)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}
func TestPaymentCreationAuthorizationPrivacyAndVerifiedCredit(t *testing.T) {
	f, method, config := paymentFixture(t)
	ctx := context.Background()
	securityStatus(t, f.request(f.user, "admin/payment-methods", "GET", nil), 403)
	securityStatus(t, f.request(f.user, "admin/payment-methods", "POST", map[string]any{}), 403)
	securityStatus(t, f.request(f.user, "admin/payment-interfaces", "GET", nil), 403)
	wallet := f.request(f.user, "wallet", "GET", nil)
	securityStatus(t, wallet, 200)
	if strings.Contains(wallet.Body.String(), config["key"]) || strings.Contains(wallet.Body.String(), "payment.example.test") {
		t.Fatal("merchant configuration leaked")
	}
	key := Secret()
	order := createPayment(t, f, method, "10.00", key)
	repeated := createPayment(t, f, method, "10.00", key)
	if order.ID != repeated.ID || order.Status != "pending" {
		t.Fatal("request replay creates new order")
	}
	securityStatus(t, f.request(f.user, "wallet/recharge", "POST", map[string]any{"payment_method_id": method, "amount": "20.00", "request_key": key}), 409)
	securityStatus(t, f.request(f.user, "wallet/recharge", "POST", map[string]any{"payment_method_id": method, "amount": "1.00", "request_key": Secret()}), 400)
	securityStatus(t, f.request(f.other, fmt.Sprintf("orders/%d/pay", order.ID), "POST", map[string]any{}), 404)
	securityStatus(t, f.request(f.user, fmt.Sprintf("orders/%d/pay", order.ID), "POST", map[string]any{}), 200)
	r := httptest.NewRequest("GET", "http://panel.example.test/api/v1/payments/return?trade_status=TRADE_SUCCESS", nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	securityStatus(t, w, 303)
	var balance int64
	if e := f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance); e != nil || balance != 0 {
		t.Fatal("submission or browser return credited funds", e)
	}
	for _, field := range []string{"money", "pid", "type", "out_trade_no", "trade_status"} {
		v := paymentValues(config, order, "fixture-trade")
		v.Set(field, "incorrect")
		v.Set("sign", epay.Sign(config, v))
		if response := notifyPayment(f, method, v, false); response.Code == 200 {
			t.Fatal("wrong callback field accepted", field)
		}
	}
	v := paymentValues(config, order, "fixture-trade")
	v.Set("money", "20.00")
	v.Set("sign", epay.Sign(config, v))
	if notifyPayment(f, method, v, false).Code == 200 {
		t.Fatal("signed incorrect amount accepted")
	}
	v = paymentValues(config, order, "fixture-trade")
	v.Set("sign", "invalid")
	if notifyPayment(f, method, v, false).Code == 200 {
		t.Fatal("forged signature accepted")
	}
	v = paymentValues(config, order, "fixture-trade")
	v.Add("money", "10.00")
	if notifyPayment(f, method, v, false).Code == 200 {
		t.Fatal("duplicate amount accepted")
	}
	v = paymentValues(config, order, "fixture-trade")
	results := make(chan *httptest.ResponseRecorder, 12)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- notifyPayment(f, method, v, i%2 == 0) }()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.Code != 200 || result.Body.String() != "success" {
			t.Fatalf("valid callback response %d", result.Code)
		}
	}
	var count, paid int64
	if e := f.p.QueryRow(ctx, "SELECT balance_cents,(SELECT count(*) FROM wallet_entries WHERE order_id=$2),(SELECT count(*) FROM shop_orders WHERE id=$2 AND status='paid') FROM wallet_accounts WHERE user_id=$1", f.user, order.ID).Scan(&balance, &count, &paid); e != nil || balance != 1000 || count != 1 || paid != 1 {
		t.Fatal("callback repeated or partially credited", e)
	}
	orders := f.request(f.user, "orders", "GET", nil)
	if strings.Contains(orders.Body.String(), config["key"]) || strings.Contains(orders.Body.String(), "submit.php") {
		t.Fatal("private attempt data leaked to user orders")
	}
	securityStatus(t, f.request(f.user, fmt.Sprintf("orders/%d/pay", order.ID), "POST", map[string]any{}), 409)
}
func TestPaymentSnapshotDeletionAndCrossMethodTransactionReplay(t *testing.T) {
	f, method, config := paymentFixture(t)
	ctx := context.Background()
	one := createPayment(t, f, method, "10.00", Secret())
	secondConfig := payment.Config{}
	for k, v := range config {
		secondConfig[k] = v
	}
	secondConfig["key"] = "fixture-second-merchant-key"
	secondConfig["url"] = "https://payment.example.test/submit.php"
	response := f.request(f.admin, "admin/payment-methods", "POST", map[string]any{"name": "fixture second method", "interface": "epay", "config": secondConfig, "enabled": true})
	securityStatus(t, response, 200)
	var second struct{ ID int64 }
	json.Unmarshal(response.Body.Bytes(), &second)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM payment_methods WHERE id=$1", second.ID) })
	two := createPayment(t, f, second.ID, "10.00", Secret())
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/payment-methods/%d", method), "DELETE", map[string]any{}), 200)
	if response = notifyPayment(f, method, paymentValues(config, one, "fixture-shared-trade"), false); response.Code != 200 {
		t.Fatal("deleting method broke existing order")
	}
	if response = notifyPayment(f, second.ID, paymentValues(secondConfig, two, "fixture-shared-trade"), false); response.Code == 200 {
		t.Fatal("transaction reused across method IDs or key changes")
	}
	if response = notifyPayment(f, second.ID, paymentValues(secondConfig, two, "fixture-second-trade"), false); response.Code != 200 {
		t.Fatal("distinct valid transaction rejected")
	}
	var balance int64
	if e := f.p.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance); e != nil || balance != 2000 {
		t.Fatal("invalid final balance", e)
	}
}

func TestPaymentCreditConcurrentWithWalletPurchase(t *testing.T) {
	f, method, config := paymentFixture(t)
	ctx := context.Background()
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/users/%d/recharge", f.user), "POST", map[string]string{"amount": "10.00", "note": "fixture initial balance", "request_key": Secret()}), 200)
	order := createPayment(t, f, method, "10.00", Secret())
	v := paymentValues(config, order, "fixture-parallel-trade")
	quoteResponse := f.request(f.user, "shop/quote", "POST", map[string]any{"plan_id": f.plan, "cycle": "monthly"})
	securityStatus(t, quoteResponse, 200)
	var quote struct {
		Epoch int64 `json:"epoch"`
	}
	json.Unmarshal(quoteResponse.Body.Bytes(), &quote)
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 9)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- notifyPayment(f, method, v, false) }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- f.request(f.user, "shop/purchase", "POST", map[string]any{"plan_id": f.plan, "cycle": "monthly", "expected_price_cents": 1000, "expected_epoch": quote.Epoch, "request_key": Secret()})
	}()
	wg.Wait()
	close(results)
	for result := range results {
		securityStatus(t, result, 200)
	}
	var balance, sum int64
	if e := f.p.QueryRow(ctx, "SELECT balance_cents,(SELECT sum(amount_cents) FROM wallet_entries WHERE user_id=$1) FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance, &sum); e != nil || balance != 1000 || sum != balance {
		t.Fatal("concurrent credit/debit lost money", e)
	}
}

func TestPaymentLedgerFailureRollsBackAndAllowsRetry(t *testing.T) {
	f, method, config := paymentFixture(t)
	ctx := context.Background()
	order := createPayment(t, f, method, "10.00", Secret())
	name := "paymentfail_" + Secret()[:10]
	_, e := f.p.Exec(ctx, fmt.Sprintf("CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated payment ledger failure'; END $$", name))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON wallet_entries", name))
		f.p.Exec(ctx, fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", name))
	})
	_, e = f.p.Exec(ctx, fmt.Sprintf("CREATE TRIGGER %s BEFORE INSERT ON wallet_entries FOR EACH ROW WHEN (NEW.order_id=%d) EXECUTE FUNCTION %s()", name, order.ID, name))
	if e != nil {
		t.Fatal(e)
	}
	v := paymentValues(config, order, "fixture-rollback-trade")
	if notifyPayment(f, method, v, false).Code == 200 {
		t.Fatal("failed ledger write acknowledged")
	}
	var balance int64
	var status string
	var trade *string
	e = f.p.QueryRow(ctx, "SELECT w.balance_cents,o.status,a.gateway_trade_no FROM wallet_accounts w JOIN shop_orders o ON o.user_id=w.user_id JOIN payment_attempts a ON a.order_id=o.id WHERE o.id=$1", order.ID).Scan(&balance, &status, &trade)
	if e != nil || balance != 0 || status != "pending" || trade != nil {
		t.Fatal("partial payment commit", e)
	}
	if _, e = f.p.Exec(ctx, fmt.Sprintf("DROP TRIGGER %s ON wallet_entries", name)); e != nil {
		t.Fatal(e)
	}
	if notifyPayment(f, method, v, false).Code != 200 {
		t.Fatal("notification retry after rollback rejected")
	}
}

func TestPaymentMethodPaginationHasNoSmallCountLimit(t *testing.T) {
	f, _, config := paymentFixture(t)
	ctx := context.Background()
	ids := []int64{}
	t.Cleanup(func() {
		for _, id := range ids {
			f.p.Exec(ctx, "DELETE FROM payment_methods WHERE id=$1", id)
		}
	})
	for i := range 55 {
		response := f.request(f.admin, "admin/payment-methods", "POST", map[string]any{"name": fmt.Sprintf("fixture method %d", i), "interface": "epay", "config": config})
		securityStatus(t, response, 200)
		var result struct{ ID int64 }
		json.Unmarshal(response.Body.Bytes(), &result)
		ids = append(ids, result.ID)
	}
	response := f.request(f.admin, "admin/payment-methods?page=2", "GET", nil)
	securityStatus(t, response, 200)
	var result struct {
		Total int
		Items []map[string]any
	}
	json.Unmarshal(response.Body.Bytes(), &result)
	if result.Total != 56 || len(result.Items) != 6 {
		t.Fatal("methods cannot be managed past first page")
	}
	wallet := f.request(f.user, "wallet", "GET", nil)
	var public struct {
		Methods []map[string]any `json:"payment_channels"`
	}
	json.Unmarshal(wallet.Body.Bytes(), &public)
	if len(public.Methods) != 56 {
		t.Fatal("enabled methods missing from user wallet")
	}
	for _, method := range public.Methods {
		if len(method) != 2 {
			t.Fatal("merchant settings leaked")
		}
	}
}

func TestCancelledPaymentCannotBeResumedOrCredited(t *testing.T) {
	f, method, config := paymentFixture(t)
	key := Secret()
	order := createPayment(t, f, method, "10.00", key)
	if _, e := f.p.Exec(context.Background(), "UPDATE shop_orders SET status='cancelled' WHERE id=$1", order.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.s.resolvePaymentCheckout(context.Background(), order.ID); e == nil {
		t.Fatal("cached checkout bypasses cancelled state")
	}
	securityStatus(t, f.request(f.user, "wallet/recharge", "POST", map[string]any{"payment_method_id": method, "amount": "10.00", "request_key": key}), 409)
	securityStatus(t, f.request(f.user, fmt.Sprintf("orders/%d/pay", order.ID), "POST", map[string]any{}), 409)
	if notifyPayment(f, method, paymentValues(config, order, "fixture-cancelled-trade"), false).Code == 200 {
		t.Fatal("cancelled order credited")
	}
}

type scriptedPaymentDriver struct {
	epay.Driver
	create func(context.Context, payment.Config, payment.Order) (payment.Checkout, error)
}

func (d scriptedPaymentDriver) Create(ctx context.Context, c payment.Config, o payment.Order) (payment.Checkout, error) {
	return d.create(ctx, c, o)
}

func TestPaymentNotificationCanArriveDuringGatewayCreation(t *testing.T) {
	f, method, config := paymentFixture(t)
	f.s.payments = payment.NewRegistry(scriptedPaymentDriver{create: func(ctx context.Context, c payment.Config, o payment.Order) (payment.Checkout, error) {
		values := paymentValues(config, rechargeResult{OrderNo: o.Number}, "fixture-early-notification")
		req := httptest.NewRequest("GET", fmt.Sprintf("http://panel.example.test/api/v1/payments/notify/epay/%d?%s", method, values.Encode()), nil).WithContext(ctx)
		response := httptest.NewRecorder()
		f.h.ServeHTTP(response, req)
		if response.Code != 200 {
			return payment.Checkout{}, errors.New("early payment notification was not accepted")
		}
		return (epay.Driver{}).Create(ctx, c, o)
	}})
	order := createPayment(t, f, method, "10.00", Secret())
	if order.Status != "paid" {
		t.Fatal("early callback not reflected in creation response")
	}
	var balance int64
	if e := f.p.QueryRow(context.Background(), "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1", f.user).Scan(&balance); e != nil || balance != 1000 {
		t.Fatal("early callback could not credit wallet", e)
	}
}

func TestGatewayCreationRetryPreservesOrderAndCredentials(t *testing.T) {
	f, method, _ := paymentFixture(t)
	numbers := []string{}
	f.s.payments = payment.NewRegistry(scriptedPaymentDriver{create: func(ctx context.Context, c payment.Config, o payment.Order) (payment.Checkout, error) {
		numbers = append(numbers, o.Number)
		if len(numbers) == 1 {
			return payment.Checkout{}, errors.New("simulated checkout timeout")
		}
		return (epay.Driver{}).Create(ctx, c, o)
	}})
	key := Secret()
	body := map[string]any{"payment_method_id": method, "amount": "10.00", "request_key": key}
	securityStatus(t, f.request(f.user, "wallet/recharge", "POST", body), 503)
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/payment-methods/%d", method), "DELETE", map[string]any{}), 200)
	order := createPayment(t, f, method, "10.00", key)
	if len(numbers) != 2 || numbers[0] != numbers[1] || order.Status != "pending" {
		t.Fatal("retry changed the merchant reference")
	}
	var count int
	if e := f.p.QueryRow(context.Background(), "SELECT count(*) FROM shop_orders WHERE user_id=$1", f.user).Scan(&count); e != nil || count != 1 {
		t.Fatal("retry created orphan or duplicate orders", e)
	}
}

func TestConcurrentPaymentRequestsCreateOneOrder(t *testing.T) {
	f, method, _ := paymentFixture(t)
	key := Secret()
	body := map[string]any{"payment_method_id": method, "amount": "10.00", "request_key": key}
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 12)
	for range 12 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- f.request(f.user, "wallet/recharge", "POST", body) }()
	}
	wg.Wait()
	close(results)
	var expected int64
	for response := range results {
		securityStatus(t, response, 200)
		var order rechargeResult
		if e := json.Unmarshal(response.Body.Bytes(), &order); e != nil {
			t.Fatal(e)
		}
		if expected == 0 {
			expected = order.ID
		}
		if order.ID != expected {
			t.Fatal("concurrent retries created separate orders")
		}
	}
	var count, balance int64
	if e := f.p.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM shop_orders WHERE user_id=$1),(SELECT balance_cents FROM wallet_accounts WHERE user_id=$1)", f.user).Scan(&count, &balance); e != nil || count != 1 || balance != 0 {
		t.Fatal("creating orders altered wallet or duplicated order", e)
	}
}

func TestSameTransactionCannotCreditTwoUsersConcurrently(t *testing.T) {
	f, method, config := paymentFixture(t)
	one := createPayment(t, f, method, "10.00", Secret())
	response := f.request(f.other, "wallet/recharge", "POST", map[string]any{"payment_method_id": method, "amount": "10.00", "request_key": Secret()})
	securityStatus(t, response, 200)
	var two rechargeResult
	if e := json.Unmarshal(response.Body.Bytes(), &two); e != nil {
		t.Fatal(e)
	}
	values := []url.Values{paymentValues(config, one, "fixture-cross-user-trade"), paymentValues(config, two, "fixture-cross-user-trade")}
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, v := range values {
		wg.Add(1)
		go func() { defer wg.Done(); results <- notifyPayment(f, method, v, false) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for result := range results {
		if result.Code == 200 {
			success++
		}
	}
	var total, count int64
	if e := f.p.QueryRow(context.Background(), "SELECT (SELECT sum(balance_cents) FROM wallet_accounts WHERE user_id=ANY($1::bigint[])),(SELECT count(*) FROM wallet_entries WHERE user_id=ANY($1::bigint[]))", []int64{f.user, f.other}).Scan(&total, &count); e != nil || success != 1 || total != 1000 || count != 1 {
		t.Fatal("shared transaction multiplied funds across wallets", e)
	}
}

func TestPaymentNotificationRejectsInvalidSnapshotCredentials(t *testing.T) {
	f, method, config := paymentFixture(t)
	order := createPayment(t, f, method, "10.00", Secret())
	config["key"] = ""
	data, _ := json.Marshal(config)
	if _, e := f.p.Exec(context.Background(), "UPDATE payment_attempts SET config=$2 WHERE order_id=$1", order.ID, data); e != nil {
		t.Fatal(e)
	}
	if notifyPayment(f, method, paymentValues(config, order, "fixture-empty-key"), false).Code == 200 {
		t.Fatal("missing snapshot key authorized payment")
	}
}
