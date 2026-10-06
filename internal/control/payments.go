package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/payment"
)

func paymentDBError(w http.ResponseWriter) {
	slog.Error("payment database operation failed")
	fail(w, 503, "支付服务暂时不可用，请稍后重试")
}
func paymentCallbackPath(r *http.Request) bool {
	if r.Method != "GET" && r.Method != "POST" {
		return false
	}
	prefix := "/api/v1/payments/notify/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) != 2 {
		return false
	}
	id, e := strconv.ParseInt(parts[1], 10, 64)
	return e == nil && id > 0 && parts[0] != ""
}
func (s *Server) paymentInterfaces(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	writeJSON(w, 200, s.payments.Definitions())
}
func (s *Server) paymentMethods(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		fail(w, 400, "页码无效")
		return
	}
	var total int64
	if e := s.Pool.QueryRow(r.Context(), "SELECT count(*) FROM payment_methods").Scan(&total); e != nil {
		paymentDBError(w)
		return
	}
	rows, e := s.Pool.Query(r.Context(), "SELECT id,name,interface,config,enabled,sort_order FROM payment_methods ORDER BY sort_order,id LIMIT 50 OFFSET $1", (page-1)*50)
	if e != nil {
		paymentDBError(w)
		return
	}
	methods, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		paymentDBError(w)
		return
	}
	if methods == nil {
		methods = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"items": methods, "total": total, "page": page})
}
func (s *Server) savePaymentMethod(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var input struct {
		Name      string         `json:"name"`
		Interface string         `json:"interface"`
		Config    payment.Config `json:"config"`
		Enabled   bool           `json:"enabled"`
		SortOrder int            `json:"sort_order"`
	}
	input.Enabled = true
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len([]rune(input.Name)) > 80 || strings.ContainsAny(input.Name, "\r\n\x00") || input.SortOrder < -1000000 || input.SortOrder > 1000000 {
		fail(w, 400, "支付方式名称或排序无效")
		return
	}
	driver, e := s.payments.Driver(input.Interface)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if e = driver.Validate(input.Config); e != nil {
		fail(w, 400, e.Error())
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	data, _ := json.Marshal(input.Config)
	if id == 0 {
		e = s.Pool.QueryRow(r.Context(), "INSERT INTO payment_methods(name,interface,config,enabled,sort_order) VALUES($1,$2,$3,$4,$5) RETURNING id", input.Name, input.Interface, data, input.Enabled, input.SortOrder).Scan(&id)
	} else {
		tag, err := s.Pool.Exec(r.Context(), "UPDATE payment_methods SET name=$2,interface=$3,config=$4,enabled=$5,sort_order=$6,updated_at=now() WHERE id=$1", id, input.Name, input.Interface, data, input.Enabled, input.SortOrder)
		e = err
		if e == nil && tag.RowsAffected() == 0 {
			fail(w, 404, "支付方式不存在")
			return
		}
	}
	if e != nil {
		paymentDBError(w)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}
func (s *Server) deletePaymentMethod(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	tag, e := s.Pool.Exec(r.Context(), "DELETE FROM payment_methods WHERE id=$1", id)
	if e != nil {
		paymentDBError(w)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "支付方式不存在")
		return
	}
	writeJSON(w, 200, map[string]bool{"deleted": true})
}
func (s *Server) publicPaymentMethods(ctx context.Context) ([]map[string]any, error) {
	rows, e := s.Pool.Query(ctx, "SELECT id,name FROM payment_methods WHERE enabled ORDER BY sort_order,id")
	if e != nil {
		return nil, e
	}
	methods, e := pgx.CollectRows(rows, pgx.RowToMap)
	if methods == nil {
		methods = []map[string]any{}
	}
	return methods, e
}

func (s *Server) createRecharge(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MethodID   int64  `json:"payment_method_id"`
		Amount     string `json:"amount"`
		RequestKey string `json:"request_key"`
	}
	if !decode(w, r, &input) {
		return
	}
	cents, e := parseMoney(input.Amount)
	if e != nil || cents < 1000 || input.MethodID <= 0 || !requestKeyPattern.MatchString(input.RequestKey) {
		fail(w, 400, "请选择支付方式，充值金额至少为 10 元")
		return
	}
	ctx := r.Context()
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		paymentDBError(w)
		return
	}
	defer tx.Rollback(ctx)
	uid := current(r).ID
	var exists int64
	if e = tx.QueryRow(ctx, "SELECT id FROM users WHERE id=$1 AND enabled FOR UPDATE", uid).Scan(&exists); e != nil {
		fail(w, 403, "账号不可用")
		return
	}
	balance, e := walletBalanceLocked(ctx, tx, uid)
	if e != nil {
		paymentDBError(w)
		return
	}
	var id, oldAmount, oldMethod int64
	var kind, status string
	var checkoutData []byte
	e = tx.QueryRow(ctx, `SELECT o.id,o.amount_cents,o.kind,o.status,COALESCE(a.method_id,0),a.checkout FROM shop_orders o LEFT JOIN payment_attempts a ON a.order_id=o.id WHERE o.user_id=$1 AND o.request_key=$2`, uid, input.RequestKey).Scan(&id, &oldAmount, &kind, &status, &oldMethod, &checkoutData)
	if e == nil {
		if oldAmount != cents || oldMethod != input.MethodID || kind != "recharge" {
			fail(w, 409, "请求标识已用于其他操作")
			return
		}
		if status != "pending" && status != "paid" {
			fail(w, 409, "此订单已取消")
			return
		}
		if e = tx.Commit(ctx); e != nil {
			paymentDBError(w)
			return
		}
		checkout, status, e := s.resolvePaymentCheckout(ctx, id)
		if e != nil {
			fail(w, 503, "支付请求暂时不可用，可在我的订单中继续支付")
			return
		}
		writeJSON(w, 200, map[string]any{"id": id, "status": status, "checkout": checkout, "replayed": true})
		return
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		paymentDBError(w)
		return
	}
	if cents > maxMoneyCents-balance {
		fail(w, 400, "充值后余额超出范围")
		return
	}
	var pending int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM shop_orders WHERE user_id=$1 AND kind='recharge' AND status='pending' AND created_at>now()-interval '1 hour'", uid).Scan(&pending); e != nil {
		paymentDBError(w)
		return
	}
	if pending >= 20 {
		fail(w, 429, "未完成的充值订单较多，请先支付已有订单或稍后再试")
		return
	}
	var name, driverID string
	var configData []byte
	e = tx.QueryRow(ctx, "SELECT name,interface,config FROM payment_methods WHERE id=$1 AND enabled FOR SHARE", input.MethodID).Scan(&name, &driverID, &configData)
	if e != nil {
		fail(w, 400, "支付方式不存在或已停用")
		return
	}
	driver, e := s.payments.Driver(driverID)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	var config payment.Config
	if json.Unmarshal(configData, &config) != nil || driver.Validate(config) != nil {
		paymentDBError(w)
		return
	}
	settings, e := readSystemSettings(ctx, tx)
	if e != nil {
		paymentDBError(w)
		return
	}
	if settings.PanelURL == "" || !panelURL(settings.PanelURL) {
		fail(w, 409, "管理员需先在系统设置填写可公开访问的面板地址")
		return
	}
	orderNo := "R" + Secret()[:24]
	origin := strings.TrimRight(settings.PanelURL, "/")
	createContext, _ := json.Marshal(payment.Order{Number: orderNo, Amount: formatMoney(cents), Currency: "CNY", Name: "Nekopass 余额充值", NotifyURL: origin + "/api/v1/payments/notify/" + driverID + "/" + strconv.FormatInt(input.MethodID, 10), ReturnURL: origin + "/api/v1/payments/return"})
	snapshot, _ := json.Marshal(map[string]string{"source": "payment", "note": name, "payment_interface": driverID, "currency": "CNY"})
	e = tx.QueryRow(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,amount_cents,status,request_key,snapshot,payment_method_id,payment_method_name) VALUES($1,$2,'recharge',$3,'pending',$4,$5,$6,$7) RETURNING id`, orderNo, uid, cents, input.RequestKey, snapshot, input.MethodID, name).Scan(&id)
	if e != nil {
		paymentDBError(w)
		return
	}
	if _, e = tx.Exec(ctx, "INSERT INTO payment_attempts(order_id,method_id,interface,config,account_scope,create_context) VALUES($1,$2,$3,$4,$5,$6)", id, input.MethodID, driverID, configData, Hash(driver.AccountScope(config)), createContext); e != nil {
		paymentDBError(w)
		return
	}
	if e = tx.Commit(ctx); e != nil {
		paymentDBError(w)
		return
	}
	checkout, status, e := s.resolvePaymentCheckout(ctx, id)
	if e != nil {
		fail(w, 503, "支付请求暂时不可用，可在我的订单中继续支付")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "order_no": orderNo, "status": status, "checkout": checkout})
}

// resolvePaymentCheckout runs gateway calls after the pending order commits.
// Drivers must reuse Order.Number as the gateway's idempotency/merchant reference.
func (s *Server) resolvePaymentCheckout(ctx context.Context, id int64) (payment.Checkout, string, error) {
	var driverID, status string
	var configData, contextData, checkoutData []byte
	err := s.Pool.QueryRow(ctx, "SELECT a.interface,a.config,a.create_context,a.checkout,o.status FROM payment_attempts a JOIN shop_orders o ON o.id=a.order_id WHERE o.id=$1", id).Scan(&driverID, &configData, &contextData, &checkoutData, &status)
	if err != nil {
		return payment.Checkout{}, "", err
	}
	var checkout payment.Checkout
	if err = json.Unmarshal(checkoutData, &checkout); err != nil {
		return checkout, status, err
	}
	if status == "paid" {
		return checkout, status, nil
	}
	if status != "pending" {
		return checkout, status, errors.New("payment order closed")
	}
	if checkout.URL != "" {
		return checkout, status, nil
	}
	var config payment.Config
	var order payment.Order
	if err = json.Unmarshal(configData, &config); err != nil {
		return checkout, status, err
	}
	if err = json.Unmarshal(contextData, &order); err != nil {
		return checkout, status, err
	}
	driver, err := s.payments.Driver(driverID)
	if err != nil {
		return checkout, status, err
	}
	createCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	checkout, err = driver.Create(createCtx, config, order)
	if err != nil {
		return checkout, status, err
	}
	target, err := url.Parse(checkout.URL)
	if err != nil || target.Hostname() == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") || strings.ContainsAny(checkout.URL, "\r\n\x00") {
		return checkout, status, errors.New("invalid checkout URL")
	}
	data, _ := json.Marshal(checkout)
	if _, err = s.Pool.Exec(ctx, "UPDATE payment_attempts SET checkout=$2 WHERE order_id=$1", id, data); err != nil {
		return checkout, status, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT status FROM shop_orders WHERE id=$1", id).Scan(&status)
	if err == nil && status != "pending" && status != "paid" {
		err = errors.New("payment order closed")
	}
	return checkout, status, err
}
func (s *Server) payRechargeOrder(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var status string
	err := s.Pool.QueryRow(r.Context(), "SELECT o.status FROM shop_orders o JOIN payment_attempts a ON a.order_id=o.id WHERE o.id=$1 AND o.user_id=$2 AND o.kind='recharge'", id, current(r).ID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "充值订单不存在")
		return
	}
	if err != nil {
		paymentDBError(w)
		return
	}
	if status != "pending" {
		fail(w, 409, "此订单已完成或已取消")
		return
	}
	checkout, status, err := s.resolvePaymentCheckout(r.Context(), id)
	if err != nil {
		fail(w, 503, "支付请求暂时不可用，请稍后重试")
		return
	}
	writeJSON(w, 200, map[string]any{"checkout": checkout, "status": status})
}

func paymentReply(w http.ResponseWriter, driver payment.Driver, ok bool) {
	reply := driver.Acknowledge(ok)
	w.Header().Set("Content-Type", reply.ContentType)
	w.WriteHeader(reply.Status)
	io.WriteString(w, reply.Body)
}
func (s *Server) paymentNotify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(5*time.Second)) == nil {
		defer controller.SetReadDeadline(time.Time{})
	}
	driver, e := s.payments.Driver(r.PathValue("interface"))
	if e != nil {
		http.Error(w, "fail", 400)
		return
	}
	reject := func() { paymentReply(w, driver, false) }
	methodID, e := strconv.ParseInt(r.PathValue("methodID"), 10, 64)
	if e != nil || methodID <= 0 {
		reject()
		return
	}
	if len(r.URL.RawQuery) > 16384 {
		reject()
		return
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		reject()
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	body, e := io.ReadAll(r.Body)
	if e != nil {
		reject()
		return
	}
	callback := payment.Callback{Query: query, Body: body, Header: r.Header, Method: r.Method}
	reference, e := driver.Reference(callback)
	if e != nil {
		reject()
		return
	}
	var id, uid, amount int64
	var configData []byte
	var scope string
	e = s.Pool.QueryRow(r.Context(), `SELECT o.id,o.user_id,o.amount_cents,a.config,a.account_scope FROM shop_orders o JOIN payment_attempts a ON a.order_id=o.id WHERE o.order_no=$1 AND o.kind='recharge' AND a.method_id=$2 AND a.interface=$3`, reference, methodID, r.PathValue("interface")).Scan(&id, &uid, &amount, &configData, &scope)
	if e != nil {
		reject()
		return
	}
	var config payment.Config
	if json.Unmarshal(configData, &config) != nil || driver.Validate(config) != nil {
		reject()
		return
	}
	receipt, e := driver.Verify(config, callback)
	if e != nil {
		reject()
		return
	}
	paid, e := parseMoney(receipt.Amount)
	if e != nil || paid != amount || receipt.Currency != "CNY" || receipt.OrderNumber != reference || receipt.TradeNumber == "" || len(receipt.TradeNumber) > 128 || strings.ContainsAny(receipt.TradeNumber, "\r\n\x00") {
		reject()
		return
	}
	tx, e := s.Pool.Begin(r.Context())
	if e != nil {
		reject()
		return
	}
	defer tx.Rollback(r.Context())
	// Match manual recharge and purchases: user -> wallet -> order. This ordering
	// serializes credits/debits and avoids a webhook/purchase deadlock.
	var exists int64
	if e = tx.QueryRow(r.Context(), "SELECT id FROM users WHERE id=$1 FOR UPDATE", uid).Scan(&exists); e != nil {
		reject()
		return
	}
	balance, e := walletBalanceLocked(r.Context(), tx, uid)
	if e != nil {
		reject()
		return
	}
	var status, methodName string
	var trade *string
	e = tx.QueryRow(r.Context(), "SELECT o.status,o.payment_method_name,a.gateway_trade_no FROM shop_orders o JOIN payment_attempts a ON a.order_id=o.id WHERE o.id=$1 FOR UPDATE OF o,a", id).Scan(&status, &methodName, &trade)
	if e != nil {
		reject()
		return
	}
	if status == "paid" {
		if trade == nil || *trade != receipt.TradeNumber {
			reject()
			return
		}
		paymentReply(w, driver, true)
		return
	}
	if status != "pending" || paid > maxMoneyCents-balance {
		reject()
		return
	}
	// Unique merchant-scope transaction IDs prevent reuse across multiple methods.
	claim, e := tx.Exec(r.Context(), "UPDATE payment_attempts SET gateway_trade_no=$2 WHERE order_id=$1 AND account_scope=$3", id, receipt.TradeNumber, scope)
	if e != nil || claim.RowsAffected() != 1 {
		reject()
		return
	}
	balance += paid
	if _, e = tx.Exec(r.Context(), "UPDATE wallet_accounts SET balance_cents=$2,updated_at=now() WHERE user_id=$1", uid, balance); e != nil {
		reject()
		return
	}
	if _, e = tx.Exec(r.Context(), "UPDATE shop_orders SET status='paid',paid_at=now() WHERE id=$1", id); e != nil {
		reject()
		return
	}
	if _, e = tx.Exec(r.Context(), "INSERT INTO wallet_entries(user_id,order_id,amount_cents,balance_after_cents,kind,note) VALUES($1,$2,$3,$4,'recharge',$5)", uid, id, paid, balance, "在线充值 · "+methodName); e != nil {
		reject()
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		reject()
		return
	}
	paymentReply(w, driver, true)
}
