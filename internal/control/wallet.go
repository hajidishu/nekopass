package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var requestKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`)

func walletBalanceLocked(ctx context.Context, tx pgx.Tx, uid int64) (int64, error) {
	if _, e := tx.Exec(ctx, "INSERT INTO wallet_accounts(user_id) VALUES($1) ON CONFLICT DO NOTHING", uid); e != nil {
		return 0, e
	}
	var balance int64
	e := tx.QueryRow(ctx, "SELECT balance_cents FROM wallet_accounts WHERE user_id=$1 FOR UPDATE", uid).Scan(&balance)
	return balance, e
}

func (s *Server) wallet(w http.ResponseWriter, r *http.Request) {
	uid := current(r).ID
	var balance int64
	if e := s.Pool.QueryRow(r.Context(), "SELECT COALESCE((SELECT balance_cents FROM wallet_accounts WHERE user_id=$1),0)", uid).Scan(&balance); e != nil {
		s.dbError(w, e)
		return
	}
	rows, e := s.Pool.Query(r.Context(), "SELECT id,order_id,amount_cents,balance_after_cents,kind,note,created_at FROM wallet_entries WHERE user_id=$1 ORDER BY id DESC LIMIT 100", uid)
	if e != nil {
		s.dbError(w, e)
		return
	}
	entries, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"balance_cents": balance, "currency": "CNY", "entries": entries, "minimum_recharge_cents": 1000, "payment_channels": []any{}})
}

func (s *Server) orders(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		fail(w, 400, "页码无效")
		return
	}
	uid := current(r).ID
	var total int64
	if e := s.Pool.QueryRow(r.Context(), "SELECT count(*) FROM shop_orders WHERE user_id=$1", uid).Scan(&total); e != nil {
		s.dbError(w, e)
		return
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT id,order_no,kind,plan_name,cycle,amount_cents,status,snapshot,created_at,paid_at FROM shop_orders WHERE user_id=$1 ORDER BY id DESC LIMIT 20 OFFSET $2`, uid, (page-1)*20)
	if e != nil {
		s.dbError(w, e)
		return
	}
	items, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page})
}

// Until a payment gateway is connected, only an authenticated administrator may
// credit funds. This is audited manual recharge, never a user-side payment claim.
func (s *Server) adminRecharge(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	uid, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || uid < 1 {
		fail(w, 400, "用户 ID 无效")
		return
	}
	var in struct {
		Amount     string `json:"amount"`
		Note       string `json:"note"`
		RequestKey string `json:"request_key"`
	}
	if !decode(w, r, &in) {
		return
	}
	cents, e := parseMoney(in.Amount)
	if e != nil || cents <= 0 || !requestKeyPattern.MatchString(in.RequestKey) || strings.TrimSpace(in.Note) == "" || len([]rune(in.Note)) > 300 {
		fail(w, 400, "请填写正数金额、充值备注及有效请求标识")
		return
	}
	ctx := r.Context()
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var exists int64
	if e = tx.QueryRow(ctx, "SELECT id FROM users WHERE id=$1 FOR UPDATE", uid).Scan(&exists); e != nil {
		fail(w, 404, "用户不存在")
		return
	}
	balance, e := walletBalanceLocked(ctx, tx, uid)
	if e != nil {
		s.dbError(w, e)
		return
	}
	var oid, oldAmount int64
	var actor *int64
	var kind, status string
	var snapshot []byte
	e = tx.QueryRow(ctx, "SELECT id,amount_cents,actor_id,kind,status,snapshot FROM shop_orders WHERE user_id=$1 AND request_key=$2", uid, in.RequestKey).Scan(&oid, &oldAmount, &actor, &kind, &status, &snapshot)
	if e == nil {
		var old map[string]string
		_ = json.Unmarshal(snapshot, &old)
		if oldAmount != cents || actor == nil || *actor != current(r).ID || kind != "recharge" || status != "paid" || old["note"] != strings.TrimSpace(in.Note) {
			fail(w, 409, "请求标识已用于其他操作")
			return
		}
		writeJSON(w, 200, map[string]any{"id": oid, "balance_cents": balance, "replayed": true})
		return
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		s.dbError(w, e)
		return
	}
	if cents > maxMoneyCents-balance {
		fail(w, 400, "充值后余额超出范围")
		return
	}
	snapshot, _ = json.Marshal(map[string]string{"note": strings.TrimSpace(in.Note), "source": "admin"})
	e = tx.QueryRow(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,amount_cents,status,request_key,actor_id,snapshot,paid_at) VALUES($1,$2,'recharge',$3,'paid',$4,$5,$6,now()) RETURNING id`, "R"+Secret()[:24], uid, cents, in.RequestKey, current(r).ID, snapshot).Scan(&oid)
	if e != nil {
		s.dbError(w, e)
		return
	}
	balance += cents
	if _, e = tx.Exec(ctx, "UPDATE wallet_accounts SET balance_cents=$2,updated_at=now() WHERE user_id=$1", uid, balance); e != nil {
		s.dbError(w, e)
		return
	}
	if _, e = tx.Exec(ctx, `INSERT INTO wallet_entries(user_id,order_id,amount_cents,balance_after_cents,kind,actor_id,note) VALUES($1,$2,$3,$4,'recharge',$5,$6)`, uid, oid, cents, balance, current(r).ID, strings.TrimSpace(in.Note)); e != nil {
		s.dbError(w, e)
		return
	}
	if e = tx.Commit(ctx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"id": oid, "balance_cents": balance})
}

type salePlan struct {
	ID                int64
	Name, Description string
	Prices            map[string]int64
	MaxRules          int
	PurchaseLimit     int
	GroupIDs          []int64
}

func salePlanForUpdate(ctx context.Context, tx pgx.Tx, id int64) (salePlan, error) {
	var p salePlan
	var data []byte
	e := tx.QueryRow(ctx, `SELECT id,name,description,prices,max_rules,purchase_limit,COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM plan_node_groups WHERE plan_id=p.id),'{}') FROM plans p WHERE id=$1 AND enabled FOR SHARE`, id).Scan(&p.ID, &p.Name, &p.Description, &data, &p.MaxRules, &p.PurchaseLimit, &p.GroupIDs)
	if e == nil {
		e = json.Unmarshal(data, &p.Prices)
	}
	return p, e
}

func (s *Server) shopPlans(w http.ResponseWriter, r *http.Request) {
	rows, e := s.Pool.Query(r.Context(), `SELECT p.id,p.name,p.description,p.prices,p.purchase_limit,(SELECT count(*) FROM shop_orders o WHERE o.user_id=$1 AND o.plan_id=p.id AND o.status='paid' AND o.kind IN ('purchase','renewal')) AS purchase_count,p.speed_bps/125000 AS speed_mbps,p.quota_bytes,p.max_rules,p.max_connections,p.ip_limit FROM plans p WHERE p.enabled AND p.prices<>'{}'::jsonb ORDER BY p.id`, current(r).ID)
	s.sendRows(w, rows, e)
}

type checkoutInput struct {
	PlanID        int64  `json:"plan_id"`
	Cycle         string `json:"cycle"`
	RequestKey    string `json:"request_key"`
	ExpectedPrice int64  `json:"expected_price_cents"`
	ExpectedEpoch int64  `json:"expected_epoch"`
}

func (s *Server) shopQuote(w http.ResponseWriter, r *http.Request)    { s.checkout(w, r, false) }
func (s *Server) shopPurchase(w http.ResponseWriter, r *http.Request) { s.checkout(w, r, true) }

func (s *Server) checkout(w http.ResponseWriter, r *http.Request, pay bool) {
	var in checkoutInput
	if !decode(w, r, &in) {
		return
	}
	if in.PlanID <= 0 {
		fail(w, 400, "请选择套餐")
		return
	}
	if _, ok := billingMonths[in.Cycle]; !ok {
		fail(w, 400, "不支持的付款周期")
		return
	}
	if pay && !requestKeyPattern.MatchString(in.RequestKey) {
		fail(w, 400, "请求标识无效")
		return
	}
	ctx := r.Context()
	uid := current(r).ID
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	sub, e := subscriptionForUpdate(ctx, tx, uid)
	if e != nil {
		fail(w, 403, "账号不可用")
		return
	}
	balance, e := walletBalanceLocked(ctx, tx, uid)
	if e != nil {
		s.dbError(w, e)
		return
	}
	now := time.Now()
	if pay {
		var oid, oldPlan int64
		var cycle, kind, status string
		var amount int64
		e = tx.QueryRow(ctx, "SELECT id,COALESCE(plan_id,0),cycle,kind,status,amount_cents FROM shop_orders WHERE user_id=$1 AND request_key=$2", uid, in.RequestKey).Scan(&oid, &oldPlan, &cycle, &kind, &status, &amount)
		if e == nil {
			if oldPlan != in.PlanID || cycle != in.Cycle || kind == "recharge" || status != "paid" || amount != in.ExpectedPrice {
				fail(w, 409, "请求标识已用于其他操作")
				return
			}
			writeJSON(w, 200, map[string]any{"id": oid, "balance_cents": balance, "replayed": true})
			return
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			s.dbError(w, e)
			return
		}
	}
	reset, e := resetDueSubscription(ctx, tx, uid, &sub, now)
	if e != nil {
		s.dbError(w, e)
		return
	}
	p, e := salePlanForUpdate(ctx, tx, in.PlanID)
	if e != nil {
		fail(w, 404, "套餐不存在或已停售")
		return
	}
	price, available := p.Prices[in.Cycle]
	if !available {
		fail(w, 400, "该付款周期暂不出售")
		return
	}
	if price < 0 || price > maxMoneyCents {
		fail(w, 400, "套餐价格无效")
		return
	}
	if p.PurchaseLimit > 0 {
		var purchases int64
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM shop_orders WHERE user_id=$1 AND plan_id=$2 AND status='paid' AND kind IN ('purchase','renewal')", uid, p.ID).Scan(&purchases); e != nil {
			s.dbError(w, e)
			return
		}
		if purchases >= int64(p.PurchaseLimit) {
			fail(w, 409, "已达到此套餐的每用户购买上限（含续费）")
			return
		}
	}
	var ruleCount int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM rules WHERE user_id=$1", uid).Scan(&ruleCount); e != nil {
		s.dbError(w, e)
		return
	}
	same := sub.PlanID == p.ID
	maxRules := p.MaxRules
	if same {
		if e = tx.QueryRow(ctx, "SELECT max_rules FROM users WHERE id=$1", uid).Scan(&maxRules); e != nil {
			s.dbError(w, e)
			return
		}
	}
	if maxRules > 0 && ruleCount > maxRules {
		fail(w, 409, "现有规则数量超过此套餐上限，请先减少规则")
		return
	}
	expires, next, e := purchasedDates(now, sub, same, in.Cycle)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	kind := "purchase"
	if same {
		kind = "renewal"
	}
	quote := map[string]any{"plan_id": p.ID, "plan_name": p.Name, "cycle": in.Cycle, "amount_cents": price, "balance_cents": balance, "expires_at": expires, "next_reset_at": next, "epoch": sub.Epoch, "kind": kind, "replaces_plan": sub.PlanID != 0 && !same, "resets_traffic": true, "quoted_at": now}
	if !pay {
		if reset {
			e = finishRules(ctx, tx)
		} else {
			e = tx.Commit(ctx)
		}
		if e != nil {
			s.dbError(w, e)
			return
		}
		writeJSON(w, 200, quote)
		return
	}
	if in.ExpectedPrice != price || in.ExpectedEpoch != sub.Epoch {
		fail(w, 409, "套餐价格或当前周期已变化，请重新确认购买")
		return
	}
	if balance < price {
		fail(w, 409, "余额不足，请先充值")
		return
	}
	data, _ := json.Marshal(quote)
	var oid int64
	e = tx.QueryRow(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,plan_id,plan_name,cycle,amount_cents,status,request_key,snapshot,created_at,paid_at) VALUES($1,$2,$3,$4,$5,$6,$7,'paid',$8,$9,$10,$10) RETURNING id`, "P"+Secret()[:24], uid, kind, p.ID, p.Name, in.Cycle, price, in.RequestKey, data, now).Scan(&oid)
	if e != nil {
		s.dbError(w, e)
		return
	}
	balance -= price
	if _, e = tx.Exec(ctx, "UPDATE wallet_accounts SET balance_cents=$2,updated_at=now() WHERE user_id=$1", uid, balance); e != nil {
		s.dbError(w, e)
		return
	}
	if _, e = tx.Exec(ctx, `INSERT INTO wallet_entries(user_id,order_id,amount_cents,balance_after_cents,kind,note) VALUES($1,$2,$3,$4,'purchase',$5)`, uid, oid, -price, balance, p.Name+" · "+billingNames[in.Cycle]); e != nil {
		s.dbError(w, e)
		return
	}
	index := 0
	if next != nil {
		index = 1
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET plan_id=$2,plan_started_at=$3,subscription_managed=true,subscription_expires_at=$4,next_reset_at=$5,reset_anchor_at=$3,reset_index=$6,quota_epoch=quota_epoch+1,traffic_base_bytes=0,resources_revision=resources_revision+1 WHERE id=$1`, uid, p.ID, now, expires, next, index); e != nil {
		s.dbError(w, e)
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"id": oid, "balance_cents": balance, "expires_at": expires, "next_reset_at": next})
}
