package control

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type adminOrderFilter struct {
	OrderNo, Email, Kind, Status, TimeField, GatewayNo string
	UserID                                             int64
	From, To                                           *time.Time
	Page                                               int
}

func parseAdminOrderFilter(r *http.Request) (adminOrderFilter, error) {
	q := r.URL.Query()
	f := adminOrderFilter{OrderNo: strings.TrimSpace(q.Get("order_no")), Email: strings.TrimSpace(q.Get("email")), Kind: q.Get("kind"), Status: q.Get("status"), TimeField: q.Get("time_field"), GatewayNo: strings.TrimSpace(q.Get("gateway_trade_no")), Page: 1}
	if len(f.OrderNo) > 128 || len(f.Email) > 254 || len(f.GatewayNo) > 256 || strings.ContainsAny(f.OrderNo+f.Email+f.GatewayNo, "\x00\r\n") {
		return f, errors.New("筛选内容过长或格式无效")
	}
	if f.TimeField == "" {
		f.TimeField = "created"
	}
	if f.TimeField != "created" && f.TimeField != "paid" {
		return f, errors.New("时间筛选类型无效")
	}
	if f.Kind != "" && f.Kind != "purchase" && f.Kind != "renewal" && f.Kind != "recharge" && f.Kind != "rebate" {
		return f, errors.New("订单类型无效")
	}
	if f.Status != "" && f.Status != "paid" && f.Status != "pending" && f.Status != "cancelled" {
		return f, errors.New("订单状态无效")
	}
	if raw := q.Get("user_id"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			return f, errors.New("用户 ID 无效")
		}
		f.UserID = value
	}
	if raw := q.Get("page"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100000 {
			return f, errors.New("页码无效")
		}
		f.Page = value
	}
	for key, dest := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if raw := q.Get(key); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil || value.Year() < 1 || value.Year() > 9999 {
				return f, errors.New("时间须为有效 RFC3339 格式")
			}
			*dest = &value
		}
	}
	if f.From != nil && f.To != nil && f.From.After(*f.To) {
		return f, errors.New("开始时间不能晚于结束时间")
	}
	return f, nil
}

const adminOrdersJoin = ` FROM shop_orders o JOIN users u ON u.id=o.user_id LEFT JOIN payment_attempts a ON a.order_id=o.id `
const adminOrdersWhere = ` WHERE ($1::text='' OR strpos(lower(o.order_no),lower($1))>0)
 AND ($2::text='' OR strpos(lower(u.username),lower($2))>0)
 AND ($3::bigint=0 OR o.user_id=$3)
 AND ($4::text='' OR o.kind=$4) AND ($5::text='' OR o.status=$5)
 AND ($6::timestamptz IS NULL OR CASE WHEN $8::text='paid' THEN o.paid_at ELSE o.created_at END >= $6)
 AND ($7::timestamptz IS NULL OR CASE WHEN $8::text='paid' THEN o.paid_at ELSE o.created_at END <= $7)
 AND ($9::text='' OR strpos(lower(COALESCE(a.gateway_trade_no,'')),lower($9))>0) `

// Search parameters are values, never SQL fragments. No payment credentials,
// checkout signatures or provider config snapshots enter administrator orders.
func (s *Server) adminOrders(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	f, err := parseAdminOrderFilter(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	args := []any{f.OrderNo, f.Email, f.UserID, f.Kind, f.Status, f.From, f.To, f.TimeField, f.GatewayNo}
	tx, err := s.Pool.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var total int64
	if err = tx.QueryRow(r.Context(), "SELECT count(*)"+adminOrdersJoin+adminOrdersWhere, args...).Scan(&total); err != nil {
		s.dbError(w, err)
		return
	}
	args = append(args, (f.Page-1)*20)
	rows, err := tx.Query(r.Context(), `SELECT o.id,o.order_no,o.user_id,u.username,o.kind,o.plan_name,o.cycle,o.amount_cents,o.status,o.payment_method_name,o.created_at,o.paid_at,COALESCE(a.gateway_trade_no,'') AS gateway_trade_no`+adminOrdersJoin+adminOrdersWhere+" ORDER BY o.id DESC LIMIT 20 OFFSET $10", args...)
	if err != nil {
		s.dbError(w, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": f.Page})
}

func (s *Server) adminOrder(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT o.id,o.order_no,o.user_id,u.username,o.kind,o.plan_name,o.cycle,o.amount_cents,o.status,o.payment_method_name,o.created_at,o.paid_at,COALESCE(a.gateway_trade_no,'') AS gateway_trade_no,o.snapshot,COALESCE(actor.username,'') AS actor_name`+adminOrdersJoin+" LEFT JOIN users actor ON actor.id=o.actor_id WHERE o.id=$1", id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	item, err := pgx.CollectExactlyOneRow(rows, pgx.RowToMap)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "订单不存在")
		return
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, item)
}
