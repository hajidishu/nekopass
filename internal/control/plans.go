package control

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
)

type PlanInput struct {
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	Enabled             bool               `json:"enabled"`
	SpeedMbps           int64              `json:"speed_mbps"`
	QuotaBytes          int64              `json:"quota_bytes"`
	MaxRules            int                `json:"max_rules"`
	MaxConnections      int64              `json:"max_connections"`
	IPLimit             int                `json:"ip_limit"`
	RuleSpeedMbps       int64              `json:"rule_speed_mbps"`
	RuleIPLimit         int                `json:"rule_ip_limit"`
	RuleConnectionLimit int                `json:"rule_connection_limit"`
	DurationDays        int                `json:"duration_days"`
	PurchaseLimit       int                `json:"purchase_limit"`
	NodeGroupIDs        []int64            `json:"node_group_ids"`
	Prices              map[string]*string `json:"prices"`
}

func (s *Server) plans(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT p.id,p.name,p.description,p.enabled,p.prices,p.purchase_limit,p.speed_bps/125000 AS speed_mbps,p.quota_bytes,p.max_rules,p.max_connections,p.ip_limit,p.rule_speed_bps/125000 AS rule_speed_mbps,p.rule_ip_limit,p.rule_connection_limit,p.duration_days,(SELECT count(*) FROM users WHERE plan_id=p.id) AS user_count,COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM plan_node_groups WHERE plan_id=p.id),'{}') AS node_group_ids FROM plans p ORDER BY p.id`)
	s.sendRows(w, rows, e)
}
func (s *Server) sendRows(w http.ResponseWriter, rows pgx.Rows, e error) {
	if e != nil {
		s.dbError(w, e)
		return
	}
	v, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if v == nil {
		v = []map[string]any{}
	}
	writeJSON(w, 200, v)
}
func (s *Server) savePlan(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var v PlanInput
	if !decode(w, r, &v) {
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	prices, priceErr := parsePlanPrices(v.Prices)
	if priceErr != nil {
		fail(w, 400, priceErr.Error())
		return
	}
	priceJSON, _ := json.Marshal(prices)
	if v.PurchaseLimit < 0 || v.PurchaseLimit > 1000000 {
		fail(w, 400, "每用户购买上限须为 0–1000000，0 表示不限制")
		return
	}
	if v.Name == "" || len([]rune(v.Name)) > 80 || len(v.Description) > 4000 || v.SpeedMbps < 0 || v.SpeedMbps > 100000 || v.QuotaBytes < -1 || v.QuotaBytes > 1<<60 || v.MaxRules < 0 || v.MaxRules > 10000 || v.MaxConnections < 0 || v.MaxConnections > 1000000 || v.IPLimit < 0 || v.IPLimit > 1000000 || v.RuleSpeedMbps < 0 || v.RuleSpeedMbps > 100000 || v.RuleIPLimit < 0 || v.RuleIPLimit > 1000000 || v.RuleConnectionLimit < 0 || v.RuleConnectionLimit > 1000000 || v.DurationDays < 0 || v.DurationDays > 36500 || len(v.NodeGroupIDs) > 1000 {
		fail(w, 400, "套餐参数超出范围")
		return
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	id, validID := resourceID(w, r)
	if !validID {
		return
	}

	if id == 0 {
		e = tx.QueryRow(ctx, "INSERT INTO plans(name,speed_bps,quota_bytes,max_rules,max_connections) VALUES($1,$2,$3,$4,$5) RETURNING id", v.Name, v.SpeedMbps*125000, v.QuotaBytes, v.MaxRules, v.MaxConnections).Scan(&id)
	}
	if e != nil {
		s.dbError(w, e)
		return
	}
	tag, e := tx.Exec(ctx, `UPDATE plans SET name=$2,description=$3,enabled=$4,speed_bps=$5,quota_bytes=$6,max_rules=$7,max_connections=$8,ip_limit=$9,rule_speed_bps=$10,rule_ip_limit=$11,rule_connection_limit=$12,duration_days=$13,prices=$14,purchase_limit=$15 WHERE id=$1`, id, v.Name, v.Description, v.Enabled, v.SpeedMbps*125000, v.QuotaBytes, v.MaxRules, v.MaxConnections, v.IPLimit, v.RuleSpeedMbps*125000, v.RuleIPLimit, v.RuleConnectionLimit, v.DurationDays, priceJSON, v.PurchaseLimit)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "套餐不存在")
		return
	}
	if _, e = tx.Exec(ctx, "DELETE FROM plan_node_groups WHERE plan_id=$1", id); e != nil {
		s.dbError(w, e)
		return
	}
	for _, g := range v.NodeGroupIDs {
		if _, e = tx.Exec(ctx, "INSERT INTO plan_node_groups(plan_id,group_id) VALUES($1,$2) ON CONFLICT DO NOTHING", id, g); e != nil {
			s.dbError(w, e)
			return
		}
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
func (s *Server) deletePlan(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	tag, e := s.Pool.Exec(r.Context(), "DELETE FROM plans WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM users WHERE plan_id=$1)", id)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 409, "套餐不存在或仍被用户使用")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
