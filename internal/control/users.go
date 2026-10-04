package control

import (
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type UserInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	PlanID   int64  `json:"plan_id"`
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	rows, e := s.Pool.Query(r.Context(), `SELECT u.id,u.username,u.is_admin,u.account_enabled AS enabled,u.plan_id,u.plan_name,u.plan_enabled,u.plan_started_at,u.expires_at,u.next_reset_at,u.quota_epoch,u.subscription_managed,COALESCE((SELECT balance_cents FROM wallet_accounts WHERE user_id=u.id),0) AS balance_cents,u.speed_bps/125000 AS speed_mbps,u.quota_bytes,u.max_rules,u.max_connections,u.ip_limit,u.rule_speed_bps/125000 AS rule_speed_mbps,u.rule_ip_limit,u.rule_connection_limit,
 COALESCE((SELECT sum(traffic) FROM current_grants WHERE user_id=u.id),0)::bigint AS traffic_bytes,
 COALESCE((SELECT sum(spent+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)::bigint AS charged_bytes,
 COALESCE((SELECT sum(issued-released+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)::bigint AS allocated_bytes,
 COALESCE((SELECT array_agg(node_id) FROM user_nodes WHERE user_id=u.id),'{}') AS node_ids,
 (SELECT count(*) FROM rules WHERE user_id=u.id) AS rule_count
 FROM user_entitlements u WHERE $1 OR u.id=$2 ORDER BY u.id`, u.IsAdmin, u.ID)
	s.sendRows(w, rows, e)
}
func (s *Server) saveUser(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var v UserInput
	if !decode(w, r, &v) {
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	if v.Username == "" || len(v.Username) > 64 || v.PlanID < 0 {
		fail(w, 400, "用户参数无效")
		return
	}
	if (id == 0 || v.Password != "") && (len(v.Password) < 12 || len(v.Password) > 72) {
		fail(w, 400, "密码长度须为 12–72 字节")
		return
	}
	hash := ""
	if v.Password != "" {
		h, e := bcrypt.GenerateFromPassword([]byte(v.Password), bcrypt.DefaultCost)
		if e != nil {
			fail(w, 400, "密码无效")
			return
		}
		hash = string(h)
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var oldPlan int64
	if id != 0 {
		var isAdmin bool
		e = tx.QueryRow(ctx, "SELECT COALESCE(plan_id,0),is_admin FROM users WHERE id=$1 FOR UPDATE", id).Scan(&oldPlan, &isAdmin)
		if e != nil {
			fail(w, 404, "用户不存在")
			return
		}
		if isAdmin && !v.Enabled {
			fail(w, 400, "不能通过此接口禁用管理员")
			return
		}
	}
	if v.PlanID != 0 {
		var quota int64
		var limit int
		e = tx.QueryRow(ctx, "SELECT quota_bytes,max_rules FROM plans WHERE id=$1", v.PlanID).Scan(&quota, &limit)
		if e != nil {
			fail(w, 400, "套餐不存在")
			return
		}
		if id != 0 && oldPlan != v.PlanID {
			var allocated int64
			var count int
			e = tx.QueryRow(ctx, "SELECT COALESCE((SELECT sum(issued-released+unlimited_spent) FROM current_grants WHERE user_id=$1),0)::bigint,(SELECT count(*) FROM rules WHERE user_id=$1)", id).Scan(&allocated, &count)
			if e != nil {
				s.dbError(w, e)
				return
			}
			if (quota >= 0 && quota < allocated) || (limit > 0 && limit < count) {
				fail(w, 409, "套餐不足以覆盖该用户已分配额度或现有规则，请选择更大的套餐")
				return
			}
		}
	}
	if id == 0 {
		e = tx.QueryRow(ctx, "INSERT INTO users(username,password_hash,enabled,plan_id) VALUES($1,$2,$3,NULLIF($4,0)) RETURNING id", v.Username, hash, v.Enabled, v.PlanID).Scan(&id)
	} else {
		_, e = tx.Exec(ctx, `UPDATE users SET username=$2,password_hash=CASE WHEN $3='' THEN password_hash ELSE $3 END,enabled=$4,plan_id=NULLIF($5,0),plan_started_at=CASE WHEN COALESCE(plan_id,0)<>$5 THEN now() ELSE plan_started_at END,subscription_managed=CASE WHEN COALESCE(plan_id,0)<>$5 THEN false ELSE subscription_managed END,subscription_expires_at=CASE WHEN COALESCE(plan_id,0)<>$5 THEN NULL ELSE subscription_expires_at END,next_reset_at=CASE WHEN COALESCE(plan_id,0)<>$5 THEN NULL ELSE next_reset_at END WHERE id=$1`, id, v.Username, hash, v.Enabled, v.PlanID)
		if e == nil && (hash != "" || !v.Enabled) {
			_, e = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", id)
		}
	}
	if e != nil {
		s.dbError(w, e)
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
