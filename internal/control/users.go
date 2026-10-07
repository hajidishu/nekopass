package control

import (
	"github.com/nekopass/nekopass/internal/registration"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type UserInput struct {
	Referral *UserReferralSettings `json:"referral,omitempty"`
	UserResourcesInput
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	PlanID   int64  `json:"plan_id"`
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	rows, e := s.Pool.Query(r.Context(), `SELECT u.id,u.username,u.is_admin,u.account_enabled AS enabled,u.plan_id,u.plan_name,u.plan_enabled,u.plan_started_at,u.expires_at,u.next_reset_at,u.quota_epoch,u.subscription_managed,COALESCE((SELECT balance_cents FROM wallet_accounts WHERE user_id=u.id),0) AS balance_cents,u.speed_bps/125000 AS speed_mbps,u.quota_bytes,u.max_rules,u.max_connections,u.ip_limit,u.rule_speed_bps/125000 AS rule_speed_mbps,u.rule_ip_limit,u.rule_connection_limit,
 u.traffic_base_bytes+COALESCE((SELECT sum(traffic) FROM current_grants WHERE user_id=u.id),0)::bigint AS traffic_bytes,
 u.traffic_base_bytes+COALESCE((SELECT sum(spent+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)::bigint AS charged_bytes,
 u.traffic_base_bytes+COALESCE((SELECT sum(issued-released+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)::bigint AS allocated_bytes,u.resources_revision,
 COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM user_node_groups WHERE user_id=u.id),'{}') AS node_group_ids,
 COALESCE((SELECT array_agg(node_id) FROM user_nodes WHERE user_id=u.id),'{}') AS node_ids,
 (SELECT count(*) FROM rules WHERE user_id=u.id) AS rule_count,
 (SELECT referral_enabled FROM users WHERE id=u.id) AS referral_enabled,
 (SELECT referral_mode FROM users WHERE id=u.id) AS referral_mode,
 (SELECT referral_rate_bps FROM users WHERE id=u.id) AS referral_rate_bps
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
	if email, err := registration.Email(v.Username); err == nil {
		v.Username = email
	}
	if v.Username == "" || len(v.Username) > 254 || v.PlanID < 0 {
		fail(w, 400, "用户参数无效")
		return
	}
	if err := v.Referral.validate(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := v.UserResourcesInput.validate(); err != nil {
		fail(w, 400, err.Error())
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
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(lower($1),734296))", v.Username); e != nil {
		s.dbError(w, e)
		return
	}

	if _, err := registration.Email(v.Username); err == nil {
		var duplicate bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE lower(username)=$1 AND id<>$2)", v.Username, id).Scan(&duplicate); e != nil {
			s.dbError(w, e)
			return
		}
		if duplicate {
			fail(w, 409, "此邮箱已注册")
			return
		}
	}
	var oldPlan int64
	var before []byte
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
		if v.ExpectedResourcesRevision != nil {
			var revision int64
			if e = tx.QueryRow(ctx, "SELECT resources_revision FROM users WHERE id=$1", id).Scan(&revision); e != nil {
				s.dbError(w, e)
				return
			}
			if revision != *v.ExpectedResourcesRevision {
				fail(w, 409, "用户资源已变化，请刷新后重新编辑")
				return
			}
		}
		before, e = resourceSnapshot(ctx, tx, id)
		if e != nil {
			s.dbError(w, e)
			return
		}
	}
	if v.PlanID != 0 {
		var exists bool
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM plans WHERE id=$1)", v.PlanID).Scan(&exists)
		if e != nil || !exists {
			fail(w, 400, "套餐不存在")
			return
		}
	}
	if v.NodeGroupIDs != nil {
		var count int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM node_groups WHERE id=ANY($1)", *v.NodeGroupIDs).Scan(&count); e != nil {
			s.dbError(w, e)
			return
		}
		if count != len(*v.NodeGroupIDs) {
			fail(w, 400, "节点组不存在")
			return
		}
	}
	creating := id == 0
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
	if e = saveUserReferral(ctx, tx, id, v.Referral); e != nil {
		s.dbError(w, e)
		return
	}
	if e = applyUserResources(ctx, tx, id, v.UserResourcesInput, !creating && oldPlan != v.PlanID); e != nil {
		s.dbError(w, e)
		return
	}
	var limit, count int
	if e = tx.QueryRow(ctx, "SELECT max_rules,(SELECT count(*) FROM rules WHERE user_id=$1) FROM users WHERE id=$1", id).Scan(&limit, &count); e != nil {
		s.dbError(w, e)
		return
	}
	if limit > 0 && count > limit {
		fail(w, 409, "规则上限不能低于用户已有规则数量")
		return
	}
	if e = recordUserResources(ctx, tx, id, current(r).ID, before); e != nil {
		s.dbError(w, e)
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
