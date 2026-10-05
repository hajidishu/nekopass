package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type UserResourcesInput struct {
	SpeedMbps                 *int64   `json:"speed_mbps,omitempty"`
	QuotaBytes                *int64   `json:"quota_bytes,omitempty"`
	TrafficBytes              *int64   `json:"traffic_bytes,omitempty"`
	MaxRules                  *int     `json:"max_rules,omitempty"`
	MaxConnections            *int64   `json:"max_connections,omitempty"`
	IPLimit                   *int     `json:"ip_limit,omitempty"`
	RuleSpeedMbps             *int64   `json:"rule_speed_mbps,omitempty"`
	RuleIPLimit               *int     `json:"rule_ip_limit,omitempty"`
	RuleConnectionLimit       *int     `json:"rule_connection_limit,omitempty"`
	NodeGroupIDs              *[]int64 `json:"node_group_ids,omitempty"`
	ExpiresAt                 *string  `json:"expires_at,omitempty"`
	ExpectedResourcesRevision *int64   `json:"expected_resources_revision,omitempty"`
}

func (v UserResourcesInput) validate() error {
	valid64 := func(p *int64, min, max int64) bool { return p == nil || (*p >= min && *p <= max) }
	valid := func(p *int, max int) bool { return p == nil || (*p >= 0 && *p <= max) }
	if !valid64(v.SpeedMbps, 0, 100000) || !valid64(v.QuotaBytes, -1, 1<<60) || !valid64(v.TrafficBytes, 0, 1<<60) || !valid(v.MaxRules, 10000) || !valid64(v.MaxConnections, 0, 1000000) || !valid(v.IPLimit, 1000000) || !valid64(v.RuleSpeedMbps, 0, 100000) || !valid(v.RuleIPLimit, 1000000) || !valid(v.RuleConnectionLimit, 1000000) || !valid64(v.ExpectedResourcesRevision, 0, 1<<60) {
		return errors.New("用户资源参数超出范围")
	}
	if v.ExpiresAt != nil && *v.ExpiresAt != "" {
		if _, e := time.Parse(time.RFC3339, *v.ExpiresAt); e != nil {
			return errors.New("到期时间无效")
		}
	}
	if v.NodeGroupIDs != nil {
		if len(*v.NodeGroupIDs) > 1000 {
			return errors.New("节点组过多")
		}
		seen := map[int64]bool{}
		for _, id := range *v.NodeGroupIDs {
			if id <= 0 || seen[id] {
				return errors.New("节点组无效或重复")
			}
			seen[id] = true
		}
	}
	return nil
}

func resourceSnapshot(ctx context.Context, tx pgx.Tx, uid int64) ([]byte, error) {
	var data []byte
	e := tx.QueryRow(ctx, `SELECT to_jsonb(u)||jsonb_build_object('traffic_bytes',u.traffic_base_bytes+COALESCE((SELECT sum(traffic) FROM current_grants WHERE user_id=u.id),0),'node_group_ids',COALESCE((SELECT jsonb_agg(group_id ORDER BY group_id) FROM user_node_groups WHERE user_id=u.id),'[]')) FROM user_entitlements u WHERE u.id=$1`, uid).Scan(&data)
	return data, e
}

func applyUserResources(ctx context.Context, tx pgx.Tx, uid int64, v UserResourcesInput, planChanged bool) error {
	var oldQuota, used int64
	if e := tx.QueryRow(ctx, `SELECT quota_bytes,traffic_base_bytes+COALESCE((SELECT sum(traffic) FROM current_grants WHERE user_id=u.id),0)::bigint FROM users u WHERE id=$1`, uid).Scan(&oldQuota, &used); e != nil {
		return e
	}
	if v.TrafficBytes != nil {
		used = *v.TrafficBytes
	}
	rotate := planChanged || v.TrafficBytes != nil || (v.QuotaBytes != nil && *v.QuotaBytes != oldQuota)
	var expires *time.Time
	if v.ExpiresAt != nil && *v.ExpiresAt != "" {
		t, _ := time.Parse(time.RFC3339, *v.ExpiresAt)
		expires = &t
	}
	_, e := tx.Exec(ctx, `UPDATE users SET speed_bps=COALESCE($2::bigint*125000,speed_bps),quota_bytes=COALESCE($3,quota_bytes),max_rules=COALESCE($4,max_rules),max_connections=COALESCE($5,max_connections),ip_limit=COALESCE($6,ip_limit),rule_speed_bps=COALESCE($7::bigint*125000,rule_speed_bps),rule_ip_limit=COALESCE($8,rule_ip_limit),rule_connection_limit=COALESCE($9,rule_connection_limit),
 resource_expires_at=CASE WHEN $10 THEN $11::timestamptz ELSE resource_expires_at END,subscription_expires_at=CASE WHEN $10 AND subscription_managed THEN $11::timestamptz ELSE subscription_expires_at END,
 next_reset_at=CASE WHEN $10 AND $11::timestamptz IS NOT NULL THEN LEAST(next_reset_at,$11::timestamptz) ELSE next_reset_at END,
 quota_epoch=quota_epoch+CASE WHEN $12 THEN 1 ELSE 0 END,traffic_base_bytes=CASE WHEN $12 THEN $13 ELSE traffic_base_bytes END,resources_revision=resources_revision+1 WHERE id=$1`, uid, v.SpeedMbps, v.QuotaBytes, v.MaxRules, v.MaxConnections, v.IPLimit, v.RuleSpeedMbps, v.RuleIPLimit, v.RuleConnectionLimit, v.ExpiresAt != nil, expires, rotate, used)
	if e != nil {
		return e
	}
	if v.NodeGroupIDs != nil {
		if _, e = tx.Exec(ctx, "DELETE FROM user_node_groups WHERE user_id=$1", uid); e != nil {
			return e
		}
		for _, id := range *v.NodeGroupIDs {
			if _, e = tx.Exec(ctx, "INSERT INTO user_node_groups(user_id,group_id) VALUES($1,$2)", uid, id); e != nil {
				return e
			}
		}
	}
	return nil
}

func recordUserResources(ctx context.Context, tx pgx.Tx, uid, actor int64, before []byte) error {
	if before == nil {
		before = json.RawMessage(`{}`)
	}
	after, e := resourceSnapshot(ctx, tx, uid)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO user_resource_changes(user_id,actor_id,before_state,after_state) VALUES($1,$2,$3,$4)", uid, actor, before, after)
	return e
}
