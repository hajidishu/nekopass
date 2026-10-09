package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/networkpolicy"
	"github.com/nekopass/nekopass/internal/store"
	"github.com/nekopass/nekopass/internal/tunnel"
)

type RuleInput struct {
	Protocol          string   `json:"protocol"`
	UserID            int64    `json:"user_id"`
	NodeID            int64    `json:"node_id"`
	EgressNodeID      int64    `json:"egress_node_id"`
	Name              string   `json:"name"`
	GroupID           int64    `json:"group_id"`
	ListenPort        int      `json:"listen_port"`
	TargetHost        string   `json:"target_host,omitempty"`
	TargetPort        int      `json:"target_port,omitempty"`
	Targets           []string `json:"targets"`
	Balance           string   `json:"balance"`
	SpeedMbps         int64    `json:"speed_mbps"`
	IPLimit           int      `json:"ip_limit"`
	ConnectionLimit   int      `json:"connection_limit"`
	ProxyAccept       string   `json:"proxy_accept"`
	ProxySend         string   `json:"proxy_send"`
	ProxyTrustedCIDRs []string `json:"proxy_trusted_cidrs"`
	Enabled           bool     `json:"enabled"`
}

func (in *RuleInput) normalize() error {
	if in.Protocol == "" {
		in.Protocol = "tcp"
	}
	if in.Protocol != "tcp" && in.Protocol != "udp" && in.Protocol != "tcp_udp" {
		return errors.New("转发类型无效")
	}
	if in.Protocol != "tcp" && (in.ProxyAccept != "" && in.ProxyAccept != "off" || in.ProxySend != "" && in.ProxySend != "off") {
		return errors.New("UDP 规则暂不支持 Proxy Protocol")
	}
	if in.SpeedMbps != 0 || in.IPLimit != 0 || in.ConnectionLimit != 0 {
		return errors.New("规则限速、IP 和连接数限制跟随当前套餐")
	}
	if in.EgressNodeID < 0 || in.EgressNodeID == in.NodeID {
		return errors.New("出口节点无效")
	}
	if len(in.Targets) == 0 && in.TargetHost != "" {
		in.Targets = []string{net.JoinHostPort(in.TargetHost, strconv.Itoa(in.TargetPort))}
	}
	if len(in.Targets) == 0 || len(in.Targets) > 32 {
		return errors.New("请填写 1–32 个目标地址")
	}
	for i, t := range in.Targets {
		h, p, e := net.SplitHostPort(strings.TrimSpace(t))
		n, pe := strconv.Atoi(p)
		if e != nil || pe != nil || !ValidTarget(h) || n < 1 || n > 65535 {
			return fmt.Errorf("目标地址 %q 无效，格式为 host:port 或 [IPv6]:port", t)
		}
		in.Targets[i] = net.JoinHostPort(h, strconv.Itoa(n))
		if i == 0 {
			in.TargetHost = h
			in.TargetPort = n
		}
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = in.Targets[0]
	}
	if len([]rune(in.Name)) > 128 {
		return errors.New("名称不能超过 128 个字符")
	}
	if in.ListenPort != 0 && (in.ListenPort < 1024 || in.ListenPort > 65535) {
		return errors.New("监听端口为 1024–65535，留空或 0 为随机分配")
	}
	if in.Balance == "" {
		in.Balance = "random"
	}
	if in.Balance != "random" && in.Balance != "round_robin" && in.Balance != "least_connections" {
		return errors.New("负载均衡策略无效")
	}
	if in.ProxyAccept == "" {
		in.ProxyAccept = "off"
	}
	if in.ProxySend == "" {
		in.ProxySend = "off"
	}
	if in.ProxyAccept != "off" && in.ProxyAccept != "v1" && in.ProxyAccept != "v2" && in.ProxyAccept != "auto" {
		return errors.New("Proxy Protocol 接收模式无效")
	}
	if in.ProxySend != "off" && in.ProxySend != "v1" && in.ProxySend != "v2" {
		return errors.New("Proxy Protocol 发送版本无效")
	}
	if in.SpeedMbps < 0 || in.SpeedMbps > 100000 || in.IPLimit < 0 || in.IPLimit > 1000000 || in.ConnectionLimit < 0 || in.ConnectionLimit > 1000000 {
		return errors.New("规则限制超出范围")
	}
	if in.ProxyTrustedCIDRs == nil {
		in.ProxyTrustedCIDRs = []string{}
	}
	if len(in.ProxyTrustedCIDRs) > 64 {
		return errors.New("信任网段最多 64 个")
	}
	for _, p := range in.ProxyTrustedCIDRs {
		if _, e := netip.ParsePrefix(p); e != nil {
			return errors.New("Proxy Protocol 信任来源必须为 CIDR 网段")
		}
	}
	if in.ProxyAccept != "off" && len(in.ProxyTrustedCIDRs) == 0 {
		return errors.New("管理员尚未配置 Proxy Protocol 信任网段")
	}
	return nil
}
func (s *Server) ruleTx(ctx context.Context) (pgx.Tx, error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(734292)"); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func putRule(ctx context.Context, tx pgx.Tx, actor store.User, id int64, in RuleInput) (int64, error) {
	if !actor.IsAdmin {
		in.UserID = actor.ID
	}
	settings, err := readSystemSettings(ctx, tx)
	if err != nil {
		return 0, err
	}
	// Never accept a tenant-supplied trust boundary, including imports/batches.
	in.ProxyTrustedCIDRs = settings.ProxyTrustedCIDRs
	if e := in.normalize(); e != nil {
		return 0, e
	}
	policy, err := networkpolicy.Compile(settings.TargetDenyCIDRs)
	if err != nil {
		return 0, err
	}
	for _, target := range in.Targets {
		host, _, _ := net.SplitHostPort(target)
		if ip, e := netip.ParseAddr(host); e == nil && policy.Denied(ip) {
			return 0, errors.New("目标 IP 位于管理员禁止的网段")
		}
	}
	if id != 0 {
		var owner int64
		if e := tx.QueryRow(ctx, "SELECT user_id FROM rules WHERE id=$1 AND ($2 OR user_id=$3) FOR UPDATE", id, actor.IsAdmin, actor.ID).Scan(&owner); e != nil {
			return 0, errors.New("规则不存在或无权操作")
		}
		if owner != in.UserID {
			return 0, errors.New("不能变更规则所属用户")
		}
	}
	var limit int
	var usable bool
	if _, e := tx.Exec(ctx, "SELECT id FROM users WHERE id=$1 FOR UPDATE", in.UserID); e != nil {
		return 0, e
	}
	if e := tx.QueryRow(ctx, "SELECT max_rules,enabled AND (expires_at IS NULL OR expires_at>now()) FROM user_entitlements WHERE id=$1", in.UserID).Scan(&limit, &usable); e != nil {
		return 0, e
	}
	if !usable {
		return 0, errors.New("用户已停用或到期")
	}
	var allowed bool
	if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM user_nodes WHERE user_id=$1 AND node_id=$2)", in.UserID, in.NodeID).Scan(&allowed); e != nil {
		return 0, e
	}
	if !allowed {
		return 0, errors.New("用户没有此入口节点的权限")
	}
	if e := tx.QueryRow(ctx, "SELECT ingress_enabled FROM nodes WHERE id=$1", in.NodeID).Scan(&allowed); e != nil {
		return 0, e
	}
	if !allowed {
		return 0, errors.New("此节点未启用入口功能，只能选择其他入口")
	}
	if in.EgressNodeID == 0 {
		if e := tx.QueryRow(ctx, "SELECT allow_direct FROM nodes WHERE id=$1", in.NodeID).Scan(&allowed); e != nil {
			return 0, e
		}
		if !allowed {
			return 0, errors.New("此入口不允许直转，请选择出口节点")
		}
	} else {
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_tunnel_links l JOIN nodes n ON n.id=l.egress_node_id AND n.enabled AND n.tunnel_exit_enabled JOIN user_nodes u ON u.node_id=n.id AND u.user_id=$3 WHERE l.ingress_node_id=$1 AND l.egress_node_id=$2)`, in.NodeID, in.EgressNodeID, in.UserID).Scan(&allowed); e != nil {
			return 0, e
		}
		if !allowed {
			return 0, errors.New("出口节点未与该入口关联、不可用或用户无权使用")
		}
	}
	if in.EgressNodeID != 0 {
		var mode string
		if err := tx.QueryRow(ctx, "SELECT tunnel_protocol FROM nodes WHERE id=$1", in.EgressNodeID).Scan(&mode); err != nil {
			return 0, err
		}
		if tunnel.UDP(mode) && in.Protocol != "udp" {
			return 0, errors.New("raw(udp) 出口只支持 UDP 转发")
		}
	}
	if in.GroupID != 0 {
		if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rule_groups WHERE id=$1 AND user_id=$2)", in.GroupID, in.UserID).Scan(&allowed); e != nil {
			return 0, e
		}
		if !allowed {
			return 0, errors.New("分组不属于该用户")
		}
	}
	if id == 0 {
		var count int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM rules WHERE user_id=$1", in.UserID).Scan(&count); e != nil {
			return 0, e
		}
		if limit > 0 && count >= limit {
			return 0, errors.New("规则数量已达上限")
		}
	}
	var portMin, portMax int
	if err := tx.QueryRow(ctx, "SELECT port_min,port_max FROM nodes WHERE id=$1", in.NodeID).Scan(&portMin, &portMax); err != nil {
		return 0, err
	}
	if in.ListenPort != 0 && (in.ListenPort < portMin || in.ListenPort > portMax) {
		return 0, fmt.Errorf("监听端口须在节点允许范围 %d–%d 内", portMin, portMax)
	}
	if in.ListenPort == 0 {
		// The rule transaction lock serializes allocation, including import and switch operations.
		if e := tx.QueryRow(ctx, `SELECT p FROM generate_series($3::integer,$4::integer) p WHERE NOT EXISTS(SELECT 1 FROM rule_ports WHERE node_id=$1 AND listen_port=p AND rule_id<>$2 AND ($5='tcp_udp' OR protocol=$5)) ORDER BY random() LIMIT 1`, in.NodeID, id, portMin, portMax, in.Protocol).Scan(&in.ListenPort); e != nil {
			return 0, errors.New("没有可分配端口")
		}
	}
	targets, _ := json.Marshal(in.Targets)
	trusted, _ := json.Marshal(in.ProxyTrustedCIDRs)
	if id == 0 {
		if e := tx.QueryRow(ctx, `INSERT INTO rules(user_id,node_id,listen_port,target_host,target_port,enabled,egress_node_id,protocol) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,0),$8) RETURNING id`, in.UserID, in.NodeID, in.ListenPort, in.TargetHost, in.TargetPort, in.Enabled, in.EgressNodeID, in.Protocol).Scan(&id); e != nil {
			return 0, e
		}
	}
	_, e := tx.Exec(ctx, `UPDATE rules SET node_id=$2,name=$3,group_id=NULLIF($4,0),listen_port=$5,target_host=$6,target_port=$7,enabled=$8,targets=$9,balance=$10,speed_mbps=$11,ip_limit=$12,connection_limit=$13,proxy_accept=$14,proxy_send=$15,proxy_trusted_cidrs=$16,egress_node_id=NULLIF($17,0),protocol=$18,config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=$1`, id, in.NodeID, in.Name, in.GroupID, in.ListenPort, in.TargetHost, in.TargetPort, in.Enabled, targets, in.Balance, in.SpeedMbps, in.IPLimit, in.ConnectionLimit, in.ProxyAccept, in.ProxySend, trusted, in.EgressNodeID, in.Protocol)
	if e == nil {
		_, e = tx.Exec(ctx, "INSERT INTO rule_usage(node_id,rule_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", in.NodeID, id, in.UserID)
	}
	return id, e
}
func finishRules(ctx context.Context, tx pgx.Tx) error {
	if e := store.New(tx).BumpRevision(ctx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Server) saveRule(w http.ResponseWriter, r *http.Request) {
	var in RuleInput
	if !decode(w, r, &in) {
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	tx, e := s.ruleTx(r.Context())
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	id, e = putRule(r.Context(), tx, ruleActor(r), id, in)
	if e != nil {
		fail(w, 400, publicOperationError(e))
		return
	}
	if e = finishRules(r.Context(), tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	settings, e := s.readSettings(r.Context())
	if e != nil {
		s.dbError(w, e)
		return
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT r.id,r.user_id,r.node_id,COALESCE(r.egress_node_id,0) AS egress_node_id,COALESCE(en.name,'') AS egress_node_name,COALESCE(en.tunnel_protocol,'') AS egress_tunnel_protocol,r.protocol,r.listen_host,r.listen_port,r.target_host,r.target_port,r.enabled,r.name,r.group_id,r.targets,r.balance,r.proxy_accept,r.proxy_send,r.proxy_trusted_cidrs,r.traffic_baseline,r.config_revision,u.rule_speed_bps/125000 AS speed_mbps,u.rule_ip_limit AS ip_limit,u.rule_connection_limit AS connection_limit,u.username,n.name AS node_name,n.public_address,n.last_seen,n.sync_error,n.applied_revision,
 COALESCE(g.name,'') AS group_name,GREATEST(COALESCE((SELECT sum(t.traffic) FROM rule_usage t WHERE t.rule_id=r.id),0)::bigint-r.traffic_baseline,0) AS traffic_bytes,
 CASE WHEN NOT r.enabled THEN 'disabled' WHEN NOT u.account_enabled THEN 'user_disabled' WHEN u.plan_id IS NULL THEN 'no_plan' WHEN NOT u.plan_enabled THEN 'plan_disabled' WHEN u.expires_at<=now() THEN 'expired' WHEN NOT n.ingress_enabled OR NOT EXISTS(SELECT 1 FROM user_nodes un WHERE un.user_id=r.user_id AND un.node_id=r.node_id) OR (r.egress_node_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM user_nodes un WHERE un.user_id=r.user_id AND un.node_id=r.egress_node_id)) THEN 'unauthorized'
 WHEN u.quota_bytes>=0 AND (u.quota_bytes<=u.traffic_base_bytes+COALESCE((SELECT sum(traffic) FROM current_grants WHERE user_id=u.id),0) OR u.quota_bytes<u.traffic_base_bytes+COALESCE((SELECT sum(issued-released+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)) THEN 'quota_exhausted'
	 WHEN n.last_seen IS NULL OR n.last_seen<now()-interval '12 seconds' OR (en.id IS NOT NULL AND (en.last_seen IS NULL OR en.last_seen<now()-interval '12 seconds')) THEN 'offline'
	 WHEN $3 AND (n.protocol_version<14 OR (en.id IS NOT NULL AND en.protocol_version<14)) THEN 'upgrade_required'
 WHEN r.proxy_accept<>'off' AND $4 THEN 'proxy_untrusted'
 WHEN (r.protocol<>'tcp' OR en.tunnel_protocol IN ('plain_udp','dtls_udp')) AND (n.protocol_version<16 OR (en.id IS NOT NULL AND en.protocol_version<16)) THEN 'upgrade_required'
 WHEN r.proxy_accept='auto' AND n.protocol_version<10 THEN 'upgrade_required'
	 WHEN en.tunnel_protocol='tls_h2' AND (n.protocol_version<11 OR en.protocol_version<11) THEN 'upgrade_required'
 WHEN en.tunnel_protocol IN ('tls_tcp','plain_h2') AND (n.protocol_version<13 OR en.protocol_version<13) THEN 'upgrade_required'
	 WHEN n.sync_error<>'' OR COALESCE(en.sync_error,'')<>'' THEN 'failed' WHEN n.applied_revision<r.config_revision OR (en.id IS NOT NULL AND en.applied_revision<r.config_revision) THEN 'pending' ELSE 'active' END AS status
	 FROM rules r JOIN user_entitlements u ON u.id=r.user_id JOIN nodes n ON n.id=r.node_id LEFT JOIN nodes en ON en.id=r.egress_node_id LEFT JOIN rule_groups g ON g.id=r.group_id WHERE $1 OR r.user_id=$2 ORDER BY r.id DESC`, u.IsAdmin, u.ID, len(settings.TargetDenyCIDRs) > 0, len(settings.ProxyTrustedCIDRs) == 0)
	if e != nil {
		s.dbError(w, e)
		return
	}
	v, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	for _, rule := range v {
		rule["proxy_trusted_cidrs"] = settings.ProxyTrustedCIDRs
	}
	writeJSON(w, 200, v)
}
func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	s.applyBatch(w, r, BatchInput{IDs: []int64{id}, Action: "delete"})
}

type BatchInput struct {
	IDs     []int64 `json:"ids"`
	Action  string  `json:"action"`
	GroupID int64   `json:"group_id"`
	NodeID  int64   `json:"node_id"`
}

func (s *Server) batchRules(w http.ResponseWriter, r *http.Request) {
	var in BatchInput
	if !decode(w, r, &in) {
		return
	}
	s.applyBatch(w, r, in)
}
func (s *Server) applyBatch(w http.ResponseWriter, r *http.Request, in BatchInput) {
	if len(in.IDs) == 0 || len(in.IDs) > 500 {
		fail(w, 400, "请选择 1–500 条规则")
		return
	}
	unique := map[int64]bool{}
	for _, id := range in.IDs {
		if id <= 0 || unique[id] {
			fail(w, 400, "规则 ID 无效或重复")
			return
		}
		unique[id] = true
	}
	ctx := r.Context()
	u := ruleActor(r)
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var count int
	e = tx.QueryRow(ctx, "SELECT count(*) FROM rules WHERE id=ANY($1) AND ($2 OR user_id=$3)", in.IDs, u.IsAdmin, u.ID).Scan(&count)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if count != len(in.IDs) {
		fail(w, 403, "选择中包含不存在或无权操作的规则")
		return
	}
	switch in.Action {
	case "delete":
		_, e = tx.Exec(ctx, "DELETE FROM rules WHERE id=ANY($1)", in.IDs)
	case "enable", "disable":
		_, e = tx.Exec(ctx, "UPDATE rules SET enabled=$2,config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=ANY($1)", in.IDs, in.Action == "enable")
	case "clear":
		_, e = tx.Exec(ctx, "UPDATE rules r SET traffic_baseline=COALESCE((SELECT sum(traffic) FROM rule_usage WHERE rule_id=r.id),0) WHERE id=ANY($1)", in.IDs)
	case "group":
		if in.GroupID != 0 {
			var n int
			e = tx.QueryRow(ctx, "SELECT count(*) FROM rules r JOIN rule_groups g ON g.user_id=r.user_id AND g.id=$2 WHERE r.id=ANY($1)", in.IDs, in.GroupID).Scan(&n)
			if e == nil && n != len(in.IDs) {
				fail(w, 400, "规则和分组必须属于同一个用户")
				return
			}
		}
		if e == nil {
			_, e = tx.Exec(ctx, "UPDATE rules SET group_id=NULLIF($2,0) WHERE id=ANY($1)", in.IDs, in.GroupID)
		}
	case "switch":
		for _, id := range in.IDs {
			var input RuleInput
			input, e = loadRule(ctx, tx, id)
			if e != nil {
				break
			}
			input.NodeID = in.NodeID
			input.ListenPort = 0
			_, e = putRule(ctx, tx, u, id, input)
			if e != nil {
				break
			}
		}
	default:
		fail(w, 400, "未知批量操作")
		return
	}
	if e != nil {
		fail(w, 400, publicOperationError(e))
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "count": len(in.IDs)})
}
func loadRule(ctx context.Context, tx pgx.Tx, id int64) (RuleInput, error) {
	var v RuleInput
	var targets, trusted []byte
	e := tx.QueryRow(ctx, `SELECT user_id,node_id,COALESCE(egress_node_id,0),name,COALESCE(group_id,0),listen_port,targets,balance,speed_mbps,ip_limit,connection_limit,proxy_accept,proxy_send,proxy_trusted_cidrs,enabled,protocol FROM rules WHERE id=$1`, id).Scan(&v.UserID, &v.NodeID, &v.EgressNodeID, &v.Name, &v.GroupID, &v.ListenPort, &targets, &v.Balance, &v.SpeedMbps, &v.IPLimit, &v.ConnectionLimit, &v.ProxyAccept, &v.ProxySend, &trusted, &v.Enabled, &v.Protocol)
	if e == nil {
		e = json.Unmarshal(targets, &v.Targets)
	}
	if e == nil {
		e = json.Unmarshal(trusted, &v.ProxyTrustedCIDRs)
	}
	return v, e
}
func (s *Server) importRules(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rules []RuleInput `json:"rules"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Rules) == 0 || len(in.Rules) > 500 {
		fail(w, 400, "每次导入 1–500 条规则")
		return
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	ids := []int64{}
	for i, v := range in.Rules {
		id, err := putRule(ctx, tx, ruleActor(r), 0, v)
		if err != nil {
			fail(w, 400, fmt.Sprintf("第 %d 条：%s；本次导入未保存", i+1, publicOperationError(err)))
			return
		}
		ids = append(ids, id)
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"ids": ids})
}
func (s *Server) ruleStats(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	id, _ := strconv.ParseInt(r.URL.Query().Get("rule_id"), 10, 64)
	if id != 0 {
		var ok bool
		if e := s.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM rules WHERE id=$1 AND ($2 OR user_id=$3))", id, u.IsAdmin, u.ID).Scan(&ok); e != nil {
			s.dbError(w, e)
			return
		}
		if !ok {
			fail(w, 404, "规则不存在")
			return
		}
	}
	owner := u.ID
	if u.IsAdmin {
		owner, _ = strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT date_trunc('hour',created_at) AS time,sum(traffic_bytes)::bigint AS bytes FROM rule_events WHERE created_at>now()-interval '24 hours' AND ($1 OR user_id=$2) AND ($3::bigint=0 OR rule_id=$3) GROUP BY 1 ORDER BY 1`, u.IsAdmin && owner == 0, owner, id)
	if e != nil {
		s.dbError(w, e)
		return
	}
	v, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, v)
}
