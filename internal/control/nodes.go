package control

import (
	"context"
	"encoding/json"
	"github.com/nekopass/nekopass/internal/store"
	"net"
	"net/http"
	"path"
	"regexp"
	"strings"
)

type NodeInput struct {
	TLS                  *TunnelTLSConfig `json:"tls"`
	Token                string           `json:"token"`
	Name                 string           `json:"name"`
	PublicAddress        string           `json:"public_address"`
	Notes                string           `json:"notes"`
	Enabled              bool             `json:"enabled"`
	GroupIDs             []int64          `json:"group_ids"`
	ListenHost           string           `json:"listen_host"`
	PortMin              int              `json:"port_min"`
	PortMax              int              `json:"port_max"`
	MaxConnections       int64            `json:"max_connections"`
	DialTimeoutSeconds   int              `json:"dial_timeout_seconds"`
	IdleTimeoutSeconds   int              `json:"idle_timeout_seconds"`
	ProbeIntervalSeconds int              `json:"probe_interval_seconds"`
	DiskPath             string           `json:"disk_path"`
	NetworkInterfaces    []string         `json:"network_interfaces"`
	AllowDirect          bool             `json:"allow_direct"`
	IngressEnabled       bool             `json:"ingress_enabled"`
	TunnelExitEnabled    bool             `json:"tunnel_exit_enabled"`
	TunnelProtocol       string           `json:"tunnel_protocol"`
	TunnelListenHost     string           `json:"tunnel_listen_host"`
	TunnelListenPort     int              `json:"tunnel_listen_port"`
	TunnelPublicHost     string           `json:"tunnel_public_host"`
	AllowedIngressIDs    []int64          `json:"allowed_ingress_ids"`
}

var nodeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

func validNodeToken(v string) bool { return nodeTokenPattern.MatchString(v) }

func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT n.id,n.name,n.agent_version,n.update_supported,(SELECT jsonb_build_object('generation',u.generation,'version',u.version,'state',CASE WHEN u.state IN ('queued','running') AND u.requested_at<now()-interval '15 minutes' THEN 'unconfirmed' ELSE u.state END,'error',CASE WHEN u.state IN ('queued','running') AND u.requested_at<now()-interval '15 minutes' THEN '超过 15 分钟未收到更新结果，请检查节点连接及更新日志' ELSE u.error END,'requested_at',u.requested_at,'updated_at',u.updated_at) FROM node_updates u WHERE u.node_id=n.id) AS update_status,n.token,(n.instance_id<>'') AS bound,n.public_address,n.notes,n.enabled,n.listen_host,n.port_min,n.port_max,n.max_connections,n.dial_timeout_seconds,n.idle_timeout_seconds,n.probe_interval_seconds,n.disk_path,n.network_interfaces,n.ingress_enabled,n.allow_direct,n.tunnel_exit_enabled,n.tunnel_protocol,n.tls_config AS tls,n.tls_status,n.tls_error,n.tls_not_after,n.protocol_version,n.tunnel_listen_host,n.tunnel_listen_port,n.tunnel_public_host,n.last_seen,n.applied_revision,n.config_revision,n.sync_error,n.active_connections,n.probe,n.probe_received_at,COALESCE(n.last_seen>now()-interval '12 seconds',false) AS online,COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM node_group_members WHERE node_id=n.id),'{}') AS group_ids,COALESCE((SELECT array_agg(ingress_node_id ORDER BY ingress_node_id) FROM node_tunnel_links WHERE egress_node_id=n.id),'{}') AS allowed_ingress_ids,(SELECT count(*) FROM rules WHERE node_id=n.id) AS rule_count FROM nodes n ORDER BY n.id`)
	s.sendRows(w, rows, e)
}
func (s *Server) saveNode(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	v := NodeInput{Enabled: true, ListenHost: "0.0.0.0", PortMin: 1024, PortMax: 65535, MaxConnections: 10000, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, ProbeIntervalSeconds: 5, DiskPath: "/", NetworkInterfaces: []string{}, IngressEnabled: true, AllowDirect: true, TunnelProtocol: "plain_tcp", TunnelListenHost: "0.0.0.0"}
	if !decode(w, r, &v) {
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Token != "" && !validNodeToken(v.Token) {
		fail(w, 400, "节点密钥须为 8–128 位英文字母、数字、下划线或连字符")
		return
	}
	if v.AllowedIngressIDs == nil {
		v.AllowedIngressIDs = []int64{}
	}
	if v.Name == "" || len(v.Name) > 80 || len(v.Notes) > 4000 || (v.PublicAddress != "" && !ValidTarget(v.PublicAddress)) || net.ParseIP(v.ListenHost) == nil || v.PortMin < 1024 || v.PortMax > 65535 || v.PortMin > v.PortMax || v.MaxConnections < 0 || v.MaxConnections > 1000000 || v.DialTimeoutSeconds < 1 || v.DialTimeoutSeconds > 120 || v.IdleTimeoutSeconds < 10 || v.IdleTimeoutSeconds > 86400 || v.ProbeIntervalSeconds < 2 || v.ProbeIntervalSeconds > 60 || !path.IsAbs(v.DiskPath) || len(v.DiskPath) > 512 || len(v.NetworkInterfaces) > 32 || len(v.GroupIDs) > 1000 || len(v.AllowedIngressIDs) > 1000 || (v.TunnelProtocol != "plain_tcp" && v.TunnelProtocol != "tls_h2") || net.ParseIP(v.TunnelListenHost) == nil || (v.TunnelListenPort != 0 && (v.TunnelListenPort < 1 || v.TunnelListenPort > 65535)) || (v.TunnelPublicHost != "" && !ValidTarget(v.TunnelPublicHost)) || (v.TunnelExitEnabled && (v.TunnelListenPort == 0 || v.TunnelPublicHost == "")) || (!v.TunnelExitEnabled && len(v.AllowedIngressIDs) > 0) {
		fail(w, 400, "节点配置参数无效")
		return
	}
	for _, iface := range v.NetworkInterfaces {
		if len(iface) == 0 || len(iface) > 64 || strings.ContainsAny(iface, " /\t\r\n") {
			fail(w, 400, "网卡名称无效")
			return
		}
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	if e = revokeOverlappingAPIKey(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	previousProtocol := ""
	if id != 0 {
		if e = tx.QueryRow(ctx, "SELECT tunnel_protocol FROM nodes WHERE id=$1", id).Scan(&previousProtocol); e != nil {
			fail(w, 404, "节点不存在")
			return
		}
	}
	if id != 0 {
		var blocked bool
		if !v.IngressEnabled {
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules WHERE node_id=$1)", id).Scan(&blocked); e != nil {
				s.dbError(w, e)
				return
			}
			if blocked {
				fail(w, 409, "此节点仍作为入口被规则使用，请先迁移或删除这些规则")
				return
			}
		}
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules WHERE node_id=$1 AND egress_node_id IS NULL)", id).Scan(&blocked); e != nil {
			s.dbError(w, e)
			return
		}
		if !v.AllowDirect && blocked {
			fail(w, 409, "此入口仍有直转规则，请先修改规则出口")
			return
		}
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules WHERE egress_node_id=$1)", id).Scan(&blocked); e != nil {
			s.dbError(w, e)
			return
		}
		if !v.TunnelExitEnabled && blocked {
			fail(w, 409, "此出口仍被规则使用，请先修改规则出口")
			return
		}
		if v.TunnelExitEnabled && v.TunnelListenPort != 0 {
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules WHERE node_id=$1 AND listen_port=$2)", id, v.TunnelListenPort).Scan(&blocked); e != nil {
				s.dbError(w, e)
				return
			}
			if blocked {
				fail(w, 409, "隧道端口与此节点的转发规则端口冲突")
				return
			}
		}
	}
	links := map[int64]bool{}
	for _, ingress := range v.AllowedIngressIDs {
		if ingress <= 0 || ingress == id || links[ingress] {
			fail(w, 400, "入口节点列表无效或重复")
			return
		}
		links[ingress] = true
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND ingress_enabled)", ingress).Scan(&exists); e != nil {
			s.dbError(w, e)
			return
		}
		if !exists {
			fail(w, 400, "关联的节点不存在或未启用入口功能")
			return
		}
	}
	token := v.Token
	if token == "" {
		token = Secret()
	}
	var managementKey bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM site_settings WHERE api_key_hash=$1 AND api_key_hash<>'')", Hash(token)).Scan(&managementKey); e != nil {
		s.dbError(w, e)
		return
	}
	if managementKey {
		fail(w, 400, "节点密钥不能复用管理 API 密钥，请使用独立节点密钥")
		return
	}
	var tokenChanged bool
	if id == 0 {
		tokenChanged = true
		e = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", v.Name, Hash(token), token).Scan(&id)
	} else {
		var conflict bool
		e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules WHERE node_id=$1 AND listen_port NOT BETWEEN $2 AND $3)", id, v.PortMin, v.PortMax).Scan(&conflict)
		if e == nil && conflict {
			fail(w, 409, "已有规则端口超出新范围，请先修改这些规则")
			return
		}
		var previousHash string
		if e == nil {
			e = tx.QueryRow(ctx, "SELECT token_hash FROM nodes WHERE id=$1 FOR UPDATE", id).Scan(&previousHash)
		}
		tokenChanged = e == nil && previousHash != Hash(token)
	}
	if e != nil {
		s.dbError(w, e)
		return
	}
	interfaces, _ := json.Marshal(v.NetworkInterfaces)
	tag, e := tx.Exec(ctx, `UPDATE nodes SET name=$2,public_address=$3,notes=$4,enabled=$5,listen_host=$6,port_min=$7,port_max=$8,max_connections=$9,dial_timeout_seconds=$10,idle_timeout_seconds=$11,probe_interval_seconds=$12,disk_path=$13,network_interfaces=$14,allow_direct=$15,tunnel_exit_enabled=$16,tunnel_protocol=$17,tunnel_listen_host=$18,tunnel_listen_port=$19,tunnel_public_host=$20,token=$21,token_hash=$22,ingress_enabled=$23,config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=$1`, id, v.Name, v.PublicAddress, v.Notes, v.Enabled, v.ListenHost, v.PortMin, v.PortMax, v.MaxConnections, v.DialTimeoutSeconds, v.IdleTimeoutSeconds, v.ProbeIntervalSeconds, v.DiskPath, interfaces, v.AllowDirect, v.TunnelExitEnabled, v.TunnelProtocol, v.TunnelListenHost, v.TunnelListenPort, v.TunnelPublicHost, token, Hash(token), v.IngressEnabled)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "节点不存在")
		return
	}
	if e = prepareNodeTLS(ctx, tx, id, &v); e != nil {
		fail(w, 400, publicOperationError(e))
		return
	}
	if tokenChanged {
		if _, e = tx.Exec(ctx, "DELETE FROM node_install_tickets WHERE node_id=$1 AND used_at IS NULL", id); e != nil {
			s.dbError(w, e)
			return
		}
	}
	if !v.IngressEnabled {
		// No rules use this node as ingress, so retire its unused outgoing links.
		if _, e = tx.Exec(ctx, "DELETE FROM node_tunnel_links WHERE ingress_node_id=$1", id); e != nil {
			s.dbError(w, e)
			return
		}
	}
	if _, e = tx.Exec(ctx, "DELETE FROM node_tunnel_links l WHERE egress_node_id=$1 AND NOT (ingress_node_id=ANY($2::bigint[])) AND NOT EXISTS(SELECT 1 FROM rules r WHERE r.node_id=l.ingress_node_id AND r.egress_node_id=l.egress_node_id)", id, v.AllowedIngressIDs); e != nil {
		s.dbError(w, e)
		return
	}
	var still int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM node_tunnel_links WHERE egress_node_id=$1 AND NOT (ingress_node_id=ANY($2::bigint[]))", id, v.AllowedIngressIDs).Scan(&still); e != nil {
		s.dbError(w, e)
		return
	}
	if still > 0 {
		fail(w, 409, "已有规则使用即将移除的入口关联，请先修改规则")
		return
	}
	for ingress := range links {
		if _, e = tx.Exec(ctx, "INSERT INTO node_tunnel_links(ingress_node_id,egress_node_id,token) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", ingress, id, Secret()); e != nil {
			s.dbError(w, e)
			return
		}
		// A credential previously carried in plaintext must not remain valid
		// after switching to TLS, even if an observer recorded the old tunnel.
		if previousProtocol != "" && previousProtocol != v.TunnelProtocol {
			if _, e = tx.Exec(ctx, "UPDATE node_tunnel_links SET token=$3 WHERE ingress_node_id=$1 AND egress_node_id=$2", ingress, id, Secret()); e != nil {
				s.dbError(w, e)
				return
			}
		}
	}
	if _, e = tx.Exec(ctx, "DELETE FROM node_group_members WHERE node_id=$1", id); e != nil {
		s.dbError(w, e)
		return
	}
	for _, g := range v.GroupIDs {
		if _, e = tx.Exec(ctx, "INSERT INTO node_group_members(group_id,node_id) VALUES($1,$2) ON CONFLICT DO NOTHING", g, id); e != nil {
			s.dbError(w, e)
			return
		}
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	result := map[string]any{"id": id, "token": token}
	writeJSON(w, 200, result)
}
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	if e = revokeOverlappingAPIKey(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	tag, e := tx.Exec(ctx, `DELETE FROM nodes WHERE id=$1 AND NOT enabled AND (last_seen IS NULL OR applied_revision>=config_revision) AND NOT EXISTS(SELECT 1 FROM rules WHERE node_id=$1) AND NOT EXISTS(SELECT 1 FROM grants WHERE node_id=$1) AND NOT EXISTS(SELECT 1 FROM rule_usage WHERE node_id=$1)`, id)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 409, "请先停用节点并等待配置同步；存在规则或用量账本的节点需保留记录，不能删除")
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// Earlier releases stored only a hash. A successful node authentication lets us
// retain that original key for the admin UI without rotating a running node.
func (s *Server) nodeForToken(ctx context.Context, token string) (store.Node, error) {
	node, e := s.query.FindNodeByToken(ctx, Hash(token))
	if e != nil {
		return node, e
	}
	if node.Token == "" {
		if _, e = s.Pool.Exec(ctx, "UPDATE nodes SET token=$2 WHERE id=$1 AND token='' AND token_hash=$3", node.ID, token, Hash(token)); e != nil {
			return node, e
		}
		node.Token = token
	}
	return node, nil
}

func (s *Server) nodeGroups(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	rows, e := s.Pool.Query(r.Context(), `SELECT g.id,g.name,g.description,g.enabled,g.sort_order,g.strategy,COALESCE((SELECT array_agg(node_id ORDER BY node_id) FROM node_group_members WHERE group_id=g.id),'{}') AS node_ids,(SELECT count(*) FROM plan_node_groups WHERE group_id=g.id) AS plan_count FROM node_groups g ORDER BY g.sort_order,g.id`)
	s.sendRows(w, rows, e)
}
func (s *Server) saveNodeGroup(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var v struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Enabled     bool    `json:"enabled"`
		SortOrder   int     `json:"sort_order"`
		NodeIDs     []int64 `json:"node_ids"`
	}
	if !decode(w, r, &v) {
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Name == "" || len(v.Name) > 160 || len(v.Description) > 4000 || len(v.NodeIDs) > 10000 {
		fail(w, 400, "节点组参数无效")
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
		e = tx.QueryRow(ctx, "INSERT INTO node_groups(name) VALUES($1) RETURNING id", v.Name).Scan(&id)
		if e != nil {
			s.dbError(w, e)
			return
		}
	}
	tag, e := tx.Exec(ctx, "UPDATE node_groups SET name=$2,description=$3,enabled=$4,sort_order=$5 WHERE id=$1", id, v.Name, v.Description, v.Enabled, v.SortOrder)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "节点组不存在")
		return
	}
	if _, e = tx.Exec(ctx, "DELETE FROM node_group_members WHERE group_id=$1", id); e != nil {
		s.dbError(w, e)
		return
	}
	for _, n := range v.NodeIDs {
		if _, e = tx.Exec(ctx, "INSERT INTO node_group_members(group_id,node_id) VALUES($1,$2) ON CONFLICT DO NOTHING", id, n); e != nil {
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
func (s *Server) deleteNodeGroup(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	ctx := r.Context()
	tx, e := s.ruleTx(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "DELETE FROM node_groups WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM plan_node_groups WHERE group_id=$1) AND NOT EXISTS(SELECT 1 FROM user_node_groups WHERE group_id=$1)", id)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 409, "节点组不存在或正在被套餐或用户使用")
		return
	}
	if e = finishRules(ctx, tx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// This user-facing endpoint deliberately excludes addresses, configuration, tokens and sync errors.
func (s *Server) nodeStatus(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	rows, e := s.Pool.Query(r.Context(), `SELECT g.id AS group_id,g.name AS group_name,n.id,n.name,n.enabled,COALESCE(n.last_seen>now()-interval '12 seconds',false) AS online,
 CASE WHEN n.probe_received_at>now()-make_interval(secs=>GREATEST(n.probe_interval_seconds*3,15)) THEN n.probe ELSE NULL END AS metrics,n.probe_received_at AS updated_at
 FROM user_entitlements u JOIN plans p ON p.id=u.plan_id AND p.enabled
  JOIN user_node_groups pg ON pg.user_id=u.id JOIN node_groups g ON g.id=pg.group_id AND g.enabled
 JOIN node_group_members m ON m.group_id=g.id JOIN nodes n ON n.id=m.node_id
 WHERE u.id=$1 AND u.enabled AND (u.expires_at IS NULL OR u.expires_at>now()) ORDER BY g.sort_order,g.id,n.id`, u.ID)
	s.sendRows(w, rows, e)
}
