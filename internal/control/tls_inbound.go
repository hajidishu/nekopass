package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tlsinbound"
	"net/http"
)

func (s *Server) tlsInbounds(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var name string
	var only bool
	var version int
	if err := s.Pool.QueryRow(r.Context(), "SELECT name,tls_inbound_only,protocol_version FROM nodes WHERE id=$1", id).Scan(&name, &only, &version); err != nil {
		fail(w, 404, "节点不存在")
		return
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT t.id,t.node_id,t.config,(SELECT count(*) FROM rules WHERE tls_inbound_id=t.id) rule_count FROM node_tls_inbounds t WHERE node_id=$1 ORDER BY t.id`, id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	values, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	candidates, err := s.Pool.Query(r.Context(), "SELECT r.id,r.name,r.tls_inbound_id FROM rules r JOIN users u ON u.id=r.user_id WHERE r.node_id=$1 AND u.is_admin AND r.tls_inbound_id IS NOT NULL", id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	defaults, err := pgx.CollectRows(candidates, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "node_name": name, "tls_only": only, "protocol_version": version, "inbounds": values, "default_rules": defaults})
}
func (s *Server) saveTLSInbound(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	node, ok := resourceID(w, r)
	if !ok {
		return
	}
	var in struct {
		ID     int64             `json:"id"`
		Config tlsinbound.Config `json:"config"`
	}
	in.Config = tlsinbound.DefaultConfig()
	if !decode(w, r, &in) {
		return
	}
	if in.ID < 0 {
		fail(w, 400, "入口标识无效")
		return
	}
	if err := in.Config.Normalize(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx := r.Context()
	tx, err := s.ruleTx(ctx)
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var exists int64
	if err = tx.QueryRow(ctx, "SELECT id FROM nodes WHERE id=$1 FOR UPDATE", node).Scan(&exists); err != nil {
		fail(w, 404, "节点不存在")
		return
	}
	cfg := in.Config
	if cfg.ProxyAccept != "off" {
		settings, e := readSystemSettings(ctx, tx)
		if e != nil {
			s.dbError(w, e)
			return
		}
		if len(settings.ProxyTrustedCIDRs) == 0 {
			fail(w, 400, "请先配置 PROXY Protocol 信任来源")
			return
		}
	}
	if in.ID != 0 {
		if err = tx.QueryRow(ctx, "SELECT id FROM node_tls_inbounds WHERE id=$1 AND node_id=$2 FOR UPDATE", in.ID, node).Scan(&exists); err != nil {
			fail(w, 404, "共享 TLS 入口不存在")
			return
		}
	}
	var collision bool
	err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND tunnel_exit_enabled AND tunnel_listen_port=$2 AND tunnel_protocol NOT IN ('plain_udp','dtls_udp','random_udp')) OR EXISTS(SELECT 1 FROM rule_ports WHERE node_id=$1 AND protocol='tcp' AND listen_port=$2 AND COALESCE(tls_inbound_id,0)<>$3)", node, cfg.Port, in.ID).Scan(&collision)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if collision {
		fail(w, 409, "端口已被转发规则、隧道或其他 TLS 入口占用")
		return
	}
	if cfg.DefaultRuleID != 0 {
		var valid bool
		err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM rules r JOIN users u ON u.id=r.user_id WHERE r.id=$1 AND r.node_id=$2 AND r.tls_inbound_id=$3 AND u.is_admin)", cfg.DefaultRuleID, node, in.ID).Scan(&valid)
		if err != nil || !valid {
			fail(w, 400, "默认规则须为当前共享入口下的管理员规则")
			return
		}
	}
	// Allowlist edits must not silently invalidate existing registered names.
	check, err := tx.Query(ctx, "SELECT name FROM rule_sni_names WHERE tls_inbound_id=$1", in.ID)
	if err != nil {
		s.dbError(w, err)
		return
	}
	var names []string
	for check.Next() {
		var value string
		if err = check.Scan(&value); err != nil {
			break
		}
		names = append(names, value)
	}
	if err == nil {
		err = check.Err()
	}
	check.Close()
	if err != nil {
		s.dbError(w, err)
		return
	}
	for _, name := range names {
		if !cfg.Allows(name) {
			fail(w, 409, "新允许范围未覆盖已有规则的 SNI，请先调整规则")
			return
		}
	}
	data, _ := json.Marshal(cfg)
	if in.ID == 0 {
		var count int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM node_tls_inbounds WHERE node_id=$1", node).Scan(&count); err != nil {
			s.dbError(w, err)
			return
		}
		if count >= 64 {
			fail(w, 400, "单节点最多配置 64 个共享 TLS 入口")
			return
		}
		err = tx.QueryRow(ctx, "INSERT INTO node_tls_inbounds(node_id,config,port) VALUES($1,$2,$3) RETURNING id", node, data, cfg.Port).Scan(&in.ID)
		if err != nil {
			fail(w, 409, "共享入口端口冲突")
			return
		}
	}
	_, err = tx.Exec(ctx, "UPDATE node_tls_inbounds SET config=$2,port=$3,generation=generation+1 WHERE id=$1", in.ID, data, cfg.Port)
	if err != nil {
		fail(w, 409, "共享入口端口冲突")
		return
	}
	if err = touchTLSInboundNode(ctx, tx, node); err != nil {
		s.dbError(w, err)
		return
	}
	if err = finishRules(ctx, tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": in.ID})
}
func (s *Server) deleteTLSInbound(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	node, ok := resourceID(w, r)
	if !ok {
		return
	}
	var in struct {
		ID int64 `json:"id"`
	}
	if !decode(w, r, &in) {
		return
	}
	tx, err := s.ruleTx(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var count int
	if err = tx.QueryRow(r.Context(), "SELECT count(*) FROM rules WHERE tls_inbound_id=$1", in.ID).Scan(&count); err != nil {
		s.dbError(w, err)
		return
	}
	if count > 0 {
		fail(w, 409, "请先删除或迁移使用该共享入口的规则")
		return
	}
	tag, err := tx.Exec(r.Context(), "DELETE FROM node_tls_inbounds WHERE id=$1 AND node_id=$2", in.ID, node)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "入口不存在")
		return
	}
	if err = touchTLSInboundNode(r.Context(), tx, node); err != nil {
		s.dbError(w, err)
		return
	}
	if err = finishRules(r.Context(), tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) tlsInboundPolicy(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var in struct {
		TLSOnly bool `json:"tls_only"`
	}
	if !decode(w, r, &in) {
		return
	}
	tx, err := s.ruleTx(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), "UPDATE nodes SET tls_inbound_only=$2 WHERE id=$1", id, in.TLSOnly)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "节点不存在")
		return
	}
	if err = touchTLSInboundNode(r.Context(), tx, id); err != nil {
		s.dbError(w, err)
		return
	}
	if err = finishRules(r.Context(), tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) tlsInboundChoices(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	rows, err := s.Pool.Query(r.Context(), `SELECT t.id,t.node_id,t.port,t.config->>'name' name,t.config->'allowed_sni' allowed_sni FROM node_tls_inbounds t JOIN user_nodes un ON un.node_id=t.node_id AND un.user_id=$1 JOIN nodes n ON n.id=t.node_id WHERE n.ingress_enabled AND t.config->>'enabled'='true' ORDER BY t.id`, u.ID)
	if err != nil {
		s.dbError(w, err)
		return
	}
	values, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, values)
}
func appendTLSInboundControl(ctx context.Context, tx pgx.Tx, node int64, out *pb.ControlMessage) error {
	if err := tx.QueryRow(ctx, "SELECT tls_inbound_only FROM nodes WHERE id=$1", node).Scan(&out.Node.TlsInboundOnly); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT t.id,t.config,COALESCE((SELECT r.id FROM rules r JOIN users u ON u.id=r.user_id WHERE r.id=(t.config->>'default_rule_id')::bigint AND r.tls_inbound_id=t.id AND u.is_admin),0) FROM node_tls_inbounds t WHERE t.node_id=$1 ORDER BY t.id", node)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, defaultRule int64
		var raw []byte
		if err = rows.Scan(&id, &raw, &defaultRule); err != nil {
			return err
		}
		cfg := tlsinbound.DefaultConfig()
		if err = json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
		if err = cfg.Normalize(); err != nil {
			return err
		}
		out.Node.TlsInbounds = append(out.Node.TlsInbounds, &pb.SharedTLSInbound{Id: id, Port: int32(cfg.Port), Enabled: cfg.Enabled, AllowedSni: cfg.AllowedSNI, RejectEmptySni: cfg.RejectEmptySNI, DefaultRuleId: defaultRule, ProxyAccept: cfg.ProxyAccept, MaxHandshakes: int32(cfg.MaxHandshakes), HandshakeTimeoutSeconds: int32(cfg.HandshakeTimeoutSeconds), Passthrough: true})
	}
	return rows.Err()
}
func validateTLSRule(ctx context.Context, tx pgx.Tx, in *RuleInput, id int64) error {
	var only bool
	if err := tx.QueryRow(ctx, "SELECT tls_inbound_only FROM nodes WHERE id=$1", in.NodeID).Scan(&only); err != nil {
		return err
	}
	if in.TLSInboundID == 0 {
		if only && in.Protocol == "tcp" {
			return errors.New("此入口仅允许共享 TLS 入站规则")
		}
		return nil
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT config FROM node_tls_inbounds WHERE id=$1 AND node_id=$2", in.TLSInboundID, in.NodeID).Scan(&raw); err != nil {
		return errors.New("共享 TLS 入口不存在或不属于当前节点")
	}
	var cfg tlsinbound.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if !cfg.Enabled && id == 0 {
		return errors.New("共享 TLS 入口已关闭")
	}
	for _, name := range in.SNINames {
		if !cfg.Allows(name) {
			return errors.New("SNI 不在管理员允许范围内")
		}

	}
	return nil
}
func touchTLSInboundNode(ctx context.Context, tx pgx.Tx, node int64) error {
	if _, err := tx.Exec(ctx, "UPDATE nodes SET config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=$1", node); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE rules SET config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE node_id=$1", node)
	return err
}
