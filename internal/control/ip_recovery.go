package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nekopass/nekopass/internal/iprecovery"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net/http"
	"strings"
	"time"
)

func (s *Server) nodeIPRecovery(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var name string
	var protocol int
	var online bool
	if err := s.Pool.QueryRow(r.Context(), "SELECT name,protocol_version,COALESCE(last_seen>now()-interval '12 seconds',false) FROM nodes WHERE id=$1", id).Scan(&name, &protocol, &online); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "节点不存在")
		} else {
			s.dbError(w, err)
		}
		return
	}
	cfg := iprecovery.DefaultConfig()
	var raw, status []byte
	var generation int64
	var received *time.Time
	err := s.Pool.QueryRow(r.Context(), "SELECT config,generation,status,status_received_at FROM node_ip_recovery WHERE node_id=$1", id).Scan(&raw, &generation, &status, &received)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.dbError(w, err)
		return
	}
	if len(raw) > 0 && json.Unmarshal(raw, &cfg) != nil {
		fail(w, 500, "自动换 IP 配置无法读取")
		return
	}
	report := map[string]any{}
	if len(status) > 0 && json.Unmarshal(status, &report) != nil {
		fail(w, 500, "自动换 IP 状态无法读取")
		return
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "node_name": name, "protocol_version": protocol, "online": online, "config": cfg, "generation": generation, "status": report, "status_received_at": received})
}
func (s *Server) saveNodeIPRecovery(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	cfg := iprecovery.DefaultConfig()
	if !decode(w, r, &cfg) {
		return
	}
	if err := cfg.Normalize(); err != nil {
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
	if err = tx.QueryRow(ctx, "SELECT id FROM nodes WHERE id=$1 FOR UPDATE", id).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 404, "节点不存在")
		} else {
			s.dbError(w, err)
		}
		return
	}
	raw, _ := json.Marshal(cfg)
	state := "disabled"
	if cfg.Enabled {
		state = "pending"
	}
	var generation int64
	err = tx.QueryRow(ctx, `INSERT INTO node_ip_recovery(node_id,config,status) VALUES($1,$2,jsonb_build_object('state',$3::text)) ON CONFLICT(node_id) DO UPDATE SET config=$2,generation=node_ip_recovery.generation+1,status=jsonb_build_object('state',$3::text),status_received_at=NULL RETURNING generation`, id, raw, state).Scan(&generation)
	if err != nil {
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			fail(w, 409, "该小助理实例或档案已有其他节点启用自动换 IP")
			return
		}
		s.dbError(w, err)
		return
	}
	if err = finishRules(ctx, tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"generation": generation})
}
func (s *Server) resetNodeIPRecovery(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tx, err := s.ruleTx(ctx)
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var generation int64
	err = tx.QueryRow(ctx, `UPDATE node_ip_recovery SET generation=generation+1,reset_sequence=reset_sequence+1,status=jsonb_build_object('state','pending'),status_received_at=NULL WHERE node_id=$1 RETURNING generation`, id).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 409, "请先保存自动换 IP 配置")
		return
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	if err = finishRules(ctx, tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"generation": generation})
}
func appendIPRecoveryControl(ctx context.Context, tx pgx.Tx, node int64, out *pb.ControlMessage) error {
	var raw []byte
	var generation, reset int64
	err := tx.QueryRow(ctx, "SELECT config,generation,reset_sequence FROM node_ip_recovery WHERE node_id=$1", node).Scan(&raw, &generation, &reset)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg := iprecovery.DefaultConfig()
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return errors.New("自动换 IP 配置无效")
	}
	if err = cfg.Normalize(); err != nil {
		return err
	}
	enabled := cfg.Enabled
	if cfg.BindingMode == "profile" {
		var version int32
		if err = tx.QueryRow(ctx, "SELECT protocol_version FROM nodes WHERE id=$1", node).Scan(&version); err != nil {
			return err
		}
		// Older agents ignore the binding fields and could act on an obsolete
		// fixed instance saved in this form. Send disabled until they upgrade.
		enabled = enabled && version >= pb.IPRecoveryProfileVersion
	}
	out.Node.IpRecovery = &pb.IPRecoveryConfig{Enabled: enabled, Generation: generation, ResetSequence: reset, TargetIp: cfg.TargetIP, FailureThreshold: int32(cfg.FailureThreshold), CooldownSeconds: int32(cfg.CooldownSeconds), InstanceType: cfg.InstanceType, AuthToken: cfg.AuthToken, ShareGroupToken: cfg.ShareGroupToken, AccountId: cfg.AccountID, RegionName: cfg.RegionName, InstanceId: cfg.InstanceID, StaticIp: cfg.StaticIP, BindingMode: cfg.BindingMode, ProfileId: cfg.ProfileID}
	return nil
}
func acceptIPRecoveryReport(ctx context.Context, tx pgx.Tx, node int64, status *pb.IPRecoveryStatus) error {
	if status == nil {
		return nil
	}
	if status.Generation < 1 || status.Failures < 0 || status.Failures > 720 || status.CheckedUnix < 0 || status.LastAttemptUnix < 0 || status.LastChangedUnix < 0 || status.CooldownUntilUnix < 0 {
		return errors.New("自动换 IP 状态数值无效")
	}
	switch status.State {
	case "disabled", "checking", "healthy", "unreachable", "cooldown", "changing", "waiting", "uncertain", "error":
	default:
		return errors.New("自动换 IP 状态无效")
	}
	for _, ip := range []string{status.OldIp, status.NewIp} {
		if ip != "" && !iprecovery.PublicIPv4(ip) {
			return errors.New("自动换 IP 状态地址无效")
		}
	}
	for _, value := range []string{status.InstanceId, status.AccountId, status.RegionName} {
		if len(value) > 255 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("自动换 IP 实例状态无效")
		}
	}
	var generation int64
	var raw, previous []byte
	err := tx.QueryRow(ctx, "SELECT generation,config,status FROM node_ip_recovery WHERE node_id=$1 FOR UPDATE", node).Scan(&generation, &raw, &previous)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && generation != status.Generation {
		return nil
	}
	if err != nil {
		return err
	}
	var last iprecovery.Status
	if json.Unmarshal(previous, &last) == nil && status.CheckedUnix < last.CheckedUnix {
		return nil
	}
	var cfg iprecovery.Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	feedback := strings.TrimSpace(status.Error)
	for _, secret := range []string{cfg.AuthToken, cfg.ShareGroupToken} {
		if secret != "" {
			feedback = strings.ReplaceAll(feedback, secret, "[已隐藏]")
		}
	}
	report := iprecovery.Status{Generation: status.Generation, State: status.State, Failures: int(status.Failures), Reachable: status.Reachable, CheckedUnix: status.CheckedUnix, LastAttemptUnix: status.LastAttemptUnix, LastChangedUnix: status.LastChangedUnix, CooldownUntilUnix: status.CooldownUntilUnix, OldIP: status.OldIp, NewIP: status.NewIp, Error: truncate(feedback, 500), InstanceID: status.InstanceId, AccountID: status.AccountId, RegionName: status.RegionName}
	data, _ := json.Marshal(report)
	_, err = tx.Exec(ctx, "UPDATE node_ip_recovery SET status=$3,status_received_at=now() WHERE node_id=$1 AND generation=$2", node, generation, data)
	return err
}
