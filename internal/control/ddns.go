package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
)

func (s *Server) nodeDDNS(w http.ResponseWriter, r *http.Request) {
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
	cfg := ddns.DefaultConfig()
	var data, status []byte
	var generation int64
	var received *time.Time
	err := s.Pool.QueryRow(r.Context(), "SELECT config,generation,status,status_received_at FROM node_ddns WHERE node_id=$1", id).Scan(&data, &generation, &status, &received)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.dbError(w, err)
		return
	}
	if len(data) > 0 && json.Unmarshal(data, &cfg) != nil {
		fail(w, 500, "DDNS 配置无法读取")
		return
	}
	var report map[string]any
	if len(status) > 0 {
		if json.Unmarshal(status, &report) != nil {
			fail(w, 500, "DDNS 状态无法读取")
			return
		}
	}
	if report == nil {
		report = map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "node_name": name, "protocol_version": protocol, "online": online, "config": cfg, "generation": generation, "status": report, "status_received_at": received})
}

func (s *Server) saveNodeDDNS(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	cfg := ddns.DefaultConfig()
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
	data, _ := json.Marshal(cfg)
	state := "disabled"
	if cfg.Enabled {
		state = "pending"
	}
	var generation int64
	err = tx.QueryRow(ctx, `INSERT INTO node_ddns(node_id,config,generation,status) VALUES($1,$2,1,jsonb_build_object('state',$3::text)) ON CONFLICT(node_id) DO UPDATE SET config=$2,generation=node_ddns.generation+1,status=jsonb_build_object('state',$3::text),status_received_at=NULL RETURNING generation`, id, data, state).Scan(&generation)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if cfg.Enabled {
		if _, err = tx.Exec(ctx, `UPDATE nodes SET public_address=CASE WHEN $2 THEN $4 ELSE public_address END,tunnel_public_host=CASE WHEN $3 THEN $4 ELSE tunnel_public_host END,config_revision=(SELECT value+1 FROM revision WHERE id=1) WHERE id=$1`, id, cfg.UseForIngress, cfg.UseForEgress, cfg.RecordName); err != nil {
			s.dbError(w, err)
			return
		}
	}
	if err = finishRules(ctx, tx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"generation": generation})
}

func (s *Server) runNodeDDNS(w http.ResponseWriter, r *http.Request) {
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
	err = tx.QueryRow(ctx, "UPDATE node_ddns SET generation=generation+1,status=jsonb_build_object('state','pending'),status_received_at=NULL WHERE node_id=$1 AND config->>'enabled'='true' RETURNING generation", id).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 409, "请先保存并启用 DDNS")
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

func appendDDNSControl(ctx context.Context, tx pgx.Tx, node int64, out *pb.ControlMessage) error {
	var data []byte
	var generation int64
	err := tx.QueryRow(ctx, "SELECT config,generation FROM node_ddns WHERE node_id=$1", node).Scan(&data, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cfg := ddns.DefaultConfig()
	if err = json.Unmarshal(data, &cfg); err != nil {
		return errors.New("DDNS 配置无效")
	}
	if err = cfg.Normalize(); err != nil {
		return err
	}
	out.Node.Ddns = &pb.DDNSConfig{Enabled: cfg.Enabled, Generation: generation, Provider: cfg.Provider, RecordName: cfg.RecordName, ZoneId: cfg.ZoneID, Token: cfg.Token, Ipv4: cfg.IPv4, Ipv6: cfg.IPv6, IntervalSeconds: int32(cfg.IntervalSeconds), Ttl: int32(cfg.TTL), Ipv4Url: cfg.IPv4URL, Ipv6Url: cfg.IPv6URL}
	return nil
}

func acceptDDNSReport(ctx context.Context, tx pgx.Tx, node int64, r *pb.DDNSStatus) error {
	if r == nil {
		return nil
	}
	if r.Generation < 1 || r.CheckedUnix < 0 || r.UpdatedUnix < 0 || r.UpdatedUnix > r.CheckedUnix {
		return errors.New("DDNS 状态时间无效")
	}
	if r.State != "ok" && r.State != "error" && r.State != "partial" && r.State != "pending" && r.State != "disabled" {
		return errors.New("DDNS 状态无效")
	}
	for _, value := range []struct {
		address string
		v6      bool
	}{{r.Ipv4, false}, {r.Ipv6, true}, {r.ObservedIpv4, false}, {r.ObservedIpv6, true}} {
		if value.address != "" {
			a, err := netip.ParseAddr(value.address)
			if err != nil || a.Zone() != "" || a.Is6() != value.v6 || !a.IsGlobalUnicast() || a.IsPrivate() {
				return errors.New("DDNS 地址无效")
			}
		}
	}
	var generation int64
	var config []byte
	var previous []byte
	err := tx.QueryRow(ctx, "SELECT generation,config,status FROM node_ddns WHERE node_id=$1 FOR UPDATE", node).Scan(&generation, &config, &previous)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && generation != r.Generation {
		return nil
	}
	if err != nil {
		return err
	}
	var last struct {
		Checked int64 `json:"checked_unix"`
	}
	if json.Unmarshal(previous, &last) == nil && r.CheckedUnix < last.Checked {
		return nil
	}
	var cfg ddns.Config
	if err = json.Unmarshal(config, &cfg); err != nil {
		return err
	}
	report := map[string]any{"generation": r.Generation, "state": r.State, "ipv4": r.Ipv4, "ipv6": r.Ipv6, "observed_ipv4": r.ObservedIpv4, "observed_ipv6": r.ObservedIpv6, "checked_unix": r.CheckedUnix, "updated_unix": r.UpdatedUnix, "error": truncate(strings.TrimSpace(r.Error), 500)}
	data, _ := json.Marshal(report)
	if _, err = tx.Exec(ctx, "UPDATE node_ddns SET status=$3,status_received_at=now() WHERE node_id=$1 AND generation=$2", node, r.Generation, data); err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	settings, err := readSystemSettings(ctx, tx)
	if err != nil {
		return err
	}
	v4, v6 := r.ObservedIpv4, r.ObservedIpv6
	if v4 == "" {
		v4 = r.Ipv4
	}
	if v6 == "" {
		v6 = r.Ipv6
	}
	state := r.State
	if state == "ok" && (v4 != "" && v4 != r.Ipv4 || v6 != "" && v6 != r.Ipv6) {
		state = "partial"
	}
	return recordNodeIPs(ctx, tx, node, generation, r.CheckedUnix, v4, v6, state, cfg.RecordName, settings)
}
