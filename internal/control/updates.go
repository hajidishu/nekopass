package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
)

func (s *Server) latestRelease(ctx context.Context) (release.Info, error) {
	s.releaseMu.Lock()
	defer s.releaseMu.Unlock()
	ttl := 5 * time.Minute
	if s.releaseError != nil {
		ttl = time.Minute
	}
	if !s.releaseChecked.IsZero() && time.Since(s.releaseChecked) < ttl {
		return s.releaseInfo, s.releaseError
	}
	s.releaseInfo, s.releaseError = s.releaseClient.Latest(ctx)
	s.releaseChecked = time.Now()
	return s.releaseInfo, s.releaseError
}
func (s *Server) checkUpdates(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	latest, err := s.latestRelease(r.Context())
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"current_version": release.Version, "latest": latest, "update_available": release.Newer(latest.Version, release.Version)})
}
func (s *Server) updateNode(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !release.ValidVersion(in.Version) {
		fail(w, 400, "更新版本无效")
		return
	}
	latest, err := s.latestRelease(r.Context())
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if latest.Version != in.Version {
		fail(w, 409, "请检查更新并选择 GitHub 最新正式版本")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var version string
	var supported, online bool
	var protocol int
	err = tx.QueryRow(r.Context(), "SELECT agent_version,update_supported,protocol_version,COALESCE(last_seen>now()-interval '12 seconds',false) FROM nodes WHERE id=$1 FOR UPDATE", id).Scan(&version, &supported, &protocol, &online)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "节点不存在")
		return
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	if !online {
		fail(w, 409, "节点离线，请上线后更新")
		return
	}
	if !supported || protocol < 9 {
		fail(w, 409, "此节点尚未安装更新服务，请先重新运行新版节点安装命令")
		return
	}
	if !release.Newer(in.Version, version) {
		fail(w, 409, "节点已经是该版本或更新版本")
		return
	}
	var generation int64
	err = tx.QueryRow(r.Context(), `INSERT INTO node_updates(node_id,version) VALUES($1,$2) ON CONFLICT(node_id) DO UPDATE SET generation=node_updates.generation+1,version=$2,state='queued',error='',requested_at=now(),updated_at=now() WHERE node_updates.state NOT IN ('queued','running') OR node_updates.requested_at<now()-interval '15 minutes' RETURNING generation`, id, in.Version).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 409, "节点已有更新任务，请等待完成")
		return
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"generation": generation, "version": in.Version, "state": "queued"})
}
func updateControl(ctx context.Context, tx pgx.Tx, node int64, report *pb.AgentMessage, out *pb.ControlMessage) error {
	if len(report.AgentVersion) > 64 || (report.AgentVersion != "" && report.AgentVersion != "dev" && !release.ValidVersion(report.AgentVersion)) {
		return errors.New("invalid Agent version")
	}
	if _, err := tx.Exec(ctx, "UPDATE nodes SET agent_version=$2,update_supported=$3 WHERE id=$1", node, report.AgentVersion, report.ProtocolVersion >= 9 && report.UpdateSupported); err != nil {
		return err
	}
	if r := report.UpdateStatus; r != nil {
		if r.Generation < 1 || !release.ValidVersion(r.Version) || len(r.Error) > 500 || (r.State != "queued" && r.State != "running" && r.State != "completed" && r.State != "failed") {
			return errors.New("invalid Agent update status")
		}
		state, detail := r.State, r.Error
		if state == "completed" && report.AgentVersion != r.Version {
			state = "failed"
			detail = "更新后的节点版本不匹配"
		}
		if _, err := tx.Exec(ctx, `UPDATE node_updates SET state=$4,error=$5,updated_at=CASE WHEN state<>$4 OR error<>$5 THEN now() ELSE updated_at END WHERE node_id=$1 AND generation=$2 AND version=$3 AND state IN ('queued','running') AND NOT(state='running' AND $4='queued')`, node, r.Generation, r.Version, state, detail); err != nil {
			return err
		}
	}
	var generation int64
	var version string
	err := tx.QueryRow(ctx, "SELECT generation,version FROM node_updates WHERE node_id=$1 AND state IN ('queued','running')", node).Scan(&generation, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	out.Update = &pb.UpdateRequest{Generation: generation, Version: version}
	return nil
}
