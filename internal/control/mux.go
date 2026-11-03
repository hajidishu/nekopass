package control

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func loadMux(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id int64, config **tunnel.MuxConfig) error {
	if *config != nil {
		return nil
	}
	v := tunnel.DefaultMux()
	if id != 0 {
		var data []byte
		if err := db.QueryRow(ctx, "SELECT mux_config FROM nodes WHERE id=$1", id).Scan(&data); err != nil {
			return err
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
	}
	*config = &v
	return nil
}

func appendMuxControl(ctx context.Context, tx pgx.Tx, version int32, out *pb.ControlMessage) error {
	ids := []int64{out.Node.NodeId}
	for _, r := range out.Rules {
		if r.EgressNodeId != 0 {
			ids = append(ids, r.EgressNodeId)
		}
	}
	type entry struct {
		config  tunnel.MuxConfig
		version int32
	}
	nodes := map[int64]entry{}
	rows, err := tx.Query(ctx, "SELECT id,mux_config,protocol_version FROM nodes WHERE id=ANY($1::bigint[])", ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var data []byte
		var v entry
		v.config = tunnel.DefaultMux()
		if err = rows.Scan(&id, &data, &v.version); err != nil {
			break
		}
		if err = json.Unmarshal(data, &v.config); err != nil {
			break
		}
		nodes[id] = v
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	local := nodes[out.Node.NodeId].config
	out.Node.Mux = local.Proto()
	out.Node.Mux.Enabled = local.Enabled && tunnel.MuxSupported(out.Node.TunnelProtocol)
	if out.Node.Mux.Enabled && version < pb.MuxVersion {
		out.Node.TunnelExitEnabled = false
		out.TunnelLinks = nil
		out.EgressRules = nil
	}
	for _, r := range out.Rules {
		if v, ok := nodes[r.EgressNodeId]; ok {
			r.Mux = v.config.Proto()
			r.Mux.Enabled = v.config.Enabled && tunnel.MuxSupported(r.TunnelProtocol)
			if r.Mux.Enabled && (version < pb.MuxVersion || v.version < pb.MuxVersion) {
				r.Enabled = false
			}
		}
	}
	return nil
}
