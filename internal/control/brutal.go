package control

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

type NodeBandwidth struct {
	BandwidthUpMbps        *int64 `json:"bandwidth_up_mbps,omitempty"`
	BandwidthDownMbps      *int64 `json:"bandwidth_down_mbps,omitempty"`
	BrutalEnabled          *bool  `json:"brutal_enabled,omitempty"`
	ClientTCPBrutalEnabled *bool  `json:"client_tcp_brutal_enabled,omitempty"`
}

func (v *NodeBandwidth) load(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id int64) error {
	var up, down int64
	var enabled, clientEnabled bool
	if id != 0 {
		if err := db.QueryRow(ctx, "SELECT bandwidth_up_mbps,bandwidth_down_mbps,brutal_enabled,client_tcp_brutal_enabled FROM nodes WHERE id=$1", id).Scan(&up, &down, &enabled, &clientEnabled); err != nil {
			return err
		}
	}
	if v.BandwidthUpMbps == nil {
		v.BandwidthUpMbps = &up
	}
	if v.BandwidthDownMbps == nil {
		v.BandwidthDownMbps = &down
	}
	if v.BrutalEnabled == nil {
		v.BrutalEnabled = &enabled
	}
	if v.ClientTCPBrutalEnabled == nil {
		v.ClientTCPBrutalEnabled = &clientEnabled
	}
	return nil
}
func (v NodeBandwidth) validate(mode string) error {
	if *v.BandwidthUpMbps < 0 || *v.BandwidthDownMbps < 0 || *v.BandwidthUpMbps > 1000000 || *v.BandwidthDownMbps > 1000000 {
		return errors.New("上下行带宽须为 0–1000000 Mbps")
	}
	if *v.BrutalEnabled && brutalTransport(mode) && (*v.BandwidthUpMbps == 0 || *v.BandwidthDownMbps == 0) {
		return errors.New("启用 Brutal 前请填写节点准确的上下行带宽")
	}
	if *v.ClientTCPBrutalEnabled && *v.BandwidthUpMbps == 0 {
		return errors.New("启用入口tcp Brutal 前请填写节点准确的上行带宽")
	}
	return nil
}
func brutalTransport(mode string) bool { return tunnel.H3(mode) || tunnel.UDP(mode) }

func appendBrutalControl(ctx context.Context, tx pgx.Tx, version int32, out *pb.ControlMessage) error {
	type capacity struct {
		up, down      uint64
		enabled       bool
		clientEnabled bool
		version       int32
	}
	ids := []int64{out.Node.NodeId}
	for _, r := range out.Rules {
		if r.EgressNodeId != 0 {
			ids = append(ids, r.EgressNodeId)
		}
	}
	for _, l := range out.TunnelLinks {
		ids = append(ids, l.IngressNodeId)
	}
	rows, err := tx.Query(ctx, "SELECT id,bandwidth_up_mbps*125000,bandwidth_down_mbps*125000,brutal_enabled,protocol_version,client_tcp_brutal_enabled FROM nodes WHERE id=ANY($1::bigint[])", ids)
	if err != nil {
		return err
	}
	nodes := map[int64]capacity{}
	for rows.Next() {
		var id int64
		var c capacity
		if err = rows.Scan(&id, &c.up, &c.down, &c.enabled, &c.version, &c.clientEnabled); err != nil {
			rows.Close()
			return err
		}
		nodes[id] = c
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	local := nodes[out.Node.NodeId]
	out.Node.BandwidthUpBps = local.up
	out.Node.ClientTcpBrutalEnabled = local.clientEnabled
	out.Node.BandwidthDownBps = local.down
	out.Node.BrutalEnabled = local.enabled && brutalTransport(out.Node.TunnelProtocol)
	for _, r := range out.Rules {
		remote := nodes[r.EgressNodeId]
		if !remote.enabled || !brutalTransport(r.TunnelProtocol) {
			continue
		}
		r.Congestion = &pb.TunnelCongestion{Brutal: true, SendBps: min(local.up, remote.down), ReceiveBps: min(local.down, remote.up)}
		if version < pb.BrutalVersion || remote.version < pb.BrutalVersion || r.Congestion.SendBps == 0 || r.Congestion.ReceiveBps == 0 {
			r.Enabled = false
		}
	}
	if out.Node.BrutalEnabled {
		if version < pb.BrutalVersion {
			out.Node.TunnelExitEnabled = false
			out.TunnelLinks = nil
			out.EgressRules = nil
			return nil
		}
		links := out.TunnelLinks[:0]
		for _, l := range out.TunnelLinks {
			remote := nodes[l.IngressNodeId]
			l.Congestion = &pb.TunnelCongestion{Brutal: true, SendBps: min(local.up, remote.down), ReceiveBps: min(local.down, remote.up)}
			if remote.version >= pb.BrutalVersion && l.Congestion.SendBps > 0 && l.Congestion.ReceiveBps > 0 {
				links = append(links, l)
			}
		}
		clear(out.TunnelLinks[len(links):])
		out.TunnelLinks = links
	}
	return nil
}
