package control

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const GrantWindow int64 = 256 << 20

type StreamServer struct {
	pb.UnimplementedControlServer
	Server *Server
}

func (s *StreamServer) Connect(stream pb.Control_ConnectServer) error {
	ctx := stream.Context()
	md, _ := metadata.FromIncomingContext(ctx)
	tokens := md.Get("authorization")
	if len(tokens) != 1 || !strings.HasPrefix(tokens[0], "Bearer ") {
		return status.Error(codes.Unauthenticated, "node token required")
	}
	presentedToken := strings.TrimPrefix(tokens[0], "Bearer ")
	node, e := s.Server.nodeForToken(ctx, presentedToken)
	if e != nil {
		return status.Error(codes.Unauthenticated, "invalid node token")
	}
	// A node holds its advisory lock on a dedicated session, not an API pool slot.
	// Long-lived streams must never exhaust the query pool and block login/config updates.
	conn, e := pgx.ConnectConfig(ctx, s.Server.Pool.Config().ConnConfig.Copy())
	if e != nil {
		return e
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	var locked bool
	e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", -node.ID).Scan(&locked)
	if e != nil {
		return e
	}
	if !locked {
		return status.Error(codes.AlreadyExists, "node already connected")
	}
	for {
		report, e := stream.Recv()
		if e != nil {
			return e
		}
		if report.ProtocolVersion < 5 {
			return status.Error(codes.FailedPrecondition, "upgrade Agent to protocol v5 or newer")
		}
		if len(report.InstanceId) < 16 || len(report.InstanceId) > 128 || len(report.Usage) > 10000 || len(report.RuleUsage) > 100000 || len(report.RequestUsers) > 10000 {
			return status.Error(codes.InvalidArgument, "invalid report")
		}
		result, e := s.exchangeWithCredential(ctx, conn, node.ID, report, Hash(presentedToken))
		if e != nil {
			return status.Error(codes.FailedPrecondition, publicOperationError(e))
		}
		if report.ProtocolVersion >= 12 {
			result.ControlEndpoint = s.Server.controlEndpoint()
		}
		if e = stream.Send(result); e != nil {
			return e
		}
	}
}

func (s *StreamServer) exchange(ctx context.Context, conn interface {
	Begin(context.Context) (pgx.Tx, error)
}, nodeID int64, r *pb.AgentMessage) (*pb.ControlMessage, error) {
	return s.exchangeWithCredential(ctx, conn, nodeID, r, "")
}
func (s *StreamServer) exchangeWithCredential(ctx context.Context, conn interface {
	Begin(context.Context) (pgx.Tx, error)
}, nodeID int64, r *pb.AgentMessage, expectedHash string) (*pb.ControlMessage, error) {
	tx, e := conn.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var instance, currentHash string
	e = tx.QueryRow(ctx, "SELECT instance_id,token_hash FROM nodes WHERE id=$1 FOR UPDATE", nodeID).Scan(&instance, &currentHash)
	if e != nil {
		return nil, e
	}
	if expectedHash != "" && expectedHash != currentHash {
		return nil, errors.New("node token changed; update Agent configuration before reconnecting")
	}
	if r.ProtocolVersion > 0 && r.ProtocolVersion < 6 {
		var requiresTunnel bool
		e = tx.QueryRow(ctx, `SELECT n.tunnel_exit_enabled OR EXISTS(SELECT 1 FROM rules WHERE node_id=$1 AND egress_node_id IS NOT NULL) FROM nodes n WHERE n.id=$1`, nodeID).Scan(&requiresTunnel)
		if e != nil {
			return nil, e
		}
		if requiresTunnel {
			return nil, errors.New("upgrade this Agent to protocol v6 before using node-to-node tunnels")
		}
	}
	if r.ProtocolVersion > 0 && r.ProtocolVersion < 7 {
		var requiresTLS bool
		e = tx.QueryRow(ctx, `SELECT (n.tunnel_exit_enabled AND n.tunnel_protocol='tls_h2') OR EXISTS(SELECT 1 FROM rules r JOIN nodes exit ON exit.id=r.egress_node_id WHERE r.node_id=$1 AND exit.tunnel_protocol='tls_h2') FROM nodes n WHERE n.id=$1`, nodeID).Scan(&requiresTLS)
		if e != nil {
			return nil, e
		}
		if requiresTLS {
			return nil, errors.New("upgrade this Agent to protocol v7 before using TLS HTTP/2 tunnels")
		}
	}
	if e = validateStateRestore(r, expectedHash); e != nil {
		return nil, e
	}
	if instance != "" && instance != r.InstanceId {
		if !r.RestoreState {
			return nil, errors.New("node state identity changed; create a new node instead of deleting or cloning agent state")
		}
	}
	if r.RestoreState {
		if e = settleLostNodeState(ctx, tx, nodeID); e != nil {
			return nil, e
		}
	}
	_, e = tx.Exec(ctx, "UPDATE nodes SET instance_id=$2,last_seen=now(),applied_revision=$3,sync_error=$4,active_connections=$5,protocol_version=$6,acme_ack=$7 WHERE id=$1", nodeID, r.InstanceId, r.AppliedRevision, truncate(r.Error, 4000), r.ActiveConnections, r.ProtocolVersion, r.AcmeAck)
	if e != nil {
		return nil, e
	}
	sort.Slice(r.Usage, func(i, j int) bool { return r.Usage[i].UserId < r.Usage[j].UserId })
	for _, u := range r.Usage {
		if u.QuotaEpoch < 0 || u.Spent < 0 || u.Released < 0 || u.Traffic < 0 || u.UnlimitedSpent < 0 || u.Spent > math.MaxInt64-u.UnlimitedSpent || u.Traffic > u.Spent+u.UnlimitedSpent {
			return nil, errors.New("invalid usage counters")
		}
		var issued, spent, released, traffic, unlimitedSpent int64
		var unlimitedOpen bool
		e = tx.QueryRow(ctx, "SELECT issued,spent,released,traffic,unlimited_spent,unlimited_open FROM grants WHERE node_id=$1 AND user_id=$2 AND quota_epoch=$3 FOR UPDATE", nodeID, u.UserId, u.QuotaEpoch).Scan(&issued, &spent, &released, &traffic, &unlimitedSpent, &unlimitedOpen)
		if errors.Is(e, pgx.ErrNoRows) && u.Spent == 0 && u.Released == 0 && u.Traffic == 0 && u.UnlimitedSpent == 0 {
			continue
		}
		if e != nil {
			return nil, e
		}
		if u.UnlimitedSpent < unlimitedSpent || (u.UnlimitedSpent > unlimitedSpent && !unlimitedOpen) || u.Spent < spent || u.Released < released || u.Traffic < traffic || u.Spent > issued || u.Released > issued-u.Spent {
			return nil, errors.New("usage counters regressed or exceeded grant; retain the original agent state")
		}
		_, e = tx.Exec(ctx, "UPDATE grants SET spent=$3,released=$4,traffic=$5,unlimited_spent=$6,unlimited_open=unlimited_open AND $7 WHERE node_id=$1 AND user_id=$2 AND quota_epoch=$8", nodeID, u.UserId, u.Spent, u.Released, u.Traffic, u.UnlimitedSpent, u.QuotaUnlimited, u.QuotaEpoch)
		if e != nil {
			return nil, e
		}
		if u.Traffic > traffic {
			_, e = tx.Exec(ctx, "INSERT INTO usage_events(node_id,user_id,traffic_bytes) VALUES($1,$2,$3)", nodeID, u.UserId, u.Traffic-traffic)
			if e != nil {
				return nil, e
			}
		}
	}
	for _, u := range r.RuleUsage {
		if u.Traffic < 0 {
			return nil, errors.New("negative rule usage")
		}
		var before, owner int64
		e = tx.QueryRow(ctx, "SELECT traffic,user_id FROM rule_usage WHERE node_id=$1 AND rule_id=$2 FOR UPDATE", nodeID, u.RuleId).Scan(&before, &owner)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if u.Traffic > before {
			if _, e = tx.Exec(ctx, "UPDATE rule_usage SET traffic=$3 WHERE node_id=$1 AND rule_id=$2", nodeID, u.RuleId, u.Traffic); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, "INSERT INTO rule_events(node_id,rule_id,user_id,traffic_bytes) VALUES($1,$2,$3,$4)", nodeID, u.RuleId, owner, u.Traffic-before); e != nil {
				return nil, e
			}
		}
	}
	// Every allocator locks the user row first. Concurrent nodes cannot over-allocate its quota.
	sort.Slice(r.RequestUsers, func(i, j int) bool { return r.RequestUsers[i] < r.RequestUsers[j] })
	seen := map[int64]bool{}
	for _, id := range r.RequestUsers {
		if seen[id] {
			continue
		}
		seen[id] = true
		var quota, speed, epoch, baseline int64
		if _, e = tx.Exec(ctx, "SELECT id FROM users WHERE id=$1 FOR UPDATE", id); e != nil {
			return nil, e
		}
		e = tx.QueryRow(ctx, `SELECT quota_bytes,speed_bps,quota_epoch,traffic_base_bytes FROM user_entitlements WHERE id=$1 AND enabled AND (expires_at IS NULL OR expires_at>now())
   AND EXISTS(SELECT 1 FROM user_nodes WHERE user_id=$1 AND node_id=$2)`, id, nodeID).Scan(&quota, &speed, &epoch, &baseline)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if quota < 0 {
			continue
		}
		var allocated int64
		e = tx.QueryRow(ctx, "SELECT COALESCE(sum(issued-released+unlimited_spent),0)::bigint FROM current_grants WHERE user_id=$1", id).Scan(&allocated)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, "INSERT INTO grants(node_id,user_id,quota_epoch) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", nodeID, id, epoch)
		if e != nil {
			return nil, e
		}
		var available int64
		e = tx.QueryRow(ctx, "SELECT issued-spent-released FROM grants WHERE node_id=$1 AND user_id=$2 AND quota_epoch=$3", nodeID, id, epoch).Scan(&available)
		if e != nil {
			return nil, e
		}
		window := max(GrantWindow, min(speed*10, 16<<30))
		if speed == 0 {
			window = 16 << 30
		}
		more := min(window-available, quota-baseline-allocated)
		if more > 0 {
			_, e = tx.Exec(ctx, "UPDATE grants SET issued=issued+$3 WHERE node_id=$1 AND user_id=$2 AND quota_epoch=$4", nodeID, id, more, epoch)
			if e != nil {
				return nil, e
			}
		}
	}
	// Unlimited authorization is persisted before sending a policy, so offline
	// reports remain valid after a plan changes. A finite-mode report closes it.
	if _, e = tx.Exec(ctx, `INSERT INTO grants(node_id,user_id,unlimited_open,quota_epoch)
 SELECT $1,u.id,true,u.quota_epoch FROM user_entitlements u JOIN user_nodes n ON n.user_id=u.id AND n.node_id=$1 WHERE u.quota_bytes=-1
 ON CONFLICT(node_id,user_id,quota_epoch) DO UPDATE SET unlimited_open=true WHERE NOT grants.unlimited_open`, nodeID); e != nil {
		return nil, e
	}
	out := &pb.ControlMessage{Node: &pb.NodeConfig{}, AcknowledgedUsage: r.Usage}
	settings, e := readSystemSettings(ctx, tx)
	if e != nil {
		return nil, e
	}
	out.Node.SecurityConfigured = true
	out.Node.ProxyTrustedCidrs = settings.ProxyTrustedCIDRs
	out.Node.TargetDenyCidrs = settings.TargetDenyCIDRs
	if e = tx.QueryRow(ctx, "SELECT udp_idle_timeout_seconds FROM nodes WHERE id=$1", nodeID).Scan(&out.Node.UdpIdleTimeoutSeconds); e != nil {
		return nil, e
	}
	var interfaces []byte
	e = tx.QueryRow(ctx, `SELECT id,enabled,listen_host,port_min,port_max,max_connections,dial_timeout_seconds,idle_timeout_seconds,probe_interval_seconds,disk_path,network_interfaces,tunnel_exit_enabled,tunnel_listen_host,tunnel_listen_port,tunnel_protocol FROM nodes WHERE id=$1`, nodeID).Scan(&out.Node.NodeId, &out.Node.Enabled, &out.Node.ListenHost, &out.Node.PortMin, &out.Node.PortMax, &out.Node.MaxConnections, &out.Node.DialTimeoutSeconds, &out.Node.IdleTimeoutSeconds, &out.Node.ProbeIntervalSeconds, &out.Node.DiskPath, &interfaces, &out.Node.TunnelExitEnabled, &out.Node.TunnelListenHost, &out.Node.TunnelListenPort, &out.Node.TunnelProtocol)
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(interfaces, &out.Node.NetworkInterfaces); e != nil {
		return nil, e
	}
	if r.Probe != nil && validProbe(r.Probe) {
		data, err := json.Marshal(r.Probe)
		if err != nil {
			return nil, err
		}
		if _, e = tx.Exec(ctx, "UPDATE nodes SET probe_received_at=CASE WHEN probe IS DISTINCT FROM $2::jsonb THEN now() ELSE probe_received_at END,probe=$2 WHERE id=$1", nodeID, data); e != nil {
			return nil, e
		}
	}

	e = tx.QueryRow(ctx, "SELECT value FROM revision WHERE id=1").Scan(&out.Revision)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, `SELECT u.id,(u.enabled AND (u.quota_bytes<0 OR (u.traffic_base_bytes<u.quota_bytes AND u.traffic_base_bytes+COALESCE((SELECT sum(issued-released+unlimited_spent) FROM current_grants WHERE user_id=u.id),0)<=u.quota_bytes))),COALESCE(extract(epoch FROM LEAST(u.expires_at,u.next_reset_at))::bigint,0),u.speed_bps,COALESCE(g.issued,0),u.max_connections,u.ip_limit,(u.quota_bytes=-1),u.quota_epoch
  FROM user_entitlements u JOIN user_nodes n ON n.user_id=u.id LEFT JOIN current_grants g ON g.user_id=u.id AND g.node_id=n.node_id WHERE n.node_id=$1 ORDER BY u.id`, nodeID)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		u := &pb.UserPolicy{}
		if e = rows.Scan(&u.Id, &u.Enabled, &u.ExpiresUnix, &u.SpeedBps, &u.Issued, &u.MaxConnections, &u.IpLimit, &u.QuotaUnlimited, &u.QuotaEpoch); e != nil {
			rows.Close()
			return nil, e
		}
		out.Users = append(out.Users, u)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	rows, e = tx.Query(ctx, `SELECT r.id,r.user_id,nn.listen_host,r.listen_port,r.target_host,r.target_port,r.enabled,r.targets,r.balance,
 COALESCE(LEAST(NULLIF(r.speed_mbps*125000,0),NULLIF(u.rule_speed_bps,0)),0),
 COALESCE(LEAST(NULLIF(r.ip_limit,0),NULLIF(u.rule_ip_limit,0)),0),
	 COALESCE(LEAST(NULLIF(r.connection_limit,0),NULLIF(u.rule_connection_limit,0)),0),r.proxy_accept,r.proxy_send,r.proxy_trusted_cidrs,COALESCE(r.egress_node_id,0),COALESCE(en.tunnel_public_host,''),COALESCE(en.tunnel_listen_port,0),COALESCE(l.token,''),COALESCE(en.tunnel_protocol,''),u.quota_epoch,r.protocol FROM rules r JOIN nodes nn ON nn.id=r.node_id JOIN user_entitlements u ON u.id=r.user_id JOIN user_nodes n ON n.user_id=r.user_id AND n.node_id=r.node_id LEFT JOIN nodes en ON en.id=r.egress_node_id AND en.enabled AND en.tunnel_exit_enabled LEFT JOIN node_tunnel_links l ON l.ingress_node_id=r.node_id AND l.egress_node_id=r.egress_node_id WHERE r.node_id=$1 AND nn.ingress_enabled ORDER BY r.id`, nodeID)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		v := &pb.Rule{}
		var targets, trusted []byte
		if e = rows.Scan(&v.Id, &v.UserId, &v.ListenHost, &v.ListenPort, &v.TargetHost, &v.TargetPort, &v.Enabled, &targets, &v.Balance, &v.SpeedBps, &v.IpLimit, &v.ConnectionLimit, &v.ProxyAccept, &v.ProxySend, &trusted, &v.EgressNodeId, &v.TunnelHost, &v.TunnelPort, &v.TunnelToken, &v.TunnelProtocol, &v.QuotaEpoch, &v.Protocol); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal(targets, &v.Targets); e != nil {
			rows.Close()
			return nil, e
		}
		if e = json.Unmarshal(trusted, &v.ProxyTrustedCidrs); e != nil {
			rows.Close()
			return nil, e
		}
		v.ProxyTrustedCidrs = settings.ProxyTrustedCIDRs
		if v.ProxyAccept != "off" && len(settings.ProxyTrustedCIDRs) == 0 {
			v.Enabled = false
		}
		v.IngressNodeId = nodeID
		// Older Agents cannot detect both PROXY header versions. Keep other rules
		// and the update channel usable, but never downgrade an enabled receiver.
		if v.ProxyAccept == "auto" && r.ProtocolVersion < 10 {
			v.Enabled = false
		}
		if v.EgressNodeId != 0 && (v.TunnelHost == "" || v.TunnelToken == "" || v.TunnelPort == 0) {
			v.Enabled = false
		}
		if v.Protocol != "tcp" && r.ProtocolVersion < 16 {
			v.Enabled = false
		}
		out.Rules = append(out.Rules, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if out.Node.TunnelExitEnabled {
		rows, e = tx.Query(ctx, `SELECT l.ingress_node_id,l.token FROM node_tunnel_links l JOIN nodes ingress ON ingress.id=l.ingress_node_id AND ingress.ingress_enabled WHERE l.egress_node_id=$1 ORDER BY l.ingress_node_id`, nodeID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			v := &pb.TunnelLink{}
			if e = rows.Scan(&v.IngressNodeId, &v.Token); e != nil {
				rows.Close()
				return nil, e
			}
			out.TunnelLinks = append(out.TunnelLinks, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		rows, e = tx.Query(ctx, `SELECT r.id,r.node_id,r.targets,r.user_id,u.quota_epoch,COALESCE(extract(epoch FROM LEAST(u.expires_at,u.next_reset_at))::bigint,0),r.protocol FROM rules r JOIN user_entitlements u ON u.id=r.user_id JOIN user_nodes ingress ON ingress.user_id=r.user_id AND ingress.node_id=r.node_id JOIN user_nodes exit_auth ON exit_auth.user_id=r.user_id AND exit_auth.node_id=r.egress_node_id JOIN node_tunnel_links l ON l.ingress_node_id=r.node_id AND l.egress_node_id=r.egress_node_id WHERE r.egress_node_id=$1 AND EXISTS(SELECT 1 FROM nodes source WHERE source.id=r.node_id AND source.ingress_enabled) AND r.enabled AND u.enabled AND (u.expires_at IS NULL OR u.expires_at>now()) ORDER BY r.id`, nodeID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			v := &pb.EgressRule{}
			var targets []byte
			if e = rows.Scan(&v.RuleId, &v.IngressNodeId, &targets, &v.UserId, &v.QuotaEpoch, &v.ExpiresUnix, &v.Protocol); e != nil {
				rows.Close()
				return nil, e
			}
			if e = json.Unmarshal(targets, &v.Targets); e != nil {
				rows.Close()
				return nil, e
			}
			if v.Protocol != "tcp" && r.ProtocolVersion < 16 {
				continue
			}
			out.EgressRules = append(out.EgressRules, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	if e = appendTLSControl(ctx, tx, nodeID, out); e != nil {
		return nil, e
	}
	tlsVersions := map[int64]int{}
	for _, rule := range out.Rules {
		if rule.EgressNodeId != 0 {
			version, known := tlsVersions[rule.EgressNodeId]
			if !known {
				if e = tx.QueryRow(ctx, "SELECT protocol_version FROM nodes WHERE id=$1", rule.EgressNodeId).Scan(&version); e != nil {
					return nil, e
				}
				tlsVersions[rule.EgressNodeId] = version
			}
			if rule.Protocol != "tcp" && version < 16 {
				rule.Enabled = false
			}
			if rule.Tls != nil {
				rule.Tls.SequenceAuth = r.ProtocolVersion >= 14 && version >= 14
			}
			if len(settings.TargetDenyCIDRs) > 0 && version < 14 {
				rule.Enabled = false
			}
			if r.ProtocolVersion < int32(tunnel.MinimumVersion(rule.TunnelProtocol)) || version < tunnel.MinimumVersion(rule.TunnelProtocol) {
				rule.Enabled = false
			}
		}
	}
	if out.Node.TunnelExitEnabled && tunnel.UDP(out.Node.TunnelProtocol) && r.ProtocolVersion < int32(tunnel.MinimumVersion(out.Node.TunnelProtocol)) {
		out.Node.TunnelExitEnabled = false
		out.TunnelLinks = nil
		out.EgressRules = nil
	}
	if out.Node.TunnelExitEnabled && (out.Node.TunnelProtocol == "tls_tcp" || out.Node.TunnelProtocol == "plain_h2") && r.ProtocolVersion < 13 {
		out.Node.TunnelExitEnabled = false
		out.TunnelLinks = nil
		out.EgressRules = nil
	}
	// Older agents cannot enforce target ACLs; retain probe/update control, fail forwarding closed.
	if len(settings.TargetDenyCIDRs) > 0 && r.ProtocolVersion < 14 {
		out.Node.Enabled = false
		out.Node.TunnelExitEnabled = false
		for _, rule := range out.Rules {
			rule.Enabled = false
		}
		out.EgressRules = nil
		out.TunnelLinks = nil
	}
	if e = appendDDNSControl(ctx, tx, nodeID, out); e != nil {
		return nil, e
	}
	if e = acceptDDNSReport(ctx, tx, nodeID, r.DdnsStatus); e != nil {
		return nil, e
	}
	if e = updateControl(ctx, tx, nodeID, r, out); e != nil {
		return nil, e
	}
	if e = appendStateRestore(ctx, tx, nodeID, r, out); e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return out, nil
}
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
