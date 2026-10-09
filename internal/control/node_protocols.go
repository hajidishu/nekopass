package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/tunnel"
	"net/http"
)

type NodeProtocolsInput struct {
	TLS               *TunnelTLSConfig `json:"tls"`
	AllowDirect       bool             `json:"allow_direct"`
	IngressEnabled    bool             `json:"ingress_enabled"`
	TunnelExitEnabled bool             `json:"tunnel_exit_enabled"`
	TunnelTransport   string           `json:"tunnel_transport"`
	TunnelSecurity    string           `json:"tunnel_security"`
	TunnelProtocol    string           `json:"tunnel_protocol"`
	TunnelListenHost  string           `json:"tunnel_listen_host"`
	TunnelListenPort  int              `json:"tunnel_listen_port"`
	TunnelPublicHost  string           `json:"tunnel_public_host"`
	AllowedIngressIDs []int64          `json:"allowed_ingress_ids"`
}

type NodeBasicInput struct {
	UDPIdleTimeoutSeconds int      `json:"udp_idle_timeout_seconds,omitempty"`
	Token                 *string  `json:"token,omitempty"`
	Name                  string   `json:"name"`
	PublicAddress         string   `json:"public_address"`
	Notes                 string   `json:"notes"`
	Enabled               bool     `json:"enabled"`
	GroupIDs              []int64  `json:"group_ids"`
	ListenHost            string   `json:"listen_host"`
	PortMin               int      `json:"port_min"`
	PortMax               int      `json:"port_max"`
	MaxConnections        int64    `json:"max_connections"`
	DialTimeoutSeconds    int      `json:"dial_timeout_seconds"`
	IdleTimeoutSeconds    int      `json:"idle_timeout_seconds"`
	ProbeIntervalSeconds  int      `json:"probe_interval_seconds"`
	DiskPath              string   `json:"disk_path"`
	NetworkInterfaces     []string `json:"network_interfaces"`
}

func (s *Server) saveNodeBasic(w http.ResponseWriter, r *http.Request) { s.saveNodePart(w, r, "basic") }
func (s *Server) saveNodeProtocols(w http.ResponseWriter, r *http.Request) {
	s.saveNodePart(w, r, "protocols")
}

func loadNodeInput(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id int64) (NodeInput, string, error) {
	var v NodeInput
	var hash string
	var data []byte
	err := db.QueryRow(ctx, `SELECT name,public_address,notes,enabled,listen_host,port_min,port_max,max_connections,dial_timeout_seconds,idle_timeout_seconds,probe_interval_seconds,disk_path,network_interfaces,token,token_hash,ingress_enabled,allow_direct,tunnel_exit_enabled,tunnel_protocol,tunnel_listen_host,tunnel_listen_port,tunnel_public_host,tls_config,
 COALESCE((SELECT array_agg(group_id ORDER BY group_id) FROM node_group_members WHERE node_id=n.id),'{}'),
 COALESCE((SELECT array_agg(ingress_node_id ORDER BY ingress_node_id) FROM node_tunnel_links WHERE egress_node_id=n.id),'{}')
 FROM nodes n WHERE id=$1`, id).Scan(&v.Name, &v.PublicAddress, &v.Notes, &v.Enabled, &v.ListenHost, &v.PortMin, &v.PortMax, &v.MaxConnections, &v.DialTimeoutSeconds, &v.IdleTimeoutSeconds, &v.ProbeIntervalSeconds, &v.DiskPath, &v.NetworkInterfaces, &v.Token, &hash, &v.IngressEnabled, &v.AllowDirect, &v.TunnelExitEnabled, &v.TunnelProtocol, &v.TunnelListenHost, &v.TunnelListenPort, &v.TunnelPublicHost, &data, &v.GroupIDs, &v.AllowedIngressIDs)
	if err != nil {
		return v, hash, err
	}
	if err = db.QueryRow(ctx, "SELECT udp_idle_timeout_seconds FROM nodes WHERE id=$1", id).Scan(&v.UDPIdleTimeoutSeconds); err != nil {
		return v, hash, err
	}
	cfg := DefaultTunnelTLS()
	if err = json.Unmarshal(data, &cfg); err != nil {
		return v, hash, err
	}
	v.TLS = &cfg
	v.TunnelTransport, v.TunnelSecurity = tunnel.Split(v.TunnelProtocol)
	return v, hash, nil
}

func (s *Server) nodeProtocols(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	v, _, err := loadNodeInput(r.Context(), s.Pool, id)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "节点不存在")
		return
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	var config NodeProtocolsInput
	data, _ := json.Marshal(v)
	_ = json.Unmarshal(data, &config)
	rows, err := s.Pool.Query(r.Context(), "SELECT id,name,ingress_enabled FROM nodes WHERE id<>$1 AND ingress_enabled ORDER BY id", id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer rows.Close()
	choices := []map[string]any{}
	for rows.Next() {
		var nid int64
		var name string
		var enabled bool
		if err := rows.Scan(&nid, &name, &enabled); err != nil {
			s.dbError(w, err)
			return
		}
		choices = append(choices, map[string]any{"id": nid, "name": name, "ingress_enabled": enabled})
	}
	if err := rows.Err(); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "node_name": v.Name, "config": config, "ingress_nodes": choices})
}
