package control

import (
	"context"
	"github.com/nekopass/nekopass/internal/store"
	"net/http"
	"strconv"
)

type ruleOwnerKey struct{}

func ruleActor(r *http.Request) store.User {
	u := current(r)
	u.IsAdmin = false
	if id, ok := r.Context().Value(ruleOwnerKey{}).(int64); ok {
		u.ID = id
	}
	return u
}
func (s *Server) managedUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		id, e := strconv.ParseInt(r.PathValue("userID"), 10, 64)
		if e != nil || id < 1 {
			fail(w, 400, "无效用户")
			return
		}
		if _, e = s.query.FindUser(r.Context(), id); e != nil {
			fail(w, 404, "用户不存在")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ruleOwnerKey{}, id)))
	}
}
func (s *Server) ruleNodes(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	rows, e := s.Pool.Query(r.Context(), `SELECT n.id,n.name,n.public_address,n.port_min,n.port_max,n.ingress_enabled,n.allow_direct,n.tunnel_exit_enabled,n.tunnel_protocol,COALESCE((SELECT array_agg(ingress_node_id ORDER BY ingress_node_id) FROM node_tunnel_links WHERE egress_node_id=n.id),'{}') AS allowed_ingress_ids,(n.last_seen>now()-interval '12 seconds') AS online FROM nodes n JOIN user_nodes un ON un.node_id=n.id WHERE un.user_id=$1 ORDER BY n.id`, u.ID)
	s.sendRows(w, rows, e)
}
