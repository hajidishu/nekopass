package control

import (
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
)

func (s *Server) announcement(w http.ResponseWriter, r *http.Request) {
	var content string
	if e := s.Pool.QueryRow(r.Context(), "SELECT COALESCE((SELECT content FROM announcements WHERE published ORDER BY sort_order,id DESC LIMIT 1),'')").Scan(&content); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]string{"content": content})
}
func (s *Server) saveAnnouncement(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Content) > 20000 {
		fail(w, 400, "公告最多 20000 字节")
		return
	}
	if _, e := s.Pool.Exec(r.Context(), "INSERT INTO announcements(title,content,published,legacy) VALUES('站点公告',$1,$2,true) ON CONFLICT (legacy) WHERE legacy DO UPDATE SET content=$1,published=$2,updated_at=now()", in.Content, strings.TrimSpace(in.Content) != ""); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, in)
}
func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	rows, e := s.Pool.Query(r.Context(), "SELECT g.*, (SELECT count(*) FROM rules WHERE group_id=g.id) AS rule_count FROM rule_groups g WHERE $1 OR user_id=$2 ORDER BY id", u.IsAdmin, u.ID)
	if e != nil {
		s.dbError(w, e)
		return
	}
	v, e := pgx.CollectRows(rows, pgx.RowToMap)
	if e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string `json:"name"`
		UserID int64  `json:"user_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	u := ruleActor(r)
	if !u.IsAdmin {
		in.UserID = u.ID
	}
	in.Name = strings.TrimSpace(in.Name)
	if len([]rune(in.Name)) == 0 || len([]rune(in.Name)) > 64 {
		fail(w, 400, "分组名称长度为 1–64 字")
		return
	}
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	var e error
	if id == 0 {
		e = s.Pool.QueryRow(r.Context(), "INSERT INTO rule_groups(user_id,name) VALUES($1,$2) RETURNING id", in.UserID, in.Name).Scan(&id)
	} else {
		var owner int64
		e = s.Pool.QueryRow(r.Context(), "UPDATE rule_groups SET name=$2 WHERE id=$1 AND ($3 OR user_id=$4) RETURNING user_id", id, in.Name, u.IsAdmin, u.ID).Scan(&owner)
	}
	if e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	id, validID := resourceID(w, r)
	if !validID {
		return
	}
	tag, e := s.Pool.Exec(r.Context(), "DELETE FROM rule_groups WHERE id=$1 AND ($2 OR user_id=$3)", id, u.IsAdmin, u.ID)
	if e != nil {
		s.dbError(w, e)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "分组不存在")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
