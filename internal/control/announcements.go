package control

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Server) announcements(w http.ResponseWriter, r *http.Request) {
	staff := strings.HasPrefix(r.URL.Path, "/api/v1/admin/")
	if staff && !admin(w, r) {
		return
	}
	page, ok := listPage(w, r)
	if !ok {
		return
	}
	var total int64
	if err := s.Pool.QueryRow(r.Context(), "SELECT count(*) FROM announcements WHERE $1 OR published", staff).Scan(&total); err != nil {
		s.dbError(w, err)
		return
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT id,title,CASE WHEN $1 THEN content ELSE left(content,240) END AS content,(NOT $1 AND char_length(content)>240) AS truncated,published,sort_order,updated_at FROM announcements WHERE $1 OR published ORDER BY sort_order,id DESC LIMIT 20 OFFSET $2`, staff, (page-1)*20)
	if err != nil {
		s.dbError(w, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page})
}

func (s *Server) announcementDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(w, r)
	if !ok || id == 0 {
		return
	}
	var title, content string
	if err := s.Pool.QueryRow(r.Context(), "SELECT title,content FROM announcements WHERE id=$1 AND published", id).Scan(&title, &content); err != nil {
		fail(w, 404, "公告不存在或尚未发布")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "title": title, "content": content})
}

func (s *Server) saveNotice(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var in struct {
		Title     string `json:"title"`
		Content   string `json:"content"`
		Published bool   `json:"published"`
		Sort      int    `json:"sort_order"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if len([]rune(in.Title)) < 1 || len([]rune(in.Title)) > 128 || len(in.Content) == 0 || len(in.Content) > 20000 || strings.ContainsRune(in.Content, '\x00') || strings.ContainsAny(in.Title, "\r\n\x00") || in.Sort < -1000000 || in.Sort > 1000000 {
		fail(w, 400, "标题为 1–128 字，公告正文最多 20000 字节")
		return
	}
	var err error
	if id == 0 {
		err = s.Pool.QueryRow(r.Context(), "INSERT INTO announcements(title,content,published,sort_order) VALUES($1,$2,$3,$4) RETURNING id", in.Title, in.Content, in.Published, in.Sort).Scan(&id)
	} else {
		err = s.Pool.QueryRow(r.Context(), "UPDATE announcements SET title=$2,content=$3,published=$4,sort_order=$5,updated_at=now() WHERE id=$1 RETURNING id", id, in.Title, in.Content, in.Published, in.Sort).Scan(&id)
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}

func (s *Server) deleteNotice(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := resourceID(w, r)
	if !ok || id == 0 {
		return
	}
	tag, err := s.Pool.Exec(r.Context(), "DELETE FROM announcements WHERE id=$1", id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		fail(w, 404, "公告不存在")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
