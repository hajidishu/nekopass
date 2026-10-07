package control

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func listPage(w http.ResponseWriter, r *http.Request) (int, bool) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > 100000 {
		fail(w, 400, "页码无效")
		return 0, false
	}
	return page, true
}

func ticketStaff(w http.ResponseWriter, r *http.Request) (bool, bool) {
	staff := strings.HasPrefix(r.URL.Path, "/api/v1/admin/")
	if staff && !admin(w, r) {
		return false, false
	}
	return staff, true
}

func (s *Server) ticketConfig(w http.ResponseWriter, r *http.Request) {
	v, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"captcha_mode": v.CaptchaMode})
}
func (s *Server) ticketCaptcha(w http.ResponseWriter, r *http.Request) {
	v, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	s.issueCaptcha(w, r, v, "ticket", current(r).ID)
}

func (s *Server) tickets(w http.ResponseWriter, r *http.Request) {
	staff, ok := ticketStaff(w, r)
	if !ok {
		return
	}
	page, ok := listPage(w, r)
	if !ok {
		return
	}
	uid := current(r).ID
	var total int64
	if err := s.Pool.QueryRow(r.Context(), "SELECT count(*) FROM tickets WHERE $1 OR user_id=$2", staff, uid).Scan(&total); err != nil {
		s.dbError(w, err)
		return
	}
	rows, err := s.Pool.Query(r.Context(), `SELECT t.id,t.user_id,u.username,t.title,t.priority,t.status,t.created_at,t.updated_at FROM tickets t JOIN users u ON u.id=t.user_id WHERE $1 OR t.user_id=$2 ORDER BY CASE WHEN $1 THEN CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END ELSE 0 END,t.updated_at DESC,t.id DESC LIMIT 20 OFFSET $3`, staff, uid, (page-1)*20)
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

func (s *Server) createTicket(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title     string `json:"title"`
		Content   string `json:"content"`
		Priority  string `json:"priority"`
		CaptchaID string `json:"captcha_id"`
		Captcha   string `json:"captcha"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	in.Content = strings.TrimSpace(in.Content)
	if len([]rune(in.Title)) < 1 || len([]rune(in.Title)) > 128 || len([]rune(in.Content)) < 1 || len([]rune(in.Content)) > 5000 || strings.ContainsRune(in.Content, '\x00') || strings.ContainsAny(in.Title, "\r\n\x00") || (in.Priority != "low" && in.Priority != "medium" && in.Priority != "high") {
		fail(w, 400, "请填写标题、正文和有效优先级（正文最多 5000 字）")
		return
	}
	uid := current(r).ID
	if !s.allowLogin("ticket-create:"+formatID(uid), time.Now(), 3) {
		fail(w, 429, "工单创建过于频繁")
		return
	}
	settings, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	if !s.verifyCaptcha(w, r, settings, "ticket", uid, in.CaptchaID, in.Captcha) {
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var id int64
	if err = tx.QueryRow(r.Context(), "INSERT INTO tickets(user_id,title,priority) VALUES($1,$2,$3) RETURNING id", uid, in.Title, in.Priority).Scan(&id); err != nil {
		s.dbError(w, err)
		return
	}
	if _, err = tx.Exec(r.Context(), "INSERT INTO ticket_messages(ticket_id,sender_id,sender_is_staff,content) VALUES($1,$2,false,$3)", id, uid, in.Content); err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}

func (s *Server) ticket(w http.ResponseWriter, r *http.Request) {
	staff, ok := ticketStaff(w, r)
	if !ok {
		return
	}
	id, ok := resourceID(w, r)
	if !ok || id == 0 {
		return
	}
	var owner int64
	var title, priority, status string
	if err := s.Pool.QueryRow(r.Context(), "SELECT user_id,title,priority,status FROM tickets WHERE id=$1 AND ($2 OR user_id=$3)", id, staff, current(r).ID).Scan(&owner, &title, &priority, &status); err != nil {
		fail(w, 404, "工单不存在或无权访问")
		return
	}
	page, ok := listPage(w, r)
	if !ok {
		return
	}
	var total int64
	if err := s.Pool.QueryRow(r.Context(), "SELECT count(*) FROM ticket_messages WHERE ticket_id=$1", id).Scan(&total); err != nil {
		s.dbError(w, err)
		return
	}
	rows, err := s.Pool.Query(r.Context(), "SELECT id,sender_is_staff,content,created_at FROM ticket_messages WHERE ticket_id=$1 ORDER BY id LIMIT 100 OFFSET $2", id, (page-1)*100)
	if err != nil {
		s.dbError(w, err)
		return
	}
	messages, err := pgx.CollectRows(rows, pgx.RowToMap)
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "user_id": owner, "title": title, "priority": priority, "status": status, "messages": messages, "total": total, "page": page})
}

func (s *Server) replyTicket(w http.ResponseWriter, r *http.Request) {
	staff, ok := ticketStaff(w, r)
	if !ok {
		return
	}
	id, ok := resourceID(w, r)
	if !ok || id == 0 {
		return
	}
	var in struct {
		Content string `json:"content"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Content = strings.TrimSpace(in.Content)
	if len([]rune(in.Content)) < 1 || len([]rune(in.Content)) > 5000 || strings.ContainsRune(in.Content, '\x00') {
		fail(w, 400, "回复为 1–5000 字纯文本")
		return
	}
	uid := current(r).ID
	if !s.allowLogin("ticket-reply:"+formatID(uid), time.Now(), 20) {
		fail(w, 429, "回复过于频繁")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var status string
	if err = tx.QueryRow(r.Context(), "SELECT status FROM tickets WHERE id=$1 AND ($2 OR user_id=$3) FOR UPDATE", id, staff, uid).Scan(&status); err != nil {
		fail(w, 404, "工单不存在或无权访问")
		return
	}
	if status == "closed" {
		fail(w, 409, "工单已关闭，请先重新打开")
		return
	}
	if _, err = tx.Exec(r.Context(), "INSERT INTO ticket_messages(ticket_id,sender_id,sender_is_staff,content) VALUES($1,$2,$3,$4)", id, uid, staff, in.Content); err != nil {
		s.dbError(w, err)
		return
	}
	next := "waiting_staff"
	if staff {
		next = "waiting_user"
	}
	if _, err = tx.Exec(r.Context(), "UPDATE tickets SET status=$2,updated_at=now() WHERE id=$1", id, next); err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": next})
}

func (s *Server) ticketStatus(w http.ResponseWriter, r *http.Request) {
	staff, ok := ticketStaff(w, r)
	if !ok {
		return
	}
	id, ok := resourceID(w, r)
	if !ok || id == 0 {
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Status != "closed" && in.Status != "open" {
		fail(w, 400, "工单状态无效")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var old string
	if err = tx.QueryRow(r.Context(), "SELECT status FROM tickets WHERE id=$1 AND ($2 OR user_id=$3) FOR UPDATE", id, staff, current(r).ID).Scan(&old); err != nil {
		fail(w, 404, "工单不存在或无权访问")
		return
	}
	next := old
	if in.Status == "closed" {
		next = "closed"
	} else if old == "closed" {
		next = "waiting_staff"
	}
	if _, err = tx.Exec(r.Context(), "UPDATE tickets SET status=$2,updated_at=now() WHERE id=$1", id, next); err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": next})
}
