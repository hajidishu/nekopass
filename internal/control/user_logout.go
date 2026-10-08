package control

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
)

func (s *Server) logoutUser(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, 400, "用户 ID 无效")
		return
	}
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var found int64
	// Serialize with session creation, password changes and account disabling.
	err = tx.QueryRow(r.Context(), "SELECT id FROM users WHERE id=$1 FOR UPDATE", id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "用户不存在")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=$1", id)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	if id == current(r).ID {
		http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.requestHTTPS(r), SameSite: http.SameSiteStrictMode})
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
