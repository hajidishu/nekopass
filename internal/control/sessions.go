package control

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const sessionCookieMaxAge = 365 * 24 * 60 * 60

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(r), Value: token, Path: "/", HttpOnly: true, Secure: s.requestHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: sessionCookieMaxAge})
}

func (s *Server) renewSessionCookie(w http.ResponseWriter, r *http.Request, token string, renewed pgtype.Timestamptz) error {
	if renewed.Valid && renewed.InfinityModifier == pgtype.Finite && time.Since(renewed.Time) < 24*time.Hour {
		return nil
	}
	// Conditional UPDATE renews at most once daily across concurrent requests.
	// It cannot recreate a revoked session or revive an expired legacy session.
	count, err := s.query.RenewSessionCookie(r.Context(), Hash(token))
	if err != nil {
		return err
	}
	if count > 0 {
		s.setSessionCookie(w, r, token)
	}
	return nil
}
