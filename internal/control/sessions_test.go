package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nekopass/nekopass/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestLongLoginSurvivesServerRestartAndKeepsOtherDevices(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	name, password := Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, err := f.p.Exec(ctx, "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", f.user, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	w := f.request(0, "login", "POST", map[string]string{"username": name, "password": password})
	securityStatus(t, w, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != sessionCookieMaxAge || !cookies[0].HttpOnly || cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("persistent login cookie invalid")
	}
	var expires pgtype.Timestamptz
	if err := f.p.QueryRow(ctx, "SELECT expires_at FROM sessions WHERE token_hash=$1", Hash(cookies[0].Value)).Scan(&expires); err != nil || expires.Valid {
		t.Fatal("new server session has a fixed expiry", err)
	}
	f.s = New(f.p)
	f.h = f.s.Handler(http.NotFoundHandler())
	w = f.raw(0, "me", "GET", "", func(r *http.Request) { r.AddCookie(cookies[0]) })
	securityStatus(t, w, 200)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("fresh session renewed unnecessarily")
	}
	securityStatus(t, f.request(f.user, "me", "GET", nil), 200)
}

func TestDailySessionRenewalIsAtomicAndPreservesToken(t *testing.T) {
	f := newSecurityFixture(t)
	var renewed atomic.Int64
	var failed atomic.Bool
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.request(f.user, "me", "GET", nil)
			if w.Code != 200 {
				failed.Store(true)
			}
			for _, c := range w.Result().Cookies() {
				if c.Value != f.tokens[f.user] || c.MaxAge != sessionCookieMaxAge || !c.HttpOnly {
					failed.Store(true)
				}
				renewed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() || renewed.Load() != 1 {
		t.Fatal("concurrent requests renewed incorrectly", renewed.Load())
	}
	if len(f.request(f.user, "me", "GET", nil).Result().Cookies()) != 0 {
		t.Fatal("session renewed more than once daily")
	}
	if _, err := f.p.Exec(context.Background(), "UPDATE sessions SET cookie_renewed_at=now()-interval '25 hours' WHERE user_id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	f.h = f.s.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("fixture page")) }))
	pageRequest := httptest.NewRequest("GET", "https://panel.example.test/profile", nil)
	pageRequest.AddCookie(&http.Cookie{Name: "nekopass_session", Value: f.tokens[f.user]})
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, pageRequest)
	securityStatus(t, w, 200)
	if c := w.Result().Cookies(); len(c) != 1 || !c[0].Secure || c[0].Name != "nekopass_session" || c[0].MaxAge != sessionCookieMaxAge {
		t.Fatal("HTTPS document did not renew correctly")
	}
}

type sessionLookupFailure struct{ store.DBTX }
type failedSessionRow struct{}

func (failedSessionRow) Scan(...any) error { return errors.New("fixture session database failure") }
func (db sessionLookupFailure) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "JOIN sessions") {
		return failedSessionRow{}
	}
	return db.DBTX.QueryRow(ctx, sql, args...)
}

func TestSessionDatabaseFailureDoesNotPretendLoginExpired(t *testing.T) {
	f := newSecurityFixture(t)
	f.s.query = store.New(sessionLookupFailure{f.p})
	w := f.request(f.user, "me", "GET", nil)
	securityStatus(t, w, 503)
	if len(w.Result().Cookies()) != 0 || w.Header().Get("Location") != "" {
		t.Fatal("storage failure discarded login state")
	}
	r := httptest.NewRequest("GET", "http://panel.example.test/profile", nil)
	r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: f.tokens[f.user]})
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	securityStatus(t, w, 503)
	if w.Header().Get("Location") != "" {
		t.Fatal("document database failure redirected to login")
	}
	f.s.query = store.New(f.p)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 200)
	if _, err := f.p.Exec(context.Background(), "UPDATE sessions SET expires_at=now()-interval '1 second' WHERE user_id=$1", f.user); err != nil {
		t.Fatal(err)
	}
	w = f.request(f.user, "me", "GET", nil)
	securityStatus(t, w, 401)
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("expired legacy session was revived")
	}
}

func TestAdministratorRevokesOnlyChosenUserAndCannotBeBypassed(t *testing.T) {
	f := newSecurityFixture(t)
	name, password := Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, err := f.p.Exec(context.Background(), "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", f.user, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("admin/users/%d/logout", f.user)
	securityStatus(t, f.request(f.other, path, "POST", map[string]any{}), 403)
	securityStatus(t, f.request(f.admin, "admin/users/0/logout", "POST", map[string]any{}), 400)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]any{"unexpected": true}), 400)
	securityStatus(t, f.raw(f.admin, path, "POST", "{}", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }), 403)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 200)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]any{}), 200)
	securityStatus(t, f.request(f.user, "me", "GET", nil), 401)
	securityStatus(t, f.request(f.other, "me", "GET", nil), 200)
	securityStatus(t, f.request(f.admin, "me", "GET", nil), 200)
	count, err := f.s.query.RenewSessionCookie(context.Background(), Hash(f.tokens[f.user]))
	if err != nil || count != 0 {
		t.Fatal("renewal recreated a revoked session", err)
	}
	login := f.request(0, "login", "POST", map[string]string{"username": name, "password": password})
	securityStatus(t, login, 200)
	if cookies := login.Result().Cookies(); len(cookies) != 1 || cookies[0].Value == f.tokens[f.user] {
		t.Fatal("revoked user could not establish a fresh session")
	}
	w := f.request(f.admin, fmt.Sprintf("admin/users/%d/logout", f.admin), "POST", map[string]any{})
	securityStatus(t, w, 200)
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge != -1 {
		t.Fatal("self revocation failed to clear browser cookie")
	}
	securityStatus(t, f.request(f.admin, "me", "GET", nil), 401)
}
