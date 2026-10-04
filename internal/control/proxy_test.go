package control

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginCookiesOverHTTPAndProxyHTTPS(t *testing.T) {
	p := testDB(t)
	uid, _ := testUser(t, p, 1024, 1, true)
	name, password := Secret(), Secret()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if _, err := p.Exec(context.Background(), "UPDATE users SET username=$2,password_hash=$3 WHERE id=$1", uid, name, string(hash)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": name, "password": password})
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("POST", "http://panel.example.test/api/v1/login", bytes.NewReader(body))
		r.RemoteAddr = "127.0.0.1:9000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://panel.example.test")
		if secure {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Origin", "https://panel.example.test")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("login: %d", w.Code)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Secure != secure || !cookies[0].HttpOnly {
			t.Fatal("incorrect session cookie flags")
		}
		name, other := "nekopass_session_http", "nekopass_session"
		if secure {
			name, other = other, name
		}
		if cookies[0].Name != name {
			t.Fatal("HTTP and HTTPS must use separate cookie names")
		}
		profile := httptest.NewRequest("GET", "http://panel.example.test/api/v1/me", nil)
		profile.RemoteAddr = r.RemoteAddr
		profile.Header.Set("X-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		profile.AddCookie(&http.Cookie{Name: other, Value: "stale-session-from-other-protocol"})
		profile.AddCookie(cookies[0])
		result := httptest.NewRecorder()
		h.ServeHTTP(result, profile)
		if result.Code != 200 {
			t.Fatal("session unusable")
		}
		// Page authorization must select the same cookie as the API middleware.
		page := profile.Clone(context.Background())
		page.URL.Path = "/login"
		pageResult := httptest.NewRecorder()
		h.ServeHTTP(pageResult, page)
		if pageResult.Code != http.StatusSeeOther || pageResult.Header().Get("Location") != "/" {
			t.Fatal("page authentication differs from API authentication")
		}
		logout := profile.Clone(context.Background())
		logout.Method = "POST"
		logout.URL.Path = "/api/v1/logout"
		logout.Header.Set("Content-Type", "application/json")
		loggedOut := httptest.NewRecorder()
		h.ServeHTTP(loggedOut, logout)
		deleted := loggedOut.Result().Cookies()
		if loggedOut.Code != 200 || len(deleted) != 1 || deleted[0].Name != name || deleted[0].MaxAge != -1 {
			t.Fatal("logout did not remove current protocol cookie")
		}
		replay := httptest.NewRecorder()
		h.ServeHTTP(replay, profile)
		if replay.Code != 401 {
			t.Fatal("logged-out session still accepted")
		}
	}
}

func TestReverseProxyTrust(t *testing.T) {
	s := New(nil)
	for _, tc := range []struct {
		name, remote, forwarded, proto, ip string
		secure                             bool
	}{
		{"direct", "198.51.100.7:9000", "", "", "198.51.100.7", false},
		{"spoofed", "198.51.100.7:9000", "203.0.113.2", "https", "198.51.100.7", false},
		{"proxy", "127.0.0.1:9000", "203.0.113.2", "https", "203.0.113.2", true},
		{"spoofed leftmost", "127.0.0.1:9000", "192.0.2.2, 203.0.113.2", "https", "203.0.113.2", true},
		{"bad forwarded", "127.0.0.1:9000", "bad", "https,http", "127.0.0.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://panel.example.test/", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			if s.requestHTTPS(r) != tc.secure || s.clientIP(r) != tc.ip {
				t.Fatal("incorrect proxy trust")
			}
		})
	}
	if s.SetTrustedProxies("not-a-cidr") == nil {
		t.Fatal("bad proxy configuration accepted")
	}
}

func TestHTTPAndProxyOrigin(t *testing.T) {
	s := New(nil)
	h := s.Handler(http.NotFoundHandler())
	for _, tc := range []struct {
		origin, proto, remote string
		code                  int
	}{
		{"http://panel.example.test", "", "198.51.100.7:90", 401},
		{"https://panel.example.test", "https", "127.0.0.1:90", 401},
		{"https://evil.example.test", "https", "127.0.0.1:90", 403},
		{"https://panel.example.test", "https", "198.51.100.7:90", 403},
	} {
		r := httptest.NewRequest("POST", "http://panel.example.test/api/v1/rules", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-Forwarded-Proto", tc.proto)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("origin %s: got %d", tc.origin, w.Code)
		}
	}
}
