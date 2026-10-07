package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nekopass/nekopass/internal/payment"
	"github.com/nekopass/nekopass/internal/payment/epay"
	"github.com/nekopass/nekopass/internal/registration"
	"github.com/nekopass/nekopass/internal/release"
	"github.com/nekopass/nekopass/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

type Server struct {
	mailWorkers    chan struct{}
	sendMail       func(context.Context, registration.SMTP, string, string, string) error
	payments       *payment.Registry
	Pool           *pgxpool.Pool
	query          *store.Queries
	loginMu        sync.Mutex
	loginBuckets   map[string]*loginBucket
	loginPruned    time.Time
	loginWorkers   chan struct{}
	trustedProxies []*net.IPNet
	releaseMu      sync.Mutex
	releaseClient  *release.Client
	releaseChecked time.Time
	releaseInfo    release.Info
	releaseError   error
	panelUpdateMu  sync.Mutex
	panelUpdateDir string
	settingsMu     sync.Mutex
	agentListener  *agentListener
}
type loginBucket struct {
	limiter *rate.Limiter
	seen    time.Time
}
type userKey struct{}

func New(p *pgxpool.Pool) *Server {
	s := &Server{Pool: p, query: store.New(p), loginBuckets: map[string]*loginBucket{}, loginWorkers: make(chan struct{}, 4)}
	s.mailWorkers = make(chan struct{}, 4)
	s.sendMail = registration.SendCode
	s.releaseClient = release.NewClient()
	s.payments = payment.NewRegistry(epay.Driver{})
	_ = s.SetTrustedProxies("127.0.0.0/8,::1/128")
	return s
}
func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func Secret() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	var data json.RawMessage
	if e := d.Decode(&data); e != nil || len(data) == 0 || data[0] != '{' {
		fail(w, 400, "无效的请求内容")
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return false
	}
	valueDecoder := json.NewDecoder(bytes.NewReader(data))
	valueDecoder.DisallowUnknownFields()
	if e := valueDecoder.Decode(v); e != nil {
		fail(w, 400, "无效的请求内容")
		return false
	}
	return true
}
func current(r *http.Request) store.User { return r.Context().Value(userKey{}).(store.User) }
func admin(w http.ResponseWriter, r *http.Request) bool {
	if !current(r).IsAdmin {
		fail(w, 403, "需要管理员权限")
		return false
	}
	return true
}
func (s *Server) dbError(w http.ResponseWriter, e error) {
	slog.Error("database operation", "error", e)
	fail(w, 409, "操作失败：请检查唯一约束、资源权限及额度限制")
}

func (s *Server) Handler(static http.Handler) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		u := current(r)
		writeJSON(w, 200, map[string]any{"id": u.ID, "username": u.Username, "is_admin": u.IsAdmin})
	})
	api.HandleFunc("POST /api/v1/logout", s.logout)
	api.HandleFunc("GET /api/v1/admin/settings", s.getSettings)
	api.HandleFunc("GET /api/v1/admin/updates", s.checkUpdates)
	api.HandleFunc("GET /api/v1/admin/updates/panel", s.panelUpdateStatus)
	api.HandleFunc("POST /api/v1/admin/updates/panel", s.updatePanel)
	api.HandleFunc("POST /api/v1/admin/nodes/{id}/update", s.updateNode)
	api.HandleFunc("PUT /api/v1/admin/settings", s.saveSettings)
	api.HandleFunc("POST /api/v1/admin/settings/api-key", s.rotateAPIKey)
	api.HandleFunc("DELETE /api/v1/admin/settings/api-key", s.revokeAPIKey)
	api.HandleFunc("POST /api/v1/admin/nodes/{id}/install-command", s.nodeInstallCommand)
	api.HandleFunc("GET /api/v1/admin/nodes/{id}/ddns", s.nodeDDNS)
	api.HandleFunc("GET /api/v1/admin/nodes/{id}/protocols", s.nodeProtocols)
	api.HandleFunc("PUT /api/v1/admin/nodes/{id}/protocols", s.saveNodeProtocols)
	api.HandleFunc("PUT /api/v1/admin/nodes/{id}/basic", s.saveNodeBasic)
	api.HandleFunc("PUT /api/v1/admin/nodes/{id}/ddns", s.saveNodeDDNS)
	api.HandleFunc("POST /api/v1/admin/nodes/{id}/ddns/run", s.runNodeDDNS)
	api.HandleFunc("GET /api/v1/profile", s.profile)
	api.HandleFunc("GET /api/v1/wallet", s.wallet)
	api.HandleFunc("GET /api/v1/orders", s.orders)
	api.HandleFunc("GET /api/v1/admin/orders", s.adminOrders)
	api.HandleFunc("GET /api/v1/admin/orders/{id}", s.adminOrder)
	api.HandleFunc("GET /api/v1/referrals", s.referrals)
	api.HandleFunc("GET /api/v1/tickets/config", s.ticketConfig)
	api.HandleFunc("GET /api/v1/tickets/captcha", s.ticketCaptcha)
	api.HandleFunc("GET /api/v1/tickets", s.tickets)
	api.HandleFunc("POST /api/v1/tickets", s.createTicket)
	api.HandleFunc("GET /api/v1/tickets/{id}", s.ticket)
	api.HandleFunc("POST /api/v1/tickets/{id}/messages", s.replyTicket)
	api.HandleFunc("PUT /api/v1/tickets/{id}/status", s.ticketStatus)
	api.HandleFunc("GET /api/v1/admin/tickets", s.tickets)
	api.HandleFunc("GET /api/v1/admin/tickets/{id}", s.ticket)
	api.HandleFunc("POST /api/v1/admin/tickets/{id}/messages", s.replyTicket)
	api.HandleFunc("PUT /api/v1/admin/tickets/{id}/status", s.ticketStatus)
	api.HandleFunc("GET /api/v1/announcements", s.announcements)
	api.HandleFunc("GET /api/v1/announcements/{id}", s.announcementDetail)
	api.HandleFunc("GET /api/v1/admin/announcements", s.announcements)
	api.HandleFunc("POST /api/v1/admin/announcements", s.saveNotice)
	api.HandleFunc("PUT /api/v1/admin/announcements/{id}", s.saveNotice)
	api.HandleFunc("DELETE /api/v1/admin/announcements/{id}", s.deleteNotice)
	api.HandleFunc("GET /api/v1/shop/plans", s.shopPlans)
	api.HandleFunc("POST /api/v1/shop/quote", s.shopQuote)
	api.HandleFunc("POST /api/v1/shop/purchase", s.shopPurchase)
	api.HandleFunc("POST /api/v1/admin/users/{id}/recharge", s.adminRecharge)
	api.HandleFunc("GET /api/v1/admin/users", s.adminOnly(s.users))
	api.HandleFunc("POST /api/v1/admin/users", s.saveUser)
	api.HandleFunc("PUT /api/v1/admin/users/{id}", s.saveUser)
	api.HandleFunc("GET /api/v1/admin/users/{userID}", s.managedUser(s.profile))
	api.HandleFunc("GET /api/v1/admin/announcement", s.adminOnly(s.announcement))
	api.HandleFunc("PUT /api/v1/admin/announcement", s.saveAnnouncement)
	api.HandleFunc("GET /api/v1/announcement", s.announcement)
	api.HandleFunc("PUT /api/v1/announcement", s.saveAnnouncement)
	api.HandleFunc("GET /api/v1/rule-groups", s.groups)
	api.HandleFunc("POST /api/v1/rule-groups", s.saveGroup)
	api.HandleFunc("PUT /api/v1/rule-groups/{id}", s.saveGroup)
	api.HandleFunc("DELETE /api/v1/rule-groups/{id}", s.deleteGroup)
	api.HandleFunc("POST /api/v1/rules/batch", s.batchRules)
	api.HandleFunc("POST /api/v1/rules/import", s.importRules)
	api.HandleFunc("GET /api/v1/rules/stats", s.ruleStats)
	api.HandleFunc("PUT /api/v1/nodes/{id}", s.saveNode)

	api.HandleFunc("GET /api/v1/users", s.users)
	api.HandleFunc("POST /api/v1/users", s.saveUser)
	api.HandleFunc("PUT /api/v1/users/{id}", s.saveUser)
	api.HandleFunc("GET /api/v1/nodes", s.nodes)
	api.HandleFunc("POST /api/v1/nodes", s.saveNode)
	api.HandleFunc("GET /api/v1/rules", s.rules)
	api.HandleFunc("POST /api/v1/rules", s.saveRule)
	api.HandleFunc("PUT /api/v1/rules/{id}", s.saveRule)
	api.HandleFunc("DELETE /api/v1/rules/{id}", s.deleteRule)
	api.HandleFunc("GET /api/v1/rule-nodes", s.ruleNodes)
	api.HandleFunc("GET /api/v1/node-status", s.nodeStatus)
	api.HandleFunc("GET /api/v1/admin/plans", s.plans)
	api.HandleFunc("GET /api/v1/admin/payment-interfaces", s.paymentInterfaces)
	api.HandleFunc("GET /api/v1/admin/payment-methods", s.paymentMethods)
	api.HandleFunc("POST /api/v1/admin/payment-methods", s.savePaymentMethod)
	api.HandleFunc("PUT /api/v1/admin/payment-methods/{id}", s.savePaymentMethod)
	api.HandleFunc("DELETE /api/v1/admin/payment-methods/{id}", s.deletePaymentMethod)
	api.HandleFunc("POST /api/v1/wallet/recharge", s.createRecharge)
	api.HandleFunc("POST /api/v1/orders/{id}/pay", s.payRechargeOrder)
	api.HandleFunc("POST /api/v1/admin/plans", s.savePlan)
	api.HandleFunc("PUT /api/v1/admin/plans/{id}", s.savePlan)
	api.HandleFunc("DELETE /api/v1/admin/plans/{id}", s.deletePlan)
	api.HandleFunc("GET /api/v1/admin/nodes", s.nodes)
	api.HandleFunc("POST /api/v1/admin/nodes", s.saveNode)
	api.HandleFunc("PUT /api/v1/admin/nodes/{id}", s.saveNode)
	api.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.deleteNode)
	api.HandleFunc("GET /api/v1/admin/node-groups", s.nodeGroups)
	api.HandleFunc("POST /api/v1/admin/node-groups", s.saveNodeGroup)
	api.HandleFunc("PUT /api/v1/admin/node-groups/{id}", s.saveNodeGroup)
	api.HandleFunc("DELETE /api/v1/admin/node-groups/{id}", s.deleteNodeGroup)
	api.HandleFunc("GET /api/v1/admin/users/{userID}/rules", s.managedUser(s.rules))
	api.HandleFunc("POST /api/v1/admin/users/{userID}/rules", s.managedUser(s.saveRule))
	api.HandleFunc("PUT /api/v1/admin/users/{userID}/rules/{id}", s.managedUser(s.saveRule))
	api.HandleFunc("DELETE /api/v1/admin/users/{userID}/rules/{id}", s.managedUser(s.deleteRule))
	api.HandleFunc("POST /api/v1/admin/users/{userID}/rules/batch", s.managedUser(s.batchRules))
	api.HandleFunc("POST /api/v1/admin/users/{userID}/rules/import", s.managedUser(s.importRules))
	api.HandleFunc("GET /api/v1/admin/users/{userID}/rules/stats", s.managedUser(s.ruleStats))
	api.HandleFunc("GET /api/v1/admin/users/{userID}/rule-nodes", s.managedUser(s.ruleNodes))
	api.HandleFunc("GET /api/v1/admin/users/{userID}/rule-groups", s.managedUser(s.groups))
	api.HandleFunc("POST /api/v1/admin/users/{userID}/rule-groups", s.managedUser(s.saveGroup))
	api.HandleFunc("PUT /api/v1/admin/users/{userID}/rule-groups/{id}", s.managedUser(s.saveGroup))
	api.HandleFunc("DELETE /api/v1/admin/users/{userID}/rule-groups/{id}", s.managedUser(s.deleteGroup))

	root := http.NewServeMux()
	root.HandleFunc("POST /api/v1/login", s.login)
	root.HandleFunc("GET /api/v1/registration", s.registrationConfig)
	root.HandleFunc("GET /api/v1/registration/captcha", s.captcha)
	root.HandleFunc("POST /api/v1/registration/email-code", s.sendRegistrationCode)
	root.HandleFunc("POST /api/v1/register", s.register)
	root.HandleFunc("GET /api/v1/site", s.publicSite)
	root.HandleFunc("POST /api/v1/node-install/redeem", s.redeemInstall)
	root.HandleFunc("GET /api/v1/payments/notify/{interface}/{methodID}", s.paymentNotify)
	root.HandleFunc("POST /api/v1/payments/notify/{interface}/{methodID}", s.paymentNotify)
	root.HandleFunc("GET /api/v1/payments/return", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/orders?payment=returned", http.StatusSeeOther)
	})
	root.Handle("/api/", s.auth(api))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if s.Pool.Ping(ctx) != nil {
			fail(w, 503, "database unavailable")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	root.Handle("/", s.pages(static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		if r.Method != "GET" && r.Method != "HEAD" && !paymentCallbackPath(r) {
			if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
				fail(w, 403, "来源不匹配")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				scheme := "http"
				if s.requestHTTPS(r) {
					scheme = "https"
				}
				if e != nil || u.Host != r.Host || u.Scheme != scheme {
					fail(w, 403, "来源不匹配")
					return
				}
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				fail(w, 415, "需要 application/json")
				return
			}
		}
		root.ServeHTTP(w, r)
	})
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie(s.sessionCookieName(r)); e == nil {
			u, err := s.query.FindSession(r.Context(), Hash(c.Value))
			if err == nil && u.Enabled {
				if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") && !u.IsAdmin {
					fail(w, 403, "需要管理员权限")
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
				return
			}
		}
		if r.Header.Get("Authorization") != "" {
			if u, e := s.apiKeyUser(r); e == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
				return
			}
		}
		fail(w, 401, "请登录或提供有效的管理 API 密钥")
	})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if !s.allowLogin("ip:"+s.clientIP(r), now, 5) {
		fail(w, 429, "登录尝试过于频繁")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	originalUsername := in.Username
	if email, err := registration.Email(in.Username); err == nil {
		in.Username = email
	}
	if len(in.Username) == 0 || len(in.Username) > 254 || len(in.Password) < 12 || len(in.Password) > 72 {
		fail(w, 401, "账号或密码错误")
		return
	}
	if !s.allowLogin("account:"+in.Username, now, 10) {
		fail(w, 429, "登录尝试过于频繁")
		return
	}
	// Limit expensive password work rather than allowing unbounded goroutines
	// from many source addresses or usernames to exhaust a small controller.
	select {
	case s.loginWorkers <- struct{}{}:
		defer func() { <-s.loginWorkers }()
	default:
		fail(w, 429, "登录请求较多，请稍后重试")
		return
	}
	u, e := s.query.FindUserByName(r.Context(), in.Username)
	// Preserve exact login for legacy administrator-created mixed-case emails.
	if e != nil && originalUsername != in.Username {
		u, e = s.query.FindUserByName(r.Context(), originalUsername)
	}
	passwordHash := dummyLoginHash
	if e == nil && u.Enabled {
		passwordHash = []byte(u.PasswordHash)
	}
	passwordErr := bcrypt.CompareHashAndPassword(passwordHash, []byte(in.Password))
	if e != nil || !u.Enabled || passwordErr != nil {
		fail(w, 401, "账号或密码错误")
		return
	}
	token := Secret()
	e = s.createLoginSession(r.Context(), u, token, time.Now().Add(12*time.Hour))
	if errors.Is(e, errLoginChanged) {
		fail(w, 401, "账号或密码错误")
		return
	}
	if e != nil {
		s.dbError(w, e)
		return
	}
	_, _ = s.Pool.Exec(r.Context(), "DELETE FROM sessions WHERE expires_at<now()")
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(r), Value: token, Path: "/", HttpOnly: true, Secure: s.requestHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	writeJSON(w, 200, map[string]any{"id": u.ID, "username": u.Username, "is_admin": u.IsAdmin})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(s.sessionCookieName(r))
	if c != nil {
		if err := s.query.DeleteSession(r.Context(), Hash(c.Value)); err != nil {
			s.dbError(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(r), Path: "/", Value: "", MaxAge: -1, Secure: s.requestHTTPS(r), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func ValidTarget(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func Bootstrap(ctx context.Context, p *pgxpool.Pool, username, password string) error {
	if username == "" || len(password) < 12 || len(password) > 72 {
		return errors.New("admin username and 12–72 byte password required")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	tag, e := p.Exec(ctx, "INSERT INTO users(username,password_hash,is_admin) VALUES($1,$2,true) ON CONFLICT(username) DO NOTHING", username, string(h))
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("account already exists; not modified")
	}
	return nil
}
