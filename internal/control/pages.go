package control

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/store"
)

type pageRoute struct {
	file   string
	admin  bool
	userID int64
	nodeID int64
}

func resolvePage(path string) (pageRoute, bool) {
	pages := map[string]pageRoute{
		"/admin/orders": {file: "admin_orders", admin: true}, "/tickets": {file: "tickets"}, "/admin/tickets": {file: "admin_tickets", admin: true}, "/register": {file: "register"}, "/referrals": {file: "referrals"}, "/shop": {file: "shop"}, "/orders": {file: "orders"}, "/admin/payment_gateways": {file: "admin_payment_gateways", admin: true},
		"/admin/settings": {file: "admin_settings", admin: true},
		"/":               {file: "home"}, "/login": {file: "login"}, "/profile": {file: "profile"}, "/forward_rules": {file: "forward_rules"}, "/node_status": {file: "node_status"},
		"/admin": {file: "admin", admin: true}, "/admin/announcements": {file: "admin_announcements", admin: true}, "/admin/users": {file: "admin_users", admin: true}, "/admin/plans": {file: "admin_plans", admin: true}, "/admin/nodes": {file: "admin_nodes", admin: true}, "/admin/node_groups": {file: "admin_node_groups", admin: true},
	}
	if p, ok := pages[path]; ok {
		return p, true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[1] == "admin" && parts[2] == "nodes" && (parts[4] == "ddns" || parts[4] == "protocols") {
		id, err := strconv.ParseInt(parts[3], 10, 64)
		if err == nil && id > 0 && strconv.FormatInt(id, 10) == parts[3] {
			file := "admin_node_ddns"
			if parts[4] == "protocols" {
				file = "admin_node_protocols"
			}
			return pageRoute{file: file, admin: true, nodeID: id}, true
		}
	}
	if len(parts) == 5 && parts[1] == "admin" && parts[2] == "users" && parts[4] == "forward_rules" {
		id, e := strconv.ParseInt(parts[3], 10, 64)
		if e == nil && id > 0 && strconv.FormatInt(id, 10) == parts[3] {
			return pageRoute{file: "admin_user_rules", admin: true, userID: id}, true
		}
	}
	return pageRoute{}, false
}

func safeNext(raw string, isAdmin bool) string {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n") {
		return "/"
	}
	u, e := url.Parse(raw)
	if e != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || u.Fragment != "" {
		return "/"
	}
	p, ok := resolvePage(u.Path)
	if !ok || (p.file == "login" || p.file == "register") || (p.admin && !isAdmin) {
		return "/"
	}
	return u.RequestURI()
}

var pageErrorTemplate = template.Must(template.New("error").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Code}} · Nekopass</title><style>body{margin:0;background:#0b1322;color:#dce7f7;font:15px system-ui;min-height:100vh;display:grid;place-items:center}.card{max-width:460px;padding:36px;border:1px solid #253650;border-radius:22px;background:#131f32;margin:20px}h1{color:#98c2ff}p{line-height:1.8}a{color:#98c2ff}</style></head><body><main class="card"><h1>{{.Code}}</h1><p>{{.Message}}</p><a href="/">返回主页</a></main></body></html>`))

func pageError(w http.ResponseWriter, r *http.Request, code int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if r.Method != "HEAD" {
		_ = pageErrorTemplate.Execute(w, map[string]any{"Code": code, "Message": message})
	}
}

// Explicit HTML documents, with server-side session checks. No SPA fallback.
func (s *Server) pages(static http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			pageError(w, r, 405, "此页面不支持该请求方法。")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") && !strings.HasSuffix(r.URL.Path, "/") {
			if strings.Contains(r.URL.Path, "..") {
				pageError(w, r, 404, "页面不存在。")
				return
			}
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			static.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/openapi.yaml" {
			static.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if path == "/index.html" {
			http.Redirect(w, r, "/", http.StatusPermanentRedirect)
			return
		}
		canonical := strings.TrimSuffix(path, "/")
		if canonical != "" && canonical != path {
			if _, ok := resolvePage(canonical); ok {
				if r.URL.RawQuery != "" {
					canonical += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, canonical, http.StatusPermanentRedirect)
				return
			}
		}
		route, ok := resolvePage(path)
		if !ok {
			pageError(w, r, 404, "页面不存在，请检查地址。")
			return
		}
		var user *store.User
		if cookie, e := r.Cookie(s.sessionCookieName(r)); e == nil {
			u, err := s.query.FindSession(r.Context(), Hash(cookie.Value))
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				pageError(w, r, 503, "暂时无法验证登录状态，请稍后重试。")
				return
			}
			if err == nil && u.Enabled {
				user = &u
			}
		}
		if route.file == "login" || route.file == "register" {
			if user != nil {
				http.Redirect(w, r, safeNext(r.URL.Query().Get("next"), user.IsAdmin), http.StatusSeeOther)
				return
			}
		} else {
			if user == nil {
				next := url.QueryEscape(r.URL.RequestURI())
				http.Redirect(w, r, "/login?next="+next, http.StatusSeeOther)
				return
			}
			if route.admin && !user.IsAdmin {
				pageError(w, r, 403, "此页面仅管理员可访问。")
				return
			}
			if route.userID > 0 {
				if _, e := s.query.FindUser(r.Context(), route.userID); e != nil {
					if errors.Is(e, pgx.ErrNoRows) {
						pageError(w, r, 404, "用户不存在。")
					} else {
						pageError(w, r, 503, "暂时无法加载用户。")
					}
					return
				}
			}
		}
		if route.nodeID > 0 {
			var id int64
			if err := s.Pool.QueryRow(r.Context(), "SELECT id FROM nodes WHERE id=$1", route.nodeID).Scan(&id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					pageError(w, r, 404, "节点不存在。")
				} else {
					pageError(w, r, 503, "暂时无法加载节点。")
				}
				return
			}
		}
		// Only a fixed, authorized route can reach its HTML build artifact.
		copy := r.Clone(r.Context())
		u := *r.URL
		copy.URL = &u
		copy.URL.Path = "/pages/" + route.file + ".html"
		copy.URL.RawPath = ""
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, copy)
	})
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	u := ruleActor(r)
	s.users(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
}
func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if admin(w, r) {
			next(w, r)
		}
	}
}
