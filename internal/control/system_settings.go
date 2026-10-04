package control

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/release"
	"github.com/nekopass/nekopass/internal/store"
)

type SystemSettings struct {
	SiteName            string `json:"site_name"`
	PanelURL            string `json:"panel_url"`
	AgentHost           string `json:"agent_host"`
	AgentPort           int    `json:"agent_port"`
	InstallerURL        string `json:"installer_url"`
	ReleaseBaseURL      string `json:"release_base_url"`
	AgentVersion        string `json:"agent_version"`
	InstallTokenMinutes int    `json:"install_token_minutes"`
}

func defaultSettings() SystemSettings {
	return SystemSettings{SiteName: "Nekopass", AgentPort: 9443, AgentVersion: "latest", InstallerURL: release.LatestBase + "/install-agent.sh", ReleaseBaseURL: release.DownloadBase, InstallTokenMinutes: 30}
}
func (s *Server) readSettings(ctx context.Context) (SystemSettings, error) {
	v := defaultSettings()
	var data []byte
	e := s.Pool.QueryRow(ctx, "SELECT config FROM site_settings WHERE id=1").Scan(&data)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(data, &v)
	return v, e
}
func hashOK(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func httpsURL(raw string, originOnly bool) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && !strings.ContainsAny(raw, "\r\n\x00") && (!originOnly || (u.Path == "" || u.Path == "/") && u.RawQuery == "")
}

var releaseVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateSettings(v SystemSettings) error {
	if strings.TrimSpace(v.SiteName) == "" || len([]rune(v.SiteName)) > 64 || strings.ContainsAny(v.SiteName, "\r\n\x00") {
		return errors.New("站点名称须为 1–64 字")
	}
	if v.PanelURL != "" && !panelURL(v.PanelURL) {
		return errors.New("面板地址须为 HTTP 或 HTTPS 根地址，可包含端口")
	}
	if v.AgentHost != "" && !ValidTarget(v.AgentHost) {
		return errors.New("Agent 主机须为域名或 IP，不含协议和端口")
	}
	if v.AgentPort < 1 || v.AgentPort > 65535 || v.InstallTokenMinutes < 5 || v.InstallTokenMinutes > 1440 {
		return errors.New("端口或安装凭证有效期超出范围")
	}
	for _, raw := range []string{v.InstallerURL, v.ReleaseBaseURL} {
		if raw != "" && (!httpsURL(raw, false) || len(raw) > 2048) {
			return errors.New("下载地址须为有效 HTTPS 地址")
		}
	}
	if v.ReleaseBaseURL != "" {
		u, _ := url.Parse(v.ReleaseBaseURL)
		if u.RawQuery != "" {
			return errors.New("版本下载根地址不能包含查询参数")
		}
	}
	if !releaseVersion.MatchString(v.AgentVersion) || strings.Contains(v.AgentVersion, "..") {
		return errors.New("版本号格式无效")
	}
	return nil
}
func panelURL(raw string) bool {
	return httpsURL(raw, true) || strings.HasPrefix(raw, "http://") && httpsURL("https://"+strings.TrimPrefix(raw, "http://"), true)
}
func installReady(v SystemSettings) error {
	if v.PanelURL == "" || v.AgentHost == "" || v.InstallerURL == "" || v.ReleaseBaseURL == "" {
		return errors.New("请先配置面板地址、Agent 地址和安装文件下载地址")
	}
	if strings.Contains(strings.ToLower(v.InstallerURL), "your-oss.example.com") || strings.Contains(strings.ToLower(v.ReleaseBaseURL), "your-oss.example.com") {
		return errors.New("请先在系统设置中填写实际安装文件下载地址")
	}
	return nil
}
func (s *Server) publicSite(w http.ResponseWriter, r *http.Request) {
	v, e := s.readSettings(r.Context())
	if e != nil {
		fail(w, 503, "暂时无法加载站点设置")
		return
	}
	writeJSON(w, 200, map[string]string{"site_name": v.SiteName})
}
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	v, e := s.readSettings(r.Context())
	if e != nil {
		s.dbError(w, e)
		return
	}
	var has bool
	if e = s.Pool.QueryRow(r.Context(), "SELECT api_key_hash<>'' AND NOT EXISTS(SELECT 1 FROM nodes WHERE token_hash=api_key_hash) FROM site_settings WHERE id=1").Scan(&has); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"settings": v, "api_key_configured": has})
}
func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	v := defaultSettings()
	if !decode(w, r, &v) {
		return
	}
	v.SiteName = strings.TrimSpace(v.SiteName)
	v.PanelURL = strings.TrimRight(v.PanelURL, "/")
	v.ReleaseBaseURL = strings.TrimRight(v.ReleaseBaseURL, "/")
	if e := validateSettings(v); e != nil {
		fail(w, 400, e.Error())
		return
	}
	data, _ := json.Marshal(v)
	if _, e := s.Pool.Exec(r.Context(), "UPDATE site_settings SET config=$1,updated_at=now() WHERE id=1", data); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Key string `json:"key"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Key == "" {
		in.Key = Secret()
	}
	if len(in.Key) < 32 || len(in.Key) > 256 || strings.ContainsAny(in.Key, " \t\r\n\x00") {
		fail(w, 400, "API 密钥须为 32–256 个不含空白的字符")
		return
	}
	tx, e := s.ruleTx(r.Context())
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	var reused bool
	if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM nodes WHERE token_hash=$1)", Hash(in.Key)).Scan(&reused); e != nil {
		s.dbError(w, e)
		return
	}
	if reused {
		fail(w, 400, "管理 API 密钥不能复用节点密钥")
		return
	}
	if _, e := tx.Exec(r.Context(), "UPDATE site_settings SET api_key_hash=$1,api_key_user_id=$2 WHERE id=1", Hash(in.Key), current(r).ID); e != nil {
		s.dbError(w, e)
		return
	}
	if e := tx.Commit(r.Context()); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]string{"key": in.Key})
}
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	if _, e := s.Pool.Exec(r.Context(), "UPDATE site_settings SET api_key_hash='',api_key_user_id=NULL WHERE id=1"); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// Revoke the higher-privilege credential before a node edit/delete removes the
// overlap. Otherwise its formerly shared key would become valid again afterward.
func revokeOverlappingAPIKey(ctx context.Context, db store.DBTX) error {
	_, err := db.Exec(ctx, "UPDATE site_settings SET api_key_hash='',api_key_user_id=NULL WHERE id=1 AND api_key_hash<>'' AND EXISTS(SELECT 1 FROM nodes WHERE token_hash=api_key_hash)")
	return err
}

func (s *Server) apiKeyUser(r *http.Request) (store.User, error) {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
		return store.User{}, errors.New("management API only")
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == r.Header.Get("Authorization") || len(key) < 32 || len(key) > 256 {
		return store.User{}, errors.New("invalid API key")
	}
	var hash string
	var uid *int64
	var reused bool
	if e := s.Pool.QueryRow(r.Context(), "SELECT api_key_hash,api_key_user_id,EXISTS(SELECT 1 FROM nodes WHERE token_hash=api_key_hash) FROM site_settings WHERE id=1").Scan(&hash, &uid, &reused); e != nil {
		return store.User{}, e
	}
	if reused {
		// This snapshot proves the key was shared. Guard against concurrent key
		// rotation, but do not restore validity when the node rotates its token.
		_, _ = s.Pool.Exec(r.Context(), "UPDATE site_settings SET api_key_hash='',api_key_user_id=NULL WHERE id=1 AND api_key_hash=$1", hash)
		return store.User{}, errors.New("management key overlapped a node credential; rotate management key")
	}
	if uid == nil || hash == "" || subtle.ConstantTimeCompare([]byte(hash), []byte(Hash(key))) != 1 {
		return store.User{}, errors.New("invalid API key")
	}
	u, e := s.query.FindUser(r.Context(), *uid)
	if e != nil || !u.Enabled || !u.IsAdmin {
		return store.User{}, errors.New("API key owner inactive")
	}
	return u, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func installCommand(v SystemSettings, ticket string, bound bool) string {
	args := []string{"--panel-url", v.PanelURL, "--install-token", ticket}
	if bound {
		args = append(args, "--upgrade")
	}
	quoted := []string{}
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	return "(set -eu\n" +
		"[ \"$(id -u)\" -eq 0 ] || { echo '请以 root 运行'; exit 1; }\n" +
		"if ! command -v curl >/dev/null 2>&1; then\n  if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y curl ca-certificates;\n  elif command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates;\n  elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates;\n  else echo '请先安装 curl 和 ca-certificates'; exit 1; fi\nfi\n" +
		"installer=$(mktemp)\ntrap 'rm -f \"$installer\"' EXIT\n" +
		"curl --fail --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 " + shellQuote(v.InstallerURL) + " -o \"$installer\"\n" +
		"bash \"$installer\" " + strings.Join(quoted, " ") + "\n)"
}
func (s *Server) nodeInstallCommand(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id < 1 {
		fail(w, 400, "节点 ID 无效")
		return
	}
	v, e := s.readSettings(r.Context())
	if e != nil {
		s.dbError(w, e)
		return
	}
	if e = installReady(v); e != nil {
		fail(w, 409, e.Error())
		return
	}
	var bound bool
	if e = s.Pool.QueryRow(r.Context(), "SELECT instance_id<>'' FROM nodes WHERE id=$1", id).Scan(&bound); e != nil {
		fail(w, 404, "节点不存在")
		return
	}
	ticket := Secret()
	expires := time.Now().Add(time.Duration(v.InstallTokenMinutes) * time.Minute)
	data, _ := json.Marshal(v)
	if _, e = s.Pool.Exec(r.Context(), "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,$3,$4)", Hash(ticket), id, expires, data); e != nil {
		s.dbError(w, e)
		return
	}
	_, _ = s.Pool.Exec(r.Context(), "DELETE FROM node_install_tickets WHERE expires_at<now()-interval '1 day'")
	writeJSON(w, 200, map[string]any{"command": installCommand(v, ticket, bound), "expires_at": expires, "existing_node": bound})
}
func (s *Server) redeemInstall(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if auth == token || !hashOK(token) {
		fail(w, 401, "安装凭证无效")
		return
	}
	var in struct {
		CurrentToken string `json:"current_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.CurrentToken) > 256 {
		fail(w, 400, "节点密钥无效")
		return
	}
	ctx := r.Context()
	var controlCA string
	if path := os.Getenv("NEKOPASS_AGENT_CA"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 65536 || publicCertificatePEM(string(data)) != nil {
			fail(w, 503, "节点连接公开 CA 配置无效")
			return
		}
		controlCA = string(data)
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		s.dbError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var id int64
	var data []byte
	e = tx.QueryRow(ctx, "SELECT node_id,config FROM node_install_tickets WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE", Hash(token)).Scan(&id, &data)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			fail(w, 401, "安装凭证已使用、已过期或不存在")
		} else {
			s.dbError(w, e)
		}
		return
	}
	var instance, hash, stored string
	if e = tx.QueryRow(ctx, "SELECT instance_id,token_hash,token FROM nodes WHERE id=$1 FOR UPDATE", id).Scan(&instance, &hash, &stored); e != nil {
		s.dbError(w, e)
		return
	}
	nodeToken := stored
	if instance != "" {
		if in.CurrentToken == "" || subtle.ConstantTimeCompare([]byte(Hash(in.CurrentToken)), []byte(hash)) != 1 {
			fail(w, 409, "节点已绑定，请在原节点升级；新服务器请新建节点，勿删除状态文件")
			return
		}
	}
	if nodeToken == "" {
		if in.CurrentToken != "" && subtle.ConstantTimeCompare([]byte(Hash(in.CurrentToken)), []byte(hash)) == 1 {
			nodeToken = in.CurrentToken
		} else {
			nodeToken = Secret()
		}
		if _, e = tx.Exec(ctx, "UPDATE nodes SET token_hash=$2,token=$3 WHERE id=$1", id, Hash(nodeToken), nodeToken); e != nil {
			s.dbError(w, e)
			return
		}
	}
	var v SystemSettings
	if e = json.Unmarshal(data, &v); e != nil {
		s.dbError(w, e)
		return
	}
	if _, e = tx.Exec(ctx, "UPDATE node_install_tickets SET used_at=now() WHERE token_hash=$1", Hash(token)); e != nil {
		s.dbError(w, e)
		return
	}
	if e = tx.Commit(ctx); e != nil {
		s.dbError(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"node_id": id, "server": net.JoinHostPort(v.AgentHost, strconv.Itoa(v.AgentPort)), "token": nodeToken, "version": v.AgentVersion, "download_base": v.ReleaseBaseURL, "control_ca": controlCA})
}
