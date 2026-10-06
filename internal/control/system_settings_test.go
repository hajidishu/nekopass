package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestInstallSettingsValidation(t *testing.T) {
	v := defaultSettings()
	if e := validateSettings(v); e != nil {
		t.Fatal(e)
	}
	if installReady(v) == nil {
		t.Fatal("unconfigured install enabled")
	}
	v.PanelURL = "https://panel.example.test:8443"
	v.AgentHost = "panel.example.test"
	v.InstallerURL = "https://oss.example.test/install.sh?x='$(id)'"
	v.ReleaseBaseURL = "https://oss.example.test/releases"
	if e := validateSettings(v); e != nil {
		t.Fatal(e)
	}
	command := installCommand(v, "fixture-node-key", true)
	if e := installReady(v); e != nil {
		t.Fatal("download addresses should be sufficient", e)
	}
	if strings.Contains(command, "sha256") {
		t.Fatal("installation still requires checksum")
	}
	if !strings.Contains(command, shellQuote(v.InstallerURL)) || !strings.Contains(command, "--upgrade") {
		t.Fatal("unsafe command quoting or missing upgrade flag")
	}
	for _, value := range []string{"wget ", " && bash ", "--server 'https://panel.example.test:9443'", "--token 'fixture-node-key'", shellQuote(v.ReleaseBaseURL), "--version"} {
		if !strings.Contains(command, value) {
			t.Fatal("missing direct installation parameter")
		}
	}
	if strings.Contains(command, "--install-token") || strings.Contains(command, "--panel-url") || strings.Contains(command, "\n") {
		t.Fatal("old installation wrapper retained")
	}
	v.PanelURL = ""
	if e := installReady(v); e != nil {
		t.Fatal("direct installation should not require a web panel address", e)
	}
	v.PanelURL = "http://panel.example.test:8080"
	if e := validateSettings(v); e != nil {
		t.Fatal(e)
	}
	v.PanelURL = "https://panel.example.test/path"
	if validateSettings(v) == nil {
		t.Fatal("panel subpath accepted")
	}
}

func TestSettingsKeyAndInstallTicket(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	aid, _ := testUser(t, p, 1<<20, 10, true)
	uid, _ := testUser(t, p, 1<<20, 10, false)
	var original []byte
	var originalHash string
	var originalOwner *int64
	p.QueryRow(ctx, "SELECT config,api_key_hash,api_key_user_id FROM site_settings WHERE id=1").Scan(&original, &originalHash, &originalOwner)
	defer p.Exec(ctx, "UPDATE site_settings SET config=$1,api_key_hash=$2,api_key_user_id=$3 WHERE id=1", original, originalHash, originalOwner)
	sessions := map[int64]string{}
	for _, id := range []int64{aid, uid} {
		token := Secret()
		p.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", Hash(token), id)
		sessions[id] = token
	}
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	request := func(actor int64, path, method string, body any, bearer string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		if actor > 0 {
			r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: sessions[actor]})
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
	}
	check(request(uid, "admin/settings", "GET", nil, ""), 403)
	settings := defaultSettings()
	settings.SiteName = "Settings fixture"
	settings.PanelURL = "https://panel.example.test:8443"
	settings.AgentHost = "panel.example.test"
	settings.InstallerURL = "https://oss.example.test/install.sh"
	settings.ReleaseBaseURL = "https://oss.example.test/releases"
	check(request(aid, "admin/settings", "PUT", settings, ""), 200)
	public := request(0, "site", "GET", nil, "")
	check(public, 200)
	if strings.Contains(public.Body.String(), "installer") || !strings.Contains(public.Body.String(), "Settings fixture") {
		t.Fatal("public site settings leak")
	}
	keyResult := request(aid, "admin/settings/api-key", "POST", map[string]string{}, "")
	check(keyResult, 200)
	var key struct {
		Key string `json:"key"`
	}
	json.Unmarshal(keyResult.Body.Bytes(), &key)
	check(request(0, "admin/nodes", "GET", nil, key.Key), 200)
	check(request(0, "rules", "GET", nil, key.Key), 401)
	masked := request(aid, "admin/settings", "GET", nil, "")
	if strings.Contains(masked.Body.String(), key.Key) || strings.Contains(masked.Body.String(), Hash(key.Key)) {
		t.Fatal("secret returned by settings")
	}
	nodeToken := Secret()
	var node int64
	if e := p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(nodeToken), nodeToken).Scan(&node); e != nil {
		t.Fatal(e)
	}
	defer p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node)
	check(request(aid, "admin/settings/api-key", "POST", map[string]string{"key": nodeToken}, ""), 400)
	issued := request(aid, "admin/nodes/"+strconv.FormatInt(node, 10)+"/install-command", "POST", map[string]any{}, "")
	check(issued, 200)
	if strings.Contains(issued.Body.String(), key.Key) {
		t.Fatal("admin key included in installation command")
	}
	var issuedCommand struct {
		Command string `json:"command"`
		Expires any    `json:"expires_at"`
	}
	if json.Unmarshal(issued.Body.Bytes(), &issuedCommand) != nil || !strings.Contains(issuedCommand.Command, nodeToken) || issuedCommand.Expires != nil {
		t.Fatal("direct command missing persistent node key")
	}
	// Insert a known one-time ticket to test redemption without exposing plaintext storage.
	token := Secret()
	data, _ := json.Marshal(settings)
	p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()+interval '10 minutes',$3)", Hash(token), node, data)
	redeemed := request(0, "node-install/redeem", "POST", map[string]string{}, token)
	check(redeemed, 200)
	var result struct {
		Token  string `json:"token"`
		Server string `json:"server"`
	}
	json.Unmarshal(redeemed.Body.Bytes(), &result)
	if result.Token != nodeToken || result.Server != "https://panel.example.test:9443" {
		t.Fatal("bootstrap missing connection data")
	}
	if strings.Contains(redeemed.Body.String(), "sha256") {
		t.Fatal("bootstrap includes removed checksum settings")
	}
	another := Secret()
	p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()+interval '10 minutes',$3)", Hash(another), node, data)
	second := request(0, "node-install/redeem", "POST", map[string]string{}, another)
	check(second, 200)
	var stable struct {
		Token string `json:"token"`
	}
	json.Unmarshal(second.Body.Bytes(), &stable)
	if stable.Token != nodeToken {
		t.Fatal("repeat installation changed visible node key")
	}
	check(request(0, "node-install/redeem", "POST", map[string]string{}, token), 401)
	p.Exec(ctx, "UPDATE nodes SET instance_id='bound-instance' WHERE id=$1", node)
	upgrade := Secret()
	p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()+interval '10 minutes',$3)", Hash(upgrade), node, data)
	check(request(0, "node-install/redeem", "POST", map[string]string{}, upgrade), 409)
	upgraded := request(0, "node-install/redeem", "POST", map[string]string{"current_token": result.Token}, upgrade)
	check(upgraded, 200)
	var again struct {
		Token string `json:"token"`
	}
	json.Unmarshal(upgraded.Body.Bytes(), &again)
	if again.Token != result.Token {
		t.Fatal("upgrade rotated node identity")
	}
	expired := Secret()
	p.Exec(ctx, "INSERT INTO node_install_tickets(token_hash,node_id,expires_at,config) VALUES($1,$2,now()-interval '1 second',$3)", Hash(expired), node, data)
	check(request(0, "node-install/redeem", "POST", map[string]string{}, expired), 401)
	check(request(aid, "admin/settings/api-key", "DELETE", nil, ""), 200)
	check(request(0, "admin/nodes", "GET", nil, key.Key), 401)
}
