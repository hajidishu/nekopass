package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNodeProtocolAndBasicPagesSaveOnlyTheirOwnConfiguration(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	key := Secret()
	var id int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token,public_address,notes) VALUES($1,$2,$3,'original.example.test','original note') RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
	base := fmt.Sprintf("admin/nodes/%d", id)
	for _, path := range []string{base + "/protocols", base + "/basic"} {
		securityStatus(t, f.request(f.user, path, "PUT", map[string]any{}), 403)
	}
	securityStatus(t, f.request(f.user, base+"/protocols", "GET", nil), 403)
	response := f.request(f.admin, base+"/protocols", "GET", nil)
	securityStatus(t, response, 200)
	var details struct {
		Config NodeProtocolsInput `json:"config"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil {
		t.Fatal(err)
	}
	protocol := details.Config
	protocol.IngressEnabled = true
	protocol.TunnelExitEnabled = true
	protocol.TunnelProtocol = "plain_tcp"
	protocol.TunnelListenPort = 23000
	protocol.TunnelPublicHost = "exit.example.test"
	protocol.TLS.Fingerprint = "firefox"
	protocol.TLS.ClientSNI = "override.example.test"
	protocol.TLS.FallbackURL = "https://decoy.example.test"
	securityStatus(t, f.request(f.admin, base+"/protocols", "PUT", protocol), 200)
	loaded, hash, err := loadNodeInput(ctx, f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Token != key || hash != Hash(key) || loaded.PublicAddress != "original.example.test" || loaded.Notes != "original note" {
		t.Fatal("protocol save overwrote basic configuration")
	}
	if !loaded.IngressEnabled || !loaded.TunnelExitEnabled || loaded.TLS.Fingerprint != "firefox" {
		t.Fatal("switching exit protocol erased saved transport options")
	}
	data, _ := json.Marshal(loaded)
	var basic NodeBasicInput
	_ = json.Unmarshal(data, &basic)
	basic.Name = "fixture-renamed"
	basic.Token = nil
	securityStatus(t, f.request(f.admin, base+"/basic", "PUT", basic), 200)
	updated, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != basic.Name || !reflect.DeepEqual(updated.TLS, loaded.TLS) || updated.TunnelProtocol != loaded.TunnelProtocol || updated.TunnelListenPort != 23000 || !updated.TunnelExitEnabled || updated.Token != key {
		t.Fatal("basic save overwrote protocol settings or identity")
	}
	securityStatus(t, f.request(f.admin, base+"/protocols", "PUT", map[string]any{"name": "forbidden"}), 400)
	securityStatus(t, f.request(f.admin, base+"/basic", "PUT", map[string]any{"tls": protocol.TLS}), 400)
	// Legacy hash-only credentials must not rotate on a protocol/basic edit.
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET token='' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.admin, base+"/protocols", "PUT", protocol), 200)
	securityStatus(t, f.request(f.admin, base+"/basic", "PUT", basic), 200)
	legacy, hash, err := loadNodeInput(ctx, f.p, id)
	if err != nil || legacy.Token != "" || hash != Hash(key) {
		t.Fatal("legacy node credentials changed without explicit key edit", err)
	}
	h := f.s.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.URL.Path) }))
	for actor, want := range map[int64]int{0: 303, f.user: 403, f.admin: 200} {
		r := httptest.NewRequest("GET", "/"+base+"/protocols", nil)
		if actor != 0 {
			r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: f.tokens[actor]})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		securityStatus(t, w, want)
		if actor == f.admin && w.Body.String() != "/pages/admin_node_protocols.html" {
			t.Fatal("wrong MPA document")
		}
	}
}
