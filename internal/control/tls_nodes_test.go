package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestTLSNodeConfigurationScopeAndProtocolGate(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	adminID, _ := testUser(t, p, 1<<20, 10, true)
	uid, _ := testUser(t, p, 1<<20, 10, false)
	tokens := map[int64]string{}
	for _, id := range []int64{adminID, uid} {
		tokens[id] = Secret()
		if _, err := p.Exec(ctx, "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour')", Hash(tokens[id]), id); err != nil {
			t.Fatal(err)
		}
	}
	s := New(p)
	h := s.Handler(http.NotFoundHandler())
	request := func(actor int64, path, method string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/api/v1/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "nekopass_session_http", Value: tokens[actor]})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	node := func(protocol string) NodeInput {
		return NodeInput{Name: Secret(), Enabled: true, IngressEnabled: true, AllowDirect: true, ListenHost: "127.0.0.1", PortMin: 1024, PortMax: 65535, MaxConnections: 1000, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, ProbeIntervalSeconds: 5, DiskPath: "/", TunnelListenHost: "127.0.0.1", TunnelProtocol: protocol}
	}
	create := func(input NodeInput) int64 {
		t.Helper()
		w := request(adminID, "admin/nodes", "POST", input)
		if w.Code != 200 {
			t.Fatalf("node HTTP %d", w.Code)
		}
		var v struct {
			ID int64 `json:"id"`
		}
		json.Unmarshal(w.Body.Bytes(), &v)
		return v.ID
	}
	entryInput := node("plain_tcp")
	entry := create(entryInput)
	settings := DefaultTunnelTLS()
	settings.ServerName = "tunnel.example.test"
	settings.PublicPort = 443
	settings.DNSCredentials = map[string]string{"api_token": "fixture-dns-credential-not-forwarded"}
	exitInput := node("tls_h2")
	exitInput.TLS = &settings
	exitInput.TunnelExitEnabled = true
	exitInput.TunnelListenPort = 10443
	exitInput.TunnelPublicHost = "127.0.0.1"
	exitInput.AllowedIngressIDs = []int64{entry}
	exit := create(exitInput)
	t.Cleanup(func() {
		for _, id := range []int64{entry, exit} {
			p.Exec(ctx, "DELETE FROM grants WHERE node_id=$1", id)
			p.Exec(ctx, "DELETE FROM rule_usage WHERE node_id=$1", id)
			p.Exec(ctx, "DELETE FROM rules WHERE node_id=$1 OR egress_node_id=$1", id)
			p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
		}
	})
	testAuthorize(t, p, uid, entry)
	testAuthorize(t, p, uid, exit)
	var private, certificate, ca, status string
	if err := p.QueryRow(ctx, "SELECT tls_private_key,tls_certificate,tls_ca,tls_status FROM nodes WHERE id=$1", exit).Scan(&private, &certificate, &ca, &status); err != nil || private == "" || certificate == "" || ca != certificate || status != "ready" {
		t.Fatal("self-signed material not persisted")
	}
	w := request(uid, "rules", "POST", RuleInput{NodeID: entry, EgressNodeID: exit, Targets: []string{"127.0.0.1:12345"}, Enabled: true})
	if w.Code != 200 {
		t.Fatalf("rule HTTP %d", w.Code)
	}
	stream := &StreamServer{Server: s}
	entryReport := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 7, RequestUsers: []int64{uid}}
	out, err := stream.exchange(ctx, p, entry, entryReport)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Tls == nil || out.Rules[0].Tls.RootCa != ca || out.Rules[0].TunnelPort != 443 || out.Node.Tls.PrivateKey != "" {
		t.Fatal("ingress TLS policy wrong or private key leaked")
	}
	encoded, _ := protojson.Marshal(out)
	if strings.Contains(string(encoded), "fixture-dns-credential-not-forwarded") || strings.Contains(string(encoded), private) {
		t.Fatal("certificate/DNS private materials forwarded to ingress")
	}
	old := proto.Clone(entryReport).(*pb.AgentMessage)
	old.ProtocolVersion = 6
	if _, err = stream.exchange(ctx, p, entry, old); err == nil {
		t.Fatal("old Agent accepted TLS rules")
	}
	exitReport := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 7}
	out, err = stream.exchange(ctx, p, exit, exitReport)
	if err != nil {
		t.Fatal(err)
	}
	if out.Node.Tls.PrivateKey != private || len(out.EgressRules) != 1 || out.EgressRules[0].UserId != uid {
		t.Fatal("exit certificate or rule scope missing")
	}
	encoded, _ = protojson.Marshal(out)
	if strings.Contains(string(encoded), "fixture-dns-credential-not-forwarded") {
		t.Fatal("DNS credential leaked to exit")
	}
	for _, path := range []string{"admin/nodes", "nodes"} {
		if w = request(uid, path, "GET", nil); w.Code != 403 {
			t.Fatal("ordinary user read TLS administration")
		}
	}
	w = request(uid, "rule-nodes", "GET", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "tls_config") || strings.Contains(w.Body.String(), "private_key") {
		t.Fatal("rule selector disclosed TLS secrets")
	}
	settings.CertificateMode = "import"
	settings.Certificate = "invalid"
	settings.PrivateKey = "invalid"
	exitInput.TLS = &settings
	p.QueryRow(ctx, "SELECT token FROM nodes WHERE id=$1", exit).Scan(&exitInput.Token)
	w = request(adminID, fmt.Sprintf("admin/nodes/%d", exit), "PUT", exitInput)
	if w.Code != 400 {
		t.Fatal("invalid imported certificate accepted")
	}
	var stored string
	p.QueryRow(ctx, "SELECT tls_certificate FROM nodes WHERE id=$1", exit).Scan(&stored)
	if stored != certificate {
		t.Fatal("bad certificate replaced working material")
	}
}
