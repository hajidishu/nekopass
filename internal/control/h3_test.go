package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nekopass/nekopass/internal/tlsinbound"
)

func TestH3MandatoryTLSAndPortReservations(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, q := range []string{"DELETE FROM grants WHERE node_id=$1", "DELETE FROM rule_usage WHERE node_id=$1", "DELETE FROM rules WHERE node_id=$1", "DELETE FROM nodes WHERE id=$1"} {
			f.p.Exec(ctx, q, node)
		}
	})
	testAuthorize(t, f.p, f.user, node)
	endpoint := fmt.Sprintf("admin/nodes/%d/protocols", node)
	response := f.request(f.admin, endpoint, "GET", nil)
	securityStatus(t, response, 200)
	var details struct {
		Config NodeProtocolsInput `json:"config"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil {
		t.Fatal(err)
	}
	in := details.Config
	in.TunnelTransport = "h3"
	in.TunnelSecurity = "tls"
	in.TunnelExitEnabled = true
	in.TunnelListenPort = 25000
	in.TunnelPublicHost = "exit.example.test"
	securityStatus(t, f.request(f.admin, endpoint, "PUT", in), 200)
	for _, security := range []string{"none", "random"} {
		bad := in
		bad.TunnelSecurity = security
		securityStatus(t, f.request(f.admin, endpoint, "PUT", bad), 400)
	}
	// HTTP/3 and the companion HTTPS website own both socket namespaces.
	for _, network := range []string{"tcp", "udp"} {
		rule := RuleInput{NodeID: node, Name: "port-reservation", Protocol: network, ListenPort: 25000, Targets: []string{"example.com:80"}, Enabled: true}
		securityStatus(t, f.request(f.user, "rules", "POST", rule), 400)
	}
	shared := tlsinbound.DefaultConfig()
	shared.Port = 25000
	shared.Name = "collision"
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/nodes/%d/tls-inbounds", node), "PUT", map[string]any{"config": shared}), 409)
	// Automatic allocation must skip the reserved port for both TCP and UDP.
	if _, err := f.p.Exec(ctx, "UPDATE nodes SET port_min=25000,port_max=25001 WHERE id=$1", node); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		rule := RuleInput{NodeID: node, Protocol: network, Targets: []string{"example.com:80"}, Enabled: true}
		w := f.request(f.user, "rules", "POST", rule)
		if w.Code != 200 {
			t.Fatalf("allocator failed: %d %s", w.Code, w.Body.String())
		}
		var result struct{ ID int64 }
		json.Unmarshal(w.Body.Bytes(), &result)
		var port int
		if err := f.p.QueryRow(ctx, "SELECT listen_port FROM rules WHERE id=$1", result.ID).Scan(&port); err != nil || port != 25001 {
			t.Fatal("allocator used reserved port", port, err)
		}
	}
	// Moving the tunnel onto either existing rule must also fail.
	in.TunnelListenPort = 25001
	securityStatus(t, f.request(f.admin, endpoint, "PUT", in), 409)
	in.TunnelListenPort = 25000
	in.TLS.CertificateMode = "acme_http"
	in.TLS.ACMEEmail = "test@example.com"
	in.TLS.HTTPChallengePort = 25000
	securityStatus(t, f.request(f.admin, endpoint, "PUT", in), 400)
}
