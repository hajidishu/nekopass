package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func TestIndependentNodeTransportChoicesAndAgentCompatibility(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		t.Run(mode, func(t *testing.T) {
			key := Secret()
			var id int64
			if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
			base := fmt.Sprintf("admin/nodes/%d/protocols", id)
			response := f.request(f.admin, base, "GET", nil)
			securityStatus(t, response, 200)
			var details struct {
				Config NodeProtocolsInput `json:"config"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil {
				t.Fatal(err)
			}
			input := details.Config
			input.TunnelTransport, input.TunnelSecurity = tunnel.Split(mode)
			input.TunnelExitEnabled = true
			input.TunnelListenPort = 25000
			input.TunnelPublicHost = "exit.example.test"
			securityStatus(t, f.request(f.admin, base, "PUT", input), 200)
			loaded, _, err := loadNodeInput(ctx, f.p, id)
			if err != nil || loaded.TunnelProtocol != mode || loaded.TunnelTransport != input.TunnelTransport || loaded.TunnelSecurity != input.TunnelSecurity {
				t.Fatal("independent choices not saved", err)
			}
			invalid := input
			invalid.TunnelSecurity = "invalid"
			securityStatus(t, f.request(f.admin, base, "PUT", invalid), 400)
			instance := Secret()
			stream := &StreamServer{Server: New(f.p)}
			for _, version := range []int32{12, 13} {
				config, err := stream.exchange(ctx, f.p, id, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: version})
				if err != nil {
					t.Fatal(err)
				}
				enabled := int(version) >= tunnel.MinimumVersion(mode)
				if config.Node.TunnelExitEnabled != enabled {
					t.Fatal("agent capability not enforced", mode, version)
				}
			}
			// Legacy clients may still submit the old combination field on its own.
			input.TunnelTransport = ""
			input.TunnelSecurity = ""
			input.TunnelProtocol = "plain_tcp"
			securityStatus(t, f.request(f.admin, base, "PUT", input), 200)
			loaded, _, err = loadNodeInput(ctx, f.p, id)
			if err != nil || loaded.TunnelProtocol != "plain_tcp" || loaded.TunnelSecurity != "none" {
				t.Fatal("legacy payload compatibility lost", err)
			}
		})
	}
}

func TestSplitTransportTLSPreparationAndDispatch(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var id int64
			if err = tx.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,tunnel_protocol) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(Secret()), mode).Scan(&id); err != nil {
				t.Fatal(err)
			}
			cfg := DefaultTunnelTLS()
			cfg.ServerName = ""
			cfg.ClientSNI = ""
			cfg.Fingerprint = "chrome"
			input := NodeInput{TunnelProtocol: mode, TunnelExitEnabled: true, TunnelPublicHost: "exit.example.test", TLS: &cfg}
			if err = prepareNodeTLS(ctx, tx, id, &input); err != nil {
				t.Fatal(err)
			}
			var certificate, private string
			if err = tx.QueryRow(ctx, "SELECT tls_certificate,tls_private_key FROM nodes WHERE id=$1", id).Scan(&certificate, &private); err != nil {
				t.Fatal(err)
			}
			if tunnel.TLS(mode) != (certificate != "" && private != "") {
				t.Fatal("certificate issuance does not follow security option")
			}
			out := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: mode}, Rules: []*pb.Rule{{Id: 1, EgressNodeId: id, TunnelProtocol: mode}}}
			if err = appendTLSControl(ctx, tx, id, out); err != nil {
				t.Fatal(err)
			}
			if !tunnel.TLS(mode) {
				if out.Node.Tls.PrivateKey != "" || out.Node.Tls.Certificate != "" {
					t.Fatal("unencrypted mode received TLS secrets")
				}
				if out.Rules[0].Tls != nil && (out.Rules[0].Tls.RootCa != "" || out.Rules[0].Tls.Fingerprint != "off" || out.Rules[0].Tls.ServerName != "") {
					t.Fatal("unencrypted mode received active TLS options")
				}
			}
			data, _ := json.Marshal(out.Rules)
			if private != "" && strings.Contains(string(data), private) {
				t.Fatal("private key sent to entry")
			}
		})
	}
}
