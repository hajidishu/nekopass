package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

func TestRandomConfigAdministrationAndDispatch(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var entry, exit int64
	for _, id := range []*int64{&entry, &exit} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{entry, exit}) })
	base := fmt.Sprintf("admin/nodes/%d/protocols", exit)
	w := f.request(f.admin, base, "GET", nil)
	securityStatus(t, w, 200)
	var details struct {
		Config NodeProtocolsInput `json:"config"`
	}
	json.Unmarshal(w.Body.Bytes(), &details)
	cfg := details.Config
	cfg.TunnelTransport = "raw_tcp"
	cfg.TunnelSecurity = "random"
	cfg.TunnelExitEnabled = true
	cfg.TunnelListenPort = 25000
	cfg.TunnelPublicHost = "exit.example.test"
	cfg.AllowedIngressIDs = []int64{entry}
	cfg.Random = &TunnelRandomConfig{Cipher: tunnelcrypto.AES256GCM}
	securityStatus(t, f.request(f.user, base, "PUT", cfg), 403)
	w = f.request(f.admin, base, "PUT", cfg)
	securityStatus(t, w, 200)
	var response struct{ Random TunnelRandomConfig }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelcrypto.DecodeKey(response.Random.Key); err != nil {
		t.Fatal("blank key not generated", err)
	}
	loaded, _, err := loadNodeInput(ctx, f.p, exit)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Random.Key != response.Random.Key || loaded.Random.Cipher != tunnelcrypto.AES256GCM {
		t.Fatal("generated config not returned/stored")
	}
	cfg.Random = loaded.Random
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 200)
	saved, _, _ := loadNodeInput(ctx, f.p, exit)
	if saved.Random.Key != loaded.Random.Key {
		t.Fatal("saving changed populated key")
	}
	cfg.Random = &TunnelRandomConfig{Cipher: tunnelcrypto.AES256GCM, Key: "invalid"}
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 400)
	cfg.Random = &TunnelRandomConfig{Cipher: "unsupported", Key: loaded.Random.Key}
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 400)
	cfg.Random = loaded.Random
	cfg.TunnelTransport = "raw_udp"
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 200)
	cfg.TunnelTransport = "h2"
	securityStatus(t, f.request(f.admin, base, "PUT", cfg), 200)
	// Key and algorithm belong to the exit, including group member drafts;
	// the ingress's own security settings must not replace them.
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	out := &pb.ControlMessage{Node: &pb.NodeConfig{TunnelProtocol: "plain_tcp"}, Rules: []*pb.Rule{{Enabled: true, EgressNodeId: exit, TunnelProtocol: "random_h2"}, {Enabled: true, EgressNodeId: exit, TunnelProtocol: "random_h2"}, {EgressNodeId: exit, TunnelProtocol: "plain_h2"}}}
	if err = appendRandomControl(ctx, tx, entry, out); err != nil {
		t.Fatal(err)
	}
	if out.Node.Random != nil || out.Rules[2].Random != nil {
		t.Fatal("unused secrets sent")
	}
	for _, r := range out.Rules[:2] {
		if r.Random.GetKey() != loaded.Random.Key || r.Random.Cipher != tunnelcrypto.AES256GCM {
			t.Fatal("exit key not dispatched")
		}
	}
	group := &pb.Rule{Id: 1}
	finishGroupDrafts(out, []groupRuleDraft{{rule: group, peer: out.Rules[0], weight: 1}}, 26, 0)
	if len(group.EgressPeers) != 1 || group.EgressPeers[0].Random.GetKey() != loaded.Random.Key {
		t.Fatal("group peer lost encryption settings")
	}
	if strings.Contains(string(f.request(f.user, base, "GET", nil).Body.Bytes()), loaded.Random.Key) {
		t.Fatal("user obtained exit encryption key")
	}
}
