package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestUDPPortReservationAndTenantIsolation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	testAuthorize(t, f.p, f.user, node)
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	makeRule := func(network string, port int) RuleInput {
		return RuleInput{NodeID: node, ListenPort: port, Targets: []string{"8.8.8.8:53"}, Enabled: true, Protocol: network}
	}
	udp := makeRule("udp", 24001)
	response := f.request(f.user, "rules", "POST", udp)
	securityStatus(t, response, 200)
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.user, "rules", "POST", makeRule("tcp", 24001)), 200)
	if w := f.request(f.user, "rules", "POST", makeRule("udp", 24001)); w.Code == 200 {
		t.Fatal("duplicate UDP binding accepted")
	}
	if w := f.request(f.user, "rules", "POST", makeRule("tcp_udp", 24001)); w.Code == 200 {
		t.Fatal("combined rule bypassed conflict")
	}
	securityStatus(t, f.request(f.user, "rules", "POST", makeRule("tcp_udp", 24002)), 200)
	udp.Protocol = "tcp"
	if w := f.request(f.user, fmt.Sprintf("rules/%d", created.ID), "PUT", udp); w.Code == 200 {
		t.Fatal("protocol change bypassed occupied port")
	}
	var network string
	var count int
	if err := f.p.QueryRow(ctx, "SELECT protocol FROM rules WHERE id=$1", created.ID).Scan(&network); err != nil || network != "udp" {
		t.Fatal("failed edit lost original UDP reservation", err)
	}
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM rule_ports WHERE node_id=$1", node).Scan(&count); err != nil || count != 4 {
		t.Fatal("protocol reservation not atomic", err, count)
	}
	securityStatus(t, f.request(f.other, fmt.Sprintf("rules/%d", created.ID), "PUT", makeRule("udp", 24003)), 400)
	proxy := makeRule("udp", 24003)
	proxy.ProxySend = "v1"
	securityStatus(t, f.request(f.user, "rules", "POST", proxy), 400)
}
