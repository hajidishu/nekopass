package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestClientTCPBrutalAdminSettingsAndOmissionPreserve(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var id int64
	key := Secret()
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(key), key).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id)
	path := fmt.Sprintf("admin/nodes/%d", id)
	node, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	if node.ClientTCPBrutalEnabled == nil || *node.ClientTCPBrutalEnabled {
		t.Fatal("existing nodes were enabled by default")
	}
	on := true
	node.ClientTCPBrutalEnabled = &on
	securityStatus(t, f.request(f.user, path, "PUT", node), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", node), 400)
	up := int64(20)
	node.BandwidthUpMbps = &up
	securityStatus(t, f.request(f.admin, path, "PUT", node), 200)
	loaded, _, err := loadNodeInput(ctx, f.p, id)
	if err != nil || !*loaded.ClientTCPBrutalEnabled || *loaded.BandwidthDownMbps != 0 || *loaded.BrutalEnabled {
		t.Fatal("TCP client feature incorrectly required or enabled tunnel congestion", err)
	}
	data, _ := json.Marshal(loaded)
	var basic NodeBasicInput
	var protocols NodeProtocolsInput
	json.Unmarshal(data, &basic)
	json.Unmarshal(data, &protocols)
	loaded.ClientTCPBrutalEnabled = nil
	basic.ClientTCPBrutalEnabled = nil
	protocols.ClientTCPBrutalEnabled = nil
	for _, request := range []struct {
		path string
		body any
	}{{path, loaded}, {path + "/basic", basic}, {path + "/protocols", protocols}} {
		securityStatus(t, f.request(f.admin, request.path, "PUT", request.body), 200)
		current, _, err := loadNodeInput(ctx, f.p, id)
		if err != nil || !*current.ClientTCPBrutalEnabled {
			t.Fatal("an older client erased the TCP setting", err)
		}
	}
	off := false
	loaded.ClientTCPBrutalEnabled = &off
	securityStatus(t, f.request(f.admin, path, "PUT", loaded), 200)
	loaded, _, err = loadNodeInput(ctx, f.p, id)
	if err != nil || *loaded.ClientTCPBrutalEnabled {
		t.Fatal("cannot turn off client TCP Brutal", err)
	}
}

func TestClientTCPBrutalControlAndPrivacy(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var id int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,client_tcp_brutal_enabled,bandwidth_up_mbps) VALUES($1,$2,true,20) RETURNING id", Secret(), Hash(Secret())).Scan(&id); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, query := range []string{"DELETE FROM grants WHERE node_id=$1", "DELETE FROM rule_usage WHERE node_id=$1", "DELETE FROM nodes WHERE id=$1"} {
			if _, err := f.p.Exec(ctx, query, id); err != nil {
				t.Error(err)
			}
		}
	}()
	testAuthorize(t, f.p, f.user, id)
	stream := &StreamServer{Server: f.s}
	report := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 33}
	out, err := stream.exchange(ctx, f.p, id, report)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Node.ClientTcpBrutalEnabled || out.Node.BandwidthUpBps != 2500000 || out.Node.BrutalEnabled {
		t.Fatal("wrong direction or parameter units", out.Node)
	}
	response := f.request(f.user, "rule-nodes", "GET", nil)
	securityStatus(t, response, 200)
	if strings.Contains(response.Body.String(), "client_tcp_brutal_enabled") {
		t.Fatal("administrator configuration leaked to tenant")
	}
}
