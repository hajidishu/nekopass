package control

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nekopass/nekopass/internal/iprecovery"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"strings"
	"testing"
)

func TestIPRecoveryAdminScopeAndPerNodeControl(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node, other int64
	for _, target := range []*int64{&node, &other} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", "fixture-recovery-"+Secret(), Hash(Secret())).Scan(target); err != nil {
			t.Fatal(err)
		}
		id := *target
		t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
	}
	path := fmt.Sprintf("admin/nodes/%d/ip-recovery", node)
	cfg := iprecovery.DefaultConfig()
	cfg.Enabled = true
	cfg.TargetIP = "1.1.1.1"
	cfg.AuthToken = "fixture-private-cloud-token"
	cfg.ShareGroupToken = "fixture-share-token"
	cfg.AccountID = "fixture-account"
	cfg.RegionName = "ap-southeast-1"
	cfg.InstanceID = "i-fixture"
	securityStatus(t, f.request(0, path, "GET", nil), 401)
	for _, method := range []string{"GET", "PUT"} {
		securityStatus(t, f.request(f.user, path, method, cfg), 403)
	}
	securityStatus(t, f.request(f.user, path+"/reset", "POST", map[string]any{}), 403)
	securityStatus(t, f.request(f.admin, path, "PUT", cfg), 200)
	w := f.request(f.admin, path, "GET", nil)
	securityStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), cfg.AuthToken) {
		t.Fatal("administrator cannot view configured credentials")
	}
	securityStatus(t, f.request(f.admin, fmt.Sprintf("admin/nodes/%d/ip-recovery", other), "PUT", cfg), 409)
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	first := &pb.ControlMessage{Node: &pb.NodeConfig{}}
	second := &pb.ControlMessage{Node: &pb.NodeConfig{}}
	if err = appendIPRecoveryControl(ctx, tx, node, first); err != nil {
		t.Fatal(err)
	}
	if err = appendIPRecoveryControl(ctx, tx, other, second); err != nil {
		t.Fatal(err)
	}
	if first.Node.IpRecovery == nil || first.Node.IpRecovery.AuthToken != cfg.AuthToken || second.Node.IpRecovery != nil {
		t.Fatal("node scope incorrect")
	}
	report := &pb.IPRecoveryStatus{Generation: first.Node.IpRecovery.Generation, State: "cooldown", CheckedUnix: 100, LastAttemptUnix: 90, CooldownUntilUnix: 390, OldIp: "1.1.1.1", NewIp: "2.2.2.2", Error: cfg.AuthToken + " " + cfg.ShareGroupToken}
	if err = acceptIPRecoveryReport(ctx, tx, node, report); err != nil {
		t.Fatal(err)
	}
	var status []byte
	if err = tx.QueryRow(ctx, "SELECT status FROM node_ip_recovery WHERE node_id=$1", node).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(status), cfg.AuthToken) || strings.Contains(string(status), cfg.ShareGroupToken) {
		t.Fatal("status exposed cloud credentials")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.admin, path+"/reset", "POST", map[string]any{}), 200)
	var reset, generation int64
	if err = f.p.QueryRow(ctx, "SELECT reset_sequence,generation FROM node_ip_recovery WHERE node_id=$1", node).Scan(&reset, &generation); err != nil || reset != 1 || generation != 2 {
		t.Fatal("reset not delivered", err)
	}
	cfg.Enabled = false
	securityStatus(t, f.request(f.admin, path, "PUT", cfg), 200)
	w = f.request(f.admin, path, "GET", nil)
	securityStatus(t, w, 200)
	var details struct{ Config iprecovery.Config }
	if err = json.Unmarshal(w.Body.Bytes(), &details); err != nil || details.Config.Enabled || details.Config.AuthToken != cfg.AuthToken {
		t.Fatal("disable discarded credentials", err)
	}
	for _, api := range []string{"node-status", "rule-nodes", "site", "registration/config"} {
		response := f.request(f.user, api, "GET", nil)
		if strings.Contains(response.Body.String(), cfg.AuthToken) || strings.Contains(response.Body.String(), cfg.ShareGroupToken) {
			t.Fatal("user endpoint exposed credentials", api)
		}
	}
	if route, ok := resolvePage(fmt.Sprintf("/admin/nodes/%d/ip-recovery", node)); !ok || !route.admin || route.nodeID != node {
		t.Fatal("page scope invalid")
	}
	if safeNext(fmt.Sprintf("/admin/nodes/%d/ip-recovery", node), false) != "/" {
		t.Fatal("user return exposed admin page")
	}
}

func TestIPRecoveryProfilesUniqueAndFailClosedOnOldAgents(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var first, second int64
	for _, node := range []*int64{&first, &second} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,protocol_version) VALUES($1,$2,35) RETURNING id", "fixture-profile-"+Secret(), Hash(Secret())).Scan(node); err != nil {
			t.Fatal(err)
		}
		id := *node
		t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
	}
	cfg := iprecovery.DefaultConfig()
	cfg.Enabled, cfg.BindingMode, cfg.ProfileID = true, "profile", "fixture-profile-one"
	cfg.TargetIP, cfg.ShareGroupToken = "1.1.1.1", "fixture-share-token"
	put := func(node int64) int {
		return f.request(f.admin, fmt.Sprintf("admin/nodes/%d/ip-recovery", node), "PUT", cfg).Code
	}
	if got := put(first); got != 200 {
		t.Fatal("profile-only config rejected", got)
	}
	cfg.AccountID, cfg.RegionName, cfg.InstanceID = "stale-account", "ap-southeast-1", "i-stale"
	if got := put(second); got != 409 {
		t.Fatal("duplicate profile allowed with stale fixed target", got)
	}
	cfg.ProfileID = "fixture-profile-two"
	if got := put(second); got != 200 {
		t.Fatal("different profiles conflict", got)
	}
	for _, version := range []int32{35, pb.IPRecoveryProfileVersion} {
		if _, err := f.p.Exec(ctx, "UPDATE nodes SET protocol_version=$2 WHERE id=$1", second, version); err != nil {
			t.Fatal(err)
		}
		tx, err := f.p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := &pb.ControlMessage{Node: &pb.NodeConfig{}}
		err = appendIPRecoveryControl(ctx, tx, second, out)
		tx.Rollback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if out.Node.IpRecovery == nil || out.Node.IpRecovery.ProfileId != cfg.ProfileID || out.Node.IpRecovery.BindingMode != "profile" || out.Node.IpRecovery.Enabled != (version >= pb.IPRecoveryProfileVersion) {
			t.Fatal("profile capability guard incorrect", out.Node.IpRecovery)
		}
	}
	cfg.BindingMode = "instance"
	if got := put(second); got != 200 {
		t.Fatal("could not switch to fixed instance", got)
	}
	cfg.ProfileID = "fixture-unused-id"
	if got := put(first); got != 409 {
		t.Fatal("fixed duplicate instance not rejected", got)
	}
	cfg.InstanceID = "i-other"
	if got := put(first); got != 200 {
		t.Fatal("different fixed instance rejected", got)
	}
}
