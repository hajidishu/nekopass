package control

import (
	"context"
	"encoding/json"
	"fmt"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNodeUpdateAuthorizationAndGenerationIsolation(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	f.s.releaseChecked = time.Now()
	f.s.releaseInfo = release.Info{Version: "v0.11.0"}
	var node, other int64
	for _, id := range []*int64{&node, &other} {
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,protocol_version,agent_version,update_supported,last_seen) VALUES($1,$2,9,'v0.10.0',true,now()) RETURNING id", Secret(), Secret()).Scan(id); err != nil {
			t.Fatal(err)
		}
		value := *id
		t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", value) })
	}
	path := fmt.Sprintf("admin/nodes/%d/update", node)
	securityStatus(t, f.request(0, path, "POST", map[string]string{"version": "v0.11.0"}), 401)
	securityStatus(t, f.request(f.user, path, "POST", map[string]string{"version": "v0.11.0"}), 403)
	securityStatus(t, f.request(f.user, "admin/updates", "GET", nil), 403)
	securityStatus(t, f.request(f.admin, "admin/updates", "GET", nil), 200)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "../oops"}), 400)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.12.0"}), 409)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.request(f.admin, path, "POST", map[string]string{"version": "v0.11.0"})
			if w.Code == 200 {
				successes.Add(1)
			} else if w.Code != 409 {
				t.Errorf("unexpected update status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent update requests created multiple tasks")
	}
	stream := &StreamServer{Server: f.s}
	instance := Secret()
	out, err := stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: 9, AgentVersion: "v0.10.0", UpdateSupported: true})
	if err != nil || out.Update == nil || out.Update.Generation != 1 {
		t.Fatalf("task not delivered: %v", err)
	}
	foreign, err := stream.exchange(ctx, f.p, other, &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 9, AgentVersion: "v0.10.0", UpdateSupported: true, UpdateStatus: &pb.UpdateStatus{Generation: 1, Version: "v0.11.0", State: "completed"}})
	if err != nil || foreign.Update != nil {
		t.Fatal("update crossed node boundary")
	}
	readState := func() string {
		var state string
		if err := f.p.QueryRow(ctx, "SELECT state FROM node_updates WHERE node_id=$1", node).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	if readState() != "queued" {
		t.Fatal("other node changed update task")
	}
	// An old binary cannot claim that its update completed.
	_, err = stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: 9, AgentVersion: "v0.10.0", UpdateSupported: true, UpdateStatus: &pb.UpdateStatus{Generation: 1, Version: "v0.11.0", State: "completed"}})
	if err != nil || readState() != "failed" {
		t.Fatal("incorrect completion accepted")
	}
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.11.0"}), 200)
	_, err = stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: 9, AgentVersion: "v0.10.0", UpdateSupported: true, UpdateStatus: &pb.UpdateStatus{Generation: 1, Version: "v0.11.0", State: "failed"}})
	if err != nil || readState() != "queued" {
		t.Fatal("stale generation overwrote retry")
	}
	_, err = stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: 9, AgentVersion: "v0.11.0", UpdateSupported: true, UpdateStatus: &pb.UpdateStatus{Generation: 2, Version: "v0.11.0", State: "completed"}})
	if err != nil || readState() != "completed" {
		t.Fatal("valid completion rejected")
	}
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.11.0"}), 409)
}

func TestOfflineAndLegacyNodesCannotReceiveUpdate(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	f.s.releaseChecked = time.Now()
	f.s.releaseInfo = release.Info{Version: "v0.11.0"}
	var node int64
	f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node)
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	path := fmt.Sprintf("admin/nodes/%d/update", node)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.11.0"}), 409)
	f.p.Exec(ctx, "UPDATE nodes SET last_seen=now(),protocol_version=8 WHERE id=$1", node)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.11.0"}), 409)
}

func TestOfflineUpdateTimeoutIsUnconfirmedAndAcceptsLateCompletion(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,protocol_version,agent_version,update_supported) VALUES($1,$2,12,'v0.14.0',true) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	if _, err := f.p.Exec(ctx, "INSERT INTO node_updates(node_id,version,state,requested_at) VALUES($1,'v0.14.1','running',now()-interval '30 minutes')", node); err != nil {
		t.Fatal(err)
	}
	response := f.request(f.admin, "admin/nodes", "GET", nil)
	securityStatus(t, response, 200)
	var nodes []struct {
		ID     int64 `json:"id"`
		Update struct {
			State string `json:"state"`
		} `json:"update_status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range nodes {
		if n.ID == node {
			found = true
			if n.Update.State != "unconfirmed" {
				t.Fatal("expired update still shown as running")
			}
		}
	}
	if !found {
		t.Fatal("node missing from response")
	}
	stream := &StreamServer{Server: f.s}
	_, err := stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 12, AgentVersion: "v0.14.1", UpdateSupported: true, UpdateStatus: &pb.UpdateStatus{Generation: 1, Version: "v0.14.1", State: "completed"}})
	if err != nil {
		t.Fatal(err)
	}
	var state string
	if err := f.p.QueryRow(ctx, "SELECT state FROM node_updates WHERE node_id=$1", node).Scan(&state); err != nil || state != "completed" {
		t.Fatal("late completion was discarded", state, err)
	}
}
