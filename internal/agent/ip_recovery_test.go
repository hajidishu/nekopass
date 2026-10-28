package agent

import (
	"context"
	"github.com/nekopass/nekopass/internal/iprecovery"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"path/filepath"
	"testing"
	"time"
)

func TestIPRecoveryStateSurvivesRestartAndRejectsStaleWorker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	value := iprecovery.Durable{Generation: 3, ResetSequence: 1, LastAttemptUnix: 123, Pending: true, TaskTag: "task", OldIP: "1.1.1.1"}
	if err = state.SaveRecovery("key", value); err != nil {
		t.Fatal(err)
	}
	state.Close()
	state, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	saved, err := state.LoadRecovery("key")
	if err != nil || saved != value {
		t.Fatal("pending operation lost", err)
	}
	newer := value
	newer.Generation++
	if err = state.SaveRecovery("key", newer); err != nil {
		t.Fatal(err)
	}
	if state.SaveRecovery("key", value) == nil {
		t.Fatal("stale worker replaced current intent")
	}
	saved, _ = state.LoadRecovery("key")
	if saved.Generation != newer.Generation || !saved.Pending {
		t.Fatal("state not protected")
	}
}
func TestAgentRecoveryDisableCancelsBlockedPing(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := NewEngine(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	entered := make(chan struct{})
	stopped := make(chan struct{})
	engine.ipRecoveryProbe = func(ctx context.Context, _ string) (bool, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return false, ctx.Err()
	}
	message := &pb.ControlMessage{Revision: 1, Node: defaultNodeConfig()}
	message.Node.IpRecovery = &pb.IPRecoveryConfig{Enabled: true, Generation: 1, TargetIp: "1.1.1.1", FailureThreshold: 3, CooldownSeconds: 300, InstanceType: "ec2", AuthToken: "fixture-token", AccountId: "fixture-account", RegionName: "ap-southeast-1", InstanceId: "i-fixture"}
	if err = engine.Apply(message); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("ping not started")
	}
	message.Revision = 2
	message.Node.IpRecovery.Enabled = false
	message.Node.IpRecovery.Generation = 2
	if err = engine.Apply(message); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("disable failed to stop ping")
	}
	report, err := engine.Report()
	if err != nil || report.IpRecoveryStatus == nil || report.IpRecoveryStatus.State != "disabled" || report.ProtocolVersion != pb.CurrentVersion {
		t.Fatal("disabled state not reported", err)
	}
}
