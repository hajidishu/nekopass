package agent

import (
	"context"
	"encoding/json"
	"github.com/nekopass/nekopass/internal/iprecovery"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
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

func TestRecoveryBindingSwitchKeepsPendingAndCooldownAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := iprecovery.DefaultConfig()
	cfg.InstanceID = "i-fixture"
	cfg.AccountID = "fixture-account"
	cfg.RegionName = "ap-southeast-1"
	fixed := cfg.ResourceKey()
	cfg.BindingMode = "profile"
	cfg.ProfileID = "fixture-profile"
	profile := cfg.ResourceKey()
	initial := iprecovery.Durable{Generation: 1, Pending: true, TaskTag: "fixture-task", LastAttemptUnix: 1000, OldIP: "1.1.1.1", Instance: iprecovery.Instance{Type: "ec2", ID: "i-fixture", AccountID: "fixture-account", RegionName: "ap-southeast-1"}}
	if err = state.SaveRecovery(fixed, initial); err != nil {
		t.Fatal(err)
	}
	state.Close()
	state, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	loaded, err := state.LoadRecovery(profile)
	if err != nil || loaded != initial {
		t.Fatal("instance to profile switch lost pending task", loaded, err)
	}
	loaded.Generation = 2
	if err = state.SaveRecovery(profile, loaded); err != nil {
		t.Fatal(err)
	}
	back, err := state.LoadRecovery(fixed)
	if err != nil || back != loaded {
		t.Fatal("profile to instance switch lost latest task", back, err)
	}
	if state.SaveRecovery(fixed, initial) == nil {
		t.Fatal("older binding overwrote node-wide operation")
	}
	loaded.Generation = 3
	loaded.Pending = false
	loaded.TaskTag = ""
	loaded.LastChangedUnix = 1050
	if err = state.SaveRecovery(profile, loaded); err != nil {
		t.Fatal(err)
	}
	back, err = state.LoadRecovery(fixed)
	if err != nil || back != loaded {
		t.Fatal("mode switch resurrected completed task or lost cooldown", back, err)
	}
}

func TestLegacyPendingRecoverySwitchFailsClosedWithoutTarget(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	legacy := iprecovery.Durable{Generation: 2, Pending: true, TaskTag: "fixture-old-task", LastAttemptUnix: 1000}
	if err = state.db.Update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(legacy)
		return tx.Bucket([]byte("meta")).Put([]byte("ip_recovery_old-key"), data)
	}); err != nil {
		t.Fatal(err)
	}
	same, err := state.LoadRecovery("old-key")
	if err != nil || same.LegacyTargetUnknown {
		t.Fatal("same legacy binding became unidentified", same, err)
	}
	other, err := state.LoadRecovery("new-profile-key")
	if err != nil || !other.Pending || !other.LegacyTargetUnknown {
		t.Fatal("unknown legacy operation can bind new target", other, err)
	}
}

type delayedRecoveryCloud struct {
	entered chan struct{}
	release chan struct{}
}

func (f *delayedRecoveryCloud) Resolve(_ context.Context, cfg iprecovery.Config) (iprecovery.Instance, error) {
	return iprecovery.Instance{ID: cfg.InstanceID, RegionName: cfg.RegionName, AccountID: cfg.AccountID}, nil
}
func (f *delayedRecoveryCloud) IP(context.Context, iprecovery.Config) (string, error) {
	return "1.1.1.1", nil
}
func (f *delayedRecoveryCloud) Change(ctx context.Context, _ iprecovery.Config) (iprecovery.Task, error) {
	close(f.entered)
	<-ctx.Done()
	<-f.release
	return iprecovery.Task{}, &iprecovery.APIError{Ambiguous: true}
}
func (f *delayedRecoveryCloud) Task(context.Context, iprecovery.Config, string) (iprecovery.Task, bool, error) {
	return iprecovery.Task{Tag: "fixture-task", Status: "pending"}, true, nil
}

func TestRecoveryReconfigurationWaitsForOldOperationState(t *testing.T) {
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
	cloud := &delayedRecoveryCloud{entered: make(chan struct{}), release: make(chan struct{})}
	var released atomic.Bool
	defer func() {
		if !released.Swap(true) {
			close(cloud.release)
		}
	}()
	engine.ipRecoveryAPI = func() iprecovery.API { return cloud }
	var probes atomic.Int32
	engine.ipRecoveryProbe = func(context.Context, string) (bool, error) { probes.Add(1); return false, nil }
	message := &pb.ControlMessage{Revision: 1, Node: defaultNodeConfig()}
	message.Node.IpRecovery = &pb.IPRecoveryConfig{Enabled: true, Generation: 1, TargetIp: "1.1.1.1", FailureThreshold: 1, CooldownSeconds: 300, InstanceType: "ec2", AuthToken: "fixture-token", AccountId: "fixture-account", RegionName: "ap-southeast-1", InstanceId: "i-fixture"}
	if err = engine.Apply(message); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cloud.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("cloud change did not start")
	}
	message.Revision = 2
	message.Node.IpRecovery.Generation = 2
	if err = engine.Apply(message); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if probes.Load() != 1 {
		t.Fatal("new runner started before the previous operation drained")
	}
	released.Store(true)
	close(cloud.release)
	deadline := time.Now().Add(3 * time.Second)
	for probes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if probes.Load() != 2 {
		t.Fatal("replacement runner did not start")
	}
	cfg := iprecovery.DefaultConfig()
	cfg.InstanceType = "ec2"
	cfg.AccountID = "fixture-account"
	cfg.RegionName = "ap-southeast-1"
	cfg.InstanceID = "i-fixture"
	saved, err := state.LoadRecovery(cfg.ResourceKey())
	if err != nil || saved.Generation != 2 || !saved.Pending || saved.Instance.ID != "i-fixture" {
		t.Fatal("reconfiguration lost pending operation", saved, err)
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
