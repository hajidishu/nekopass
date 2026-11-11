package iprecovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryStore struct {
	mu    sync.Mutex
	value Durable
}

func (s *memoryStore) LoadRecovery(string) (Durable, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, nil
}
func (s *memoryStore) SaveRecovery(_ string, d Durable) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.Generation < s.value.Generation {
		return errors.New("stale")
	}
	s.value = d
	return nil
}

type fakeCloud struct {
	changes   atomic.Int32
	changed   atomic.Bool
	started   chan struct{}
	ambiguous bool
}

func (f *fakeCloud) Resolve(_ context.Context, cfg Config) (Instance, error) {
	return Instance{AccountID: cfg.AccountID, RegionName: cfg.RegionName, ID: cfg.InstanceID}, nil
}

func (f *fakeCloud) IP(context.Context, Config) (string, error) {
	if f.changed.Load() {
		return "2.2.2.2", nil
	}
	return "1.1.1.1", nil
}
func (f *fakeCloud) Change(context.Context, Config) (Task, error) {
	if f.changes.Add(1) == 1 {
		close(f.started)
	}
	if f.ambiguous {
		return Task{}, &APIError{Ambiguous: true}
	}
	return Task{Tag: "fixture-task", Status: "pending"}, nil
}
func (f *fakeCloud) Task(context.Context, Config, string) (Task, bool, error) {
	return Task{Tag: "fixture-task", Status: "pending"}, true, nil
}
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}
func startRunner(t *testing.T, r *Runner) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	t.Cleanup(func() { cancel(); await(t, done) })
	return cancel, done
}

func TestConsecutiveFailuresResetAndPendingTaskDoesNotRepeat(t *testing.T) {
	cfg := fixtureConfig()
	cfg.FailureThreshold = 3
	cfg.CooldownSeconds = 30
	store := &memoryStore{}
	cloud := &fakeCloud{started: make(chan struct{})}
	var probes atomic.Int32
	sequence := []bool{false, false, true, false, false, false}
	runner := &Runner{Config: cfg, Store: store, API: cloud, Interval: 5 * time.Millisecond, PollInterval: 5 * time.Millisecond, Probe: func(context.Context, string) (bool, error) {
		n := int(probes.Add(1)) - 1
		if n < len(sequence) {
			return sequence[n], nil
		}
		return false, nil
	}}
	startRunner(t, runner)
	await(t, cloud.started)
	if probes.Load() < 6 {
		t.Fatal("nonconsecutive failures triggered recovery")
	}
	time.Sleep(70 * time.Millisecond)
	if cloud.changes.Load() != 1 {
		t.Fatal("in-flight task submitted twice")
	}
	cloud.changed.Store(true)
	time.Sleep(40 * time.Millisecond)
	d, _ := store.LoadRecovery("")
	if d.Pending || d.NewIP != "2.2.2.2" || d.LastChangedUnix == 0 || cloud.changes.Load() != 1 {
		t.Fatal("change not confirmed or cooldown not honored", d)
	}
}
func TestRestartReconcilesUnknownRequestWithoutResubmitting(t *testing.T) {
	cfg := fixtureConfig()
	cfg.FailureThreshold = 1
	store := &memoryStore{}
	cloud := &fakeCloud{started: make(chan struct{}), ambiguous: true}
	makeRunner := func() *Runner {
		return &Runner{Config: cfg, Store: store, API: cloud, Interval: 5 * time.Millisecond, PollInterval: 5 * time.Millisecond, Probe: func(context.Context, string) (bool, error) { return false, nil }}
	}
	cancel, done := startRunner(t, makeRunner())
	await(t, cloud.started)
	cancel()
	await(t, done)
	d, _ := store.LoadRecovery("")
	if !d.Pending || d.OldIP != "1.1.1.1" {
		t.Fatal("in-flight intent not durable")
	}
	cfg.Generation++
	cfg.AuthToken = "updated-token"
	startRunner(t, makeRunner())
	time.Sleep(60 * time.Millisecond)
	if cloud.changes.Load() != 1 {
		t.Fatal("restart repeated ambiguous mutation")
	}
	cloud.changed.Store(true)
	time.Sleep(40 * time.Millisecond)
	d, _ = store.LoadRecovery("")
	if d.Pending || d.NewIP != "2.2.2.2" {
		t.Fatal("restart did not reconcile")
	}
}
func TestLocalPingErrorsNeverTriggerCloudMutation(t *testing.T) {
	cfg := fixtureConfig()
	cfg.FailureThreshold = 1
	cloud := &fakeCloud{started: make(chan struct{})}
	var count atomic.Int32
	runner := &Runner{Config: cfg, Store: &memoryStore{}, API: cloud, Interval: 5 * time.Millisecond, Probe: func(context.Context, string) (bool, error) {
		count.Add(1)
		return false, errors.New("permission denied")
	}}
	startRunner(t, runner)
	time.Sleep(50 * time.Millisecond)
	if count.Load() < 2 || cloud.changes.Load() != 0 {
		t.Fatal("local error rotated IP")
	}
}
func TestDisabledAndPendingTimeoutNeverIssueAnotherChange(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Enabled = false
	cloud := &fakeCloud{started: make(chan struct{})}
	r := &Runner{Config: cfg, Store: &memoryStore{}, API: cloud}
	r.Run(context.Background())
	if cloud.changes.Load() != 0 {
		t.Fatal("disabled recovery issued request")
	}
	cfg.Enabled = true
	cfg.FailureThreshold = 1
	store := &memoryStore{}
	r = &Runner{Config: cfg, Store: store, API: cloud, Interval: 5 * time.Millisecond, PollInterval: 5 * time.Millisecond, OperationTimeout: 40 * time.Millisecond, Probe: func(context.Context, string) (bool, error) { return false, nil }}
	startRunner(t, r)
	await(t, cloud.started)
	time.Sleep(100 * time.Millisecond)
	if cloud.changes.Load() != 1 {
		t.Fatal("timed-out task was submitted again")
	}
	d, _ := store.LoadRecovery("")
	if !d.Pending {
		t.Fatal("unknown task prematurely released")
	}
}
