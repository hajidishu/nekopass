package iprecovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func profileConfig() Config {
	c := fixtureConfig()
	c.BindingMode, c.ProfileID = "profile", "fixture-profile"
	c.AuthToken, c.ShareGroupToken = "", "fixture-share-token"
	c.AccountID, c.RegionName, c.InstanceID = "", "", ""
	return c
}

func TestProfileConfigurationAndDurableIdentity(t *testing.T) {
	c := profileConfig()
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	key := c.ResourceKey()
	c.AccountID, c.RegionName, c.InstanceID = "new-account", "new-region", "i-replaced"
	c.ShareGroupToken, c.Generation = "fixture-rotated-share", 4
	if c.ResourceKey() != key {
		t.Fatal("profile identity changed with resolved instance or credentials")
	}
	c.ProfileID = "fixture-other-profile"
	if c.ResourceKey() == key {
		t.Fatal("different profiles shared operation state")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.BindingMode = "unknown" },
		func(c *Config) { c.ProfileID = "" },
		func(c *Config) { c.ProfileID = "../other" },
		func(c *Config) { c.ProfileID = "bad\nheader" },
		func(c *Config) { c.ShareGroupToken = "" },
	} {
		v := profileConfig()
		mutate(&v)
		if v.Normalize() == nil {
			t.Fatal("invalid profile configuration accepted")
		}
	}
	legacy := fixtureConfig()
	legacy.BindingMode = ""
	before := legacy.ResourceKey()
	if legacy.Normalize() != nil || legacy.BindingMode != "instance" || legacy.ResourceKey() != before {
		t.Fatal("legacy fixed-instance identity changed")
	}
}

func TestProfileResolutionUsesSharingCredentialsAndAuthoritativeTarget(t *testing.T) {
	for _, kind := range []string{"ec2", "lightsail"} {
		for _, camel := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/camel=%v", kind, camel), func(t *testing.T) {
				cfg := profileConfig()
				cfg.InstanceType = kind
				cfg.AccountID, cfg.RegionName, cfg.InstanceID = "old-account", "old-region", "i-old"
				var patches int
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("X-Share-Group-Token") != cfg.ShareGroupToken || r.Header.Get("X-Auth-Token") != "" {
						t.Error("sharing credential missing or replaced")
					}
					if strings.Contains(r.URL.Path, "-instance-profiles/") {
						if r.Header.Get("X-Account-Id") != "" || r.Header.Get("X-Region-Name") != "" || r.URL.Query().Get("r") == "" {
							t.Error("stale identity or cached profile lookup")
						}
						field := "instance_id"
						if kind == "lightsail" {
							field = "instance_name"
						}
						account, region := "account_id", "region_name"
						if camel {
							field = map[string]string{"ec2": "instanceId", "lightsail": "instanceName"}[kind]
							account, region = "accountId", "regionName"
						}
						json.NewEncoder(w).Encode(map[string]any{"id": cfg.ProfileID, field: "i-new", account: "new-account", region: "ap-southeast-1"})
						return
					}
					if r.URL.Path != "/"+kind+"-instances/i-new/ip-address" || r.Header.Get("X-Account-Id") != "new-account" || r.Header.Get("X-Region-Name") != "ap-southeast-1" {
						t.Error("mutation did not use newly resolved instance")
					}
					patches++
					fmt.Fprint(w, `{"tag":"fixture-task"}`)
				}))
				defer server.Close()
				client := NewClient().(*Client)
				defer client.Close()
				client.baseURL = server.URL
				instance, err := client.Resolve(context.Background(), cfg)
				if err != nil || instance.ID != "i-new" || instance.Type != kind {
					t.Fatal(instance, err)
				}
				if _, err = client.Change(context.Background(), cfg.ForInstance(instance)); err != nil || patches != 1 {
					t.Fatal(err, patches)
				}
			})
		}
	}
}

func TestProfileRejectsMissingAndUnsafeTargetsWithoutCredentialErrors(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"instance_id":"i-new"}`, `{"instance_id":"../delete","region_name":"ap-southeast-1"}`,
		`{"instance_id":"i-new","region_name":"bad\nheader"}`,
		`{"id":"another-profile","instance_id":"i-new","region_name":"ap-southeast-1"}`,
		`{"account_invalid":true,"instance_id":"i-new","region_name":"ap-southeast-1"}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			client := NewClient().(*Client)
			defer client.Close()
			client.baseURL = server.URL
			cfg := profileConfig()
			_, err := client.Resolve(context.Background(), cfg)
			if err == nil || strings.Contains(err.Error(), cfg.ShareGroupToken) {
				t.Fatal("invalid profile accepted or secret disclosed", err)
			}
		})
	}
}

type profileCloud struct {
	mu          sync.Mutex
	current     Instance
	unavailable bool
	newIP       bool
	patches     []Instance
	tasks       []Instance
	ipTargets   []Instance
}

func (f *profileCloud) Resolve(context.Context, Config) (Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unavailable {
		return Instance{}, errors.New("profile pending replacement")
	}
	return f.current, nil
}
func (f *profileCloud) IP(_ context.Context, c Config) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ipTargets = append(f.ipTargets, Instance{Type: c.InstanceType, AccountID: c.AccountID, RegionName: c.RegionName, ID: c.InstanceID})
	if c.InstanceID != f.current.ID {
		return "", errors.New("old instance deleted")
	}
	if f.newIP {
		return "2.2.2.2", nil
	}
	return "1.1.1.1", nil
}
func (f *profileCloud) Change(_ context.Context, c Config) (Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.patches = append(f.patches, Instance{Type: c.InstanceType, AccountID: c.AccountID, RegionName: c.RegionName, ID: c.InstanceID})
	return Task{Tag: "fixture-task", Status: "pending"}, nil
}
func (f *profileCloud) Task(_ context.Context, c Config, _ string) (Task, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks = append(f.tasks, Instance{Type: c.InstanceType, AccountID: c.AccountID, RegionName: c.RegionName, ID: c.InstanceID})
	return Task{Tag: "fixture-task", Status: "pending"}, true, nil
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if check() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func TestProfileReplacementDoesNotTransplantPendingTaskOrResetCooldown(t *testing.T) {
	cfg := profileConfig()
	cfg.FailureThreshold = 1
	first := Instance{Type: "ec2", AccountID: "account-one", RegionName: "ap-southeast-1", ID: "i-one"}
	second := Instance{Type: "ec2", AccountID: "account-two", RegionName: "ap-northeast-1", ID: "i-two"}
	cloud := &profileCloud{current: first}
	store := &memoryStore{}
	var now atomic.Int64
	now.Store(1000)
	makeRunner := func() *Runner {
		return &Runner{Config: cfg, Store: store, API: cloud, Interval: time.Millisecond * 5, PollInterval: time.Millisecond * 5, Now: func() time.Time { return time.Unix(now.Load(), 0) }, Probe: func(context.Context, string) (bool, error) { return false, nil }}
	}
	cancel, done := startRunner(t, makeRunner())
	eventually(t, func() bool { cloud.mu.Lock(); defer cloud.mu.Unlock(); return len(cloud.patches) == 1 })
	cancel()
	await(t, done)
	d, _ := store.LoadRecovery("")
	if !d.Pending || d.Instance != first {
		t.Fatal("operation target not durable", d)
	}
	cloud.mu.Lock()
	cloud.current = second
	cloud.mu.Unlock()
	cfg.Generation++
	cfg.ShareGroupToken = "fixture-updated-token"
	startRunner(t, makeRunner())
	eventually(t, func() bool { d, _ := store.LoadRecovery(""); return !d.Pending && d.Instance == second })
	d, _ = store.LoadRecovery("")
	if d.NewIP != "" || d.TaskTag != "" || d.LastChangedUnix != 0 || d.LastAttemptUnix != 1000 {
		t.Fatal("replacement treated as old task success", d)
	}
	cloud.mu.Lock()
	if len(cloud.patches) != 1 || cloud.patches[0] != first {
		t.Fatal("replacement triggered a duplicate change", cloud.patches)
	}
	for _, target := range cloud.tasks {
		if target != first {
			t.Fatal("old task queried against new instance", target)
		}
	}
	cloud.mu.Unlock()
	now.Store(1301)
	eventually(t, func() bool { cloud.mu.Lock(); defer cloud.mu.Unlock(); return len(cloud.patches) == 2 })
	cloud.mu.Lock()
	if cloud.patches[1] != second {
		t.Fatal("new operation did not follow profile", cloud.patches)
	}
	cloud.newIP = true
	cloud.mu.Unlock()
	eventually(t, func() bool { d, _ := store.LoadRecovery(""); return !d.Pending && d.NewIP == "2.2.2.2" })
}

func TestUnavailableProfileNeverFallsBackToSavedInstance(t *testing.T) {
	cfg := profileConfig()
	cfg.FailureThreshold = 1
	cfg.AccountID, cfg.RegionName, cfg.InstanceID = "stale-account", "ap-southeast-1", "i-stale"
	cloud := &profileCloud{unavailable: true}
	store := &memoryStore{}
	var reports atomic.Int32
	startRunner(t, &Runner{Config: cfg, Store: store, API: cloud, Interval: time.Millisecond * 5, PollInterval: time.Millisecond * 5, Probe: func(context.Context, string) (bool, error) { return false, nil }, Publish: func(status Status) {
		if status.State == "error" {
			reports.Add(1)
		}
	}})
	eventually(t, func() bool { return reports.Load() > 0 })
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if len(cloud.patches) != 0 {
		t.Fatal("missing profile used stale fixed target")
	}
}

func TestUnidentifiedLegacyOperationNeedsExplicitReset(t *testing.T) {
	cfg := profileConfig()
	cfg.FailureThreshold = 1
	cloud := &profileCloud{current: Instance{ID: "i-new", RegionName: "ap-southeast-1"}}
	store := &memoryStore{value: Durable{Generation: 1, Pending: true, LegacyTargetUnknown: true, TaskTag: "fixture-old-task", LastAttemptUnix: 1000}}
	var uncertain atomic.Bool
	cancel, done := startRunner(t, &Runner{Config: cfg, Store: store, API: cloud, Interval: time.Millisecond * 5, PollInterval: time.Millisecond * 5, Now: func() time.Time { return time.Unix(2000, 0) }, Probe: func(context.Context, string) (bool, error) { return false, nil }, Publish: func(s Status) {
		if s.State == "uncertain" {
			uncertain.Store(true)
		}
	}})
	eventually(t, func() bool { return uncertain.Load() })
	cloud.mu.Lock()
	if len(cloud.patches) != 0 {
		t.Fatal("unidentified pending task caused new PATCH")
	}
	cloud.mu.Unlock()
	cancel()
	await(t, done)
	cfg.Generation++
	cfg.ResetSequence++
	startRunner(t, &Runner{Config: cfg, Store: store, API: cloud, Interval: time.Millisecond * 5, PollInterval: time.Millisecond * 5, Now: func() time.Time { return time.Unix(2000, 0) }, Probe: func(context.Context, string) (bool, error) { return false, nil }})
	eventually(t, func() bool { cloud.mu.Lock(); defer cloud.mu.Unlock(); return len(cloud.patches) == 1 })
}

func TestPendingOperationRetainsProviderAcrossTypeSwitch(t *testing.T) {
	old := Instance{Type: "ec2", ID: "i-original", AccountID: "fixture-account", RegionName: "ap-southeast-1"}
	cloud := &profileCloud{current: old, newIP: true}
	cfg := profileConfig()
	cfg.InstanceType = "lightsail"
	store := &memoryStore{value: Durable{Generation: 1, Pending: true, Instance: old, OldIP: "1.1.1.1", TaskTag: "fixture-task", LastAttemptUnix: time.Now().Unix()}}
	startRunner(t, &Runner{Config: cfg, Store: store, API: cloud, Interval: time.Millisecond * 5, PollInterval: time.Millisecond * 5, Probe: func(context.Context, string) (bool, error) { return true, nil }})
	eventually(t, func() bool { d, _ := store.LoadRecovery(""); return !d.Pending && d.NewIP == "2.2.2.2" })
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	if len(cloud.patches) != 0 || len(cloud.ipTargets) == 0 {
		t.Fatal("pending operation was lost or repeated")
	}
	for _, target := range cloud.ipTargets {
		if target != old {
			t.Fatal("old EC2 operation used new Lightsail target", target)
		}
	}
}

func TestFixedResolutionFreezesProvider(t *testing.T) {
	client := NewClient().(*Client)
	defer client.Close()
	for _, kind := range []string{"ec2", "lightsail"} {
		cfg := fixtureConfig()
		cfg.InstanceType = kind
		instance, err := client.Resolve(context.Background(), cfg)
		if err != nil || instance.Type != kind {
			t.Fatal("fixed target omitted its provider", instance, err)
		}
		cfg.InstanceType = "other"
		if cfg.ForInstance(instance).InstanceType != kind {
			t.Fatal("operation provider was not frozen")
		}
	}
}
