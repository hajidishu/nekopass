package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/release"
)

func TestPanelUpdatesRequireAdminLatestVersionAndSingleTask(t *testing.T) {
	f := newSecurityFixture(t)
	dir := t.TempDir()
	f.s.SetPanelUpdateDirectory(dir)
	previous := release.Version
	release.Version = "v0.13.0"
	defer func() { release.Version = previous }()
	f.s.releaseChecked = time.Now()
	f.s.releaseInfo = release.Info{Version: "v0.13.1"}
	path := "admin/updates/panel"
	request := map[string]string{"version": "v0.13.1"}
	securityStatus(t, f.request(0, path, "POST", request), 401)
	securityStatus(t, f.request(f.user, path, "GET", nil), 403)
	securityStatus(t, f.request(f.user, path, "POST", request), 403)
	securityStatus(t, f.request(f.admin, path, "POST", request), 409)
	if e := os.WriteFile(filepath.Join(dir, "panel-update-ready"), []byte("systemd"), 0600); e != nil {
		t.Fatal(e)
	}
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.13.1;id"}), 400)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]string{"version": "v0.13.2"}), 409)
	securityStatus(t, f.request(f.admin, path, "POST", map[string]any{"version": "v0.13.1", "command": "id"}), 400)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.request(f.admin, path, "POST", request)
			if w.Code == 202 {
				successes.Add(1)
			} else if w.Code != 409 {
				t.Errorf("unexpected update status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("duplicate update tasks accepted", successes.Load())
	}
	var task panelUpdateTask
	if !readUpdateFile(filepath.Join(dir, "panel-update-task.json"), &task) || task.ActorID != f.admin || task.State != "queued" {
		t.Fatal("missing durable task")
	}
	var queued map[string]any
	data, e := os.ReadFile(filepath.Join(dir, "update-request.json"))
	if e != nil || json.Unmarshal(data, &queued) != nil || len(queued) != 2 || queued["version"] != "v0.13.1" {
		t.Fatal("invalid helper request", e)
	}
	result, _ := json.Marshal(map[string]any{"generation": task.Generation, "version": task.Version, "state": "completed"})
	os.WriteFile(filepath.Join(dir, "update-result.json"), result, 0600)
	if f.s.currentPanelUpdate().State != "failed" {
		t.Fatal("wrong binary version reported success")
	}
	release.Version = "v0.13.1"
	if f.s.currentPanelUpdate().State != "completed" {
		t.Fatal("completed helper update not recognized")
	}
	securityStatus(t, f.request(f.admin, path, "POST", request), 409)
}

func TestPanelUpdateStatusIgnoresForeignResultsAndTimesOut(t *testing.T) {
	s := New(nil)
	dir := t.TempDir()
	s.SetPanelUpdateDirectory(dir)
	task := panelUpdateTask{Generation: 1, Version: "v0.13.1", State: "queued", RequestedAt: time.Now()}
	data, _ := json.Marshal(task)
	os.WriteFile(filepath.Join(dir, "panel-update-task.json"), data, 0600)
	os.WriteFile(filepath.Join(dir, "update-result.json"), []byte(`{"generation":2,"version":"v0.13.1","state":"completed"}`), 0600)
	if s.currentPanelUpdate().State != "queued" {
		t.Fatal("foreign helper result accepted")
	}
	task.RequestedAt = time.Now().Add(-16 * time.Minute)
	data, _ = json.Marshal(task)
	os.WriteFile(filepath.Join(dir, "panel-update-task.json"), data, 0600)
	if s.currentPanelUpdate().State != "failed" {
		t.Fatal("stale task blocks all future updates")
	}
}
