package agent

import (
	"encoding/json"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUpdateGenerationSurvivesRestartWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	e, err := NewEngine(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.SetUpdateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &pb.ControlMessage{Update: &pb.UpdateRequest{Generation: 1, Version: "v0.10.0"}}
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "update-request.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if json.Unmarshal(data, &request) != nil || request["version"] != "v0.10.0" {
		t.Fatal("bad update request")
	}
	if info, _ := os.Stat(file); runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("request permissions")
	}
	os.Remove(file)
	e.Close()
	restored, err := NewEngine(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.SetUpdateDirectory(dir)
	if err = restored.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("cached update replayed")
	}
	// Only a matching result generation is accepted; completed needs the actual binary version.
	os.WriteFile(filepath.Join(dir, "update-result.json"), []byte(`{"generation":2,"version":"v0.10.0","state":"completed"}`), 0600)
	report, _ := restored.Report()
	if report.UpdateStatus.State != "queued" {
		t.Fatal("foreign generation accepted")
	}
	os.WriteFile(filepath.Join(dir, "update-result.json"), []byte(`{"generation":1,"version":"v0.10.0","state":"completed"}`), 0600)
	report, _ = restored.Report()
	if release.Version != "v0.10.0" && report.UpdateStatus.State != "failed" {
		t.Fatal("wrong binary version accepted")
	}
	cfg.Update.Generation = 2
	if err = restored.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(file); err != nil {
		t.Fatal("new update not queued")
	}
}
