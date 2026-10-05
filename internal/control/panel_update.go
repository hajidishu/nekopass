package control

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nekopass/nekopass/internal/release"
)

type panelUpdateTask struct {
	Generation  int64     `json:"generation"`
	Version     string    `json:"version"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	ActorID     int64     `json:"actor_id"`
}

func (s *Server) SetPanelUpdateDirectory(directory string) { s.panelUpdateDir = directory }
func readUpdateFile(name string, v any) bool {
	info, e := os.Lstat(name)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return false
	}
	data, e := os.ReadFile(name)
	return e == nil && json.Unmarshal(data, v) == nil
}
func (s *Server) panelUpdateSupported() bool {
	if s.panelUpdateDir == "" {
		return false
	}
	i, e := os.Lstat(filepath.Join(s.panelUpdateDir, "panel-update-ready"))
	return e == nil && i.Mode().IsRegular()
}
func (s *Server) currentPanelUpdate() *panelUpdateTask {
	var task panelUpdateTask
	if s.panelUpdateDir == "" || !readUpdateFile(filepath.Join(s.panelUpdateDir, "panel-update-task.json"), &task) || task.Generation < 1 || !release.ValidVersion(task.Version) {
		return nil
	}
	var result panelUpdateTask
	if readUpdateFile(filepath.Join(s.panelUpdateDir, "update-result.json"), &result) && result.Generation == task.Generation && result.Version == task.Version && (result.State == "running" || result.State == "completed" || result.State == "failed") {
		task.State = result.State
		task.Error = result.Error
		if task.State == "completed" && release.Version != task.Version {
			task.State = "failed"
			task.Error = "更新后版本不匹配，请查看面板更新服务日志"
		}
	}
	if (task.State == "queued" || task.State == "running") && time.Since(task.RequestedAt) > 15*time.Minute {
		task.State = "failed"
		task.Error = "更新任务超时，请查看面板更新服务日志"
	}
	return &task
}
func (s *Server) panelUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	s.panelUpdateMu.Lock()
	defer s.panelUpdateMu.Unlock()
	writeJSON(w, 200, map[string]any{"supported": s.panelUpdateSupported(), "current_version": release.Version, "task": s.currentPanelUpdate()})
}
func atomicUpdateFile(dir, name string, data []byte) error {
	f, e := os.CreateTemp(dir, ".panel-update-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}
func (s *Server) updatePanel(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !release.ValidVersion(in.Version) {
		fail(w, 400, "更新版本无效")
		return
	}
	latest, e := s.latestRelease(r.Context())
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	if latest.Version != in.Version || !release.Newer(in.Version, release.Version) {
		fail(w, 409, "请更新至最新正式版本，当前没有可用升级")
		return
	}
	s.panelUpdateMu.Lock()
	defer s.panelUpdateMu.Unlock()
	if !s.panelUpdateSupported() {
		fail(w, 409, "尚未安装面板更新服务，请先安装新版更新服务")
		return
	}
	if task := s.currentPanelUpdate(); task != nil && (task.State == "queued" || task.State == "running") {
		fail(w, 409, "已有面板更新任务，请等待完成")
		return
	}
	if _, e = os.Lstat(filepath.Join(s.panelUpdateDir, "update-request.json")); !os.IsNotExist(e) {
		fail(w, 409, "已有待处理更新请求")
		return
	}
	task := panelUpdateTask{Generation: time.Now().UnixNano(), Version: in.Version, State: "queued", RequestedAt: time.Now(), ActorID: current(r).ID}
	data, _ := json.Marshal(task)
	if e = atomicUpdateFile(s.panelUpdateDir, "panel-update-task.json", data); e != nil {
		fail(w, 500, "无法保存面板更新任务")
		return
	}
	request, _ := json.Marshal(map[string]any{"generation": task.Generation, "version": task.Version})
	if e = atomicUpdateFile(s.panelUpdateDir, "update-request.json", request); e != nil {
		task.State = "failed"
		task.Error = "无法提交面板更新请求"
		data, _ = json.Marshal(task)
		_ = atomicUpdateFile(s.panelUpdateDir, "panel-update-task.json", data)
		fail(w, 500, task.Error)
		return
	}
	writeJSON(w, 202, task)
}
