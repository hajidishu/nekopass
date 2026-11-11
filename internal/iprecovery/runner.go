package iprecovery

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Durable struct {
	LegacyTargetUnknown bool     `json:"legacy_target_unknown,omitempty"`
	Instance            Instance `json:"instance"`
	Generation          int64    `json:"generation"`
	ResetSequence       int64    `json:"reset_sequence"`
	LastAttemptUnix     int64    `json:"last_attempt_unix"`
	LastChangedUnix     int64    `json:"last_changed_unix"`
	Pending             bool     `json:"pending"`
	OldIP               string   `json:"old_ip"`
	NewIP               string   `json:"new_ip"`
	TaskTag             string   `json:"task_tag"`
}
type Store interface {
	LoadRecovery(string) (Durable, error)
	SaveRecovery(string, Durable) error
}
type Status struct {
	InstanceID        string `json:"instance_id"`
	AccountID         string `json:"account_id"`
	RegionName        string `json:"region_name"`
	Generation        int64  `json:"generation"`
	State             string `json:"state"`
	Failures          int    `json:"failures"`
	Reachable         bool   `json:"reachable"`
	CheckedUnix       int64  `json:"checked_unix"`
	LastAttemptUnix   int64  `json:"last_attempt_unix"`
	LastChangedUnix   int64  `json:"last_changed_unix"`
	CooldownUntilUnix int64  `json:"cooldown_until_unix"`
	OldIP             string `json:"old_ip"`
	NewIP             string `json:"new_ip"`
	Error             string `json:"error"`
}
type Runner struct {
	Config  Config
	Store   Store
	API     API
	Probe   func(context.Context, string) (bool, error)
	Publish func(Status)
	Changed func()
	// Tests replace timings; production always uses a five-second probe interval.
	Interval, PollInterval, OperationTimeout time.Duration
	Now                                      func() time.Time
}
type jobResult struct {
	disk            Durable
	state, feedback string
	done, changed   bool
}

func (r *Runner) Run(ctx context.Context) {
	cfg := r.Config
	if !cfg.Enabled {
		return
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Probe == nil {
		r.Probe = Ping
	}
	if r.Interval == 0 {
		r.Interval = time.Duration(IntervalSeconds) * time.Second
	}
	if r.PollInterval == 0 {
		r.PollInterval = 5 * time.Second
	}
	if r.OperationTimeout == 0 {
		r.OperationTimeout = 10 * time.Minute
	}
	if closer, ok := r.API.(interface{ Close() }); ok {
		defer closer.Close()
	}
	status := Status{Generation: cfg.Generation, State: "checking"}
	emit := func(d Durable) {
		status.InstanceID, status.AccountID, status.RegionName = d.Instance.ID, d.Instance.AccountID, d.Instance.RegionName
		status.LastAttemptUnix = d.LastAttemptUnix
		status.LastChangedUnix = d.LastChangedUnix
		status.OldIP = d.OldIP
		status.NewIP = d.NewIP
		if base := max(d.LastAttemptUnix, d.LastChangedUnix); base > 0 {
			status.CooldownUntilUnix = base + int64(cfg.CooldownSeconds)
		}
		if r.Publish != nil {
			r.Publish(status)
		}
	}
	key := cfg.ResourceKey()
	disk, err := r.Store.LoadRecovery(key)
	if err != nil {
		status.State = "error"
		status.Error = "无法读取自动换 IP 状态"
		emit(disk)
		return
	}
	if cfg.ResetSequence > disk.ResetSequence {
		disk.Pending = false
		disk.TaskTag = ""
	}
	disk.Generation = cfg.Generation
	disk.ResetSequence = cfg.ResetSequence
	if err = r.Store.SaveRecovery(key, disk); err != nil {
		status.State = "error"
		status.Error = "无法保存自动换 IP 状态"
		emit(disk)
		return
	}
	results := make(chan jobResult, 8)
	var jobs sync.WaitGroup
	busy := false
	phase := ""
	resumeAt := time.Time{}
	defer jobs.Wait()
	launch := func(newAttempt bool) {
		busy = true
		phase = "changing"
		status.Error = ""
		if !newAttempt {
			phase = "waiting"
		}
		snapshot := disk
		jobs.Add(1)
		go func() { defer jobs.Done(); r.change(ctx, key, snapshot, newAttempt, results) }()
	}
	if disk.Pending {
		launch(false)
	}
	tick := time.NewTicker(r.Interval)
	defer tick.Stop()
	probe := func() {
		reachable, err := r.Probe(ctx, cfg.TargetIP)
		if ctx.Err() != nil {
			return
		}
		status.CheckedUnix = r.Now().Unix()
		status.Reachable = reachable
		if err != nil {
			status.Failures = 0
			status.State = "error"
			status.Error = "ICMP 检测不可用，请检查节点网络和 ping 权限"
			emit(disk)
			return
		}
		if reachable {
			status.Failures = 0
		} else {
			status.Failures = min(status.Failures+1, cfg.FailureThreshold)
		}
		switch {
		case busy:
			status.State = phase
		case disk.Pending:
			status.State = "uncertain"
			if !r.Now().Before(resumeAt) {
				launch(false)
				status.State = phase
			}
		case max(disk.LastAttemptUnix, disk.LastChangedUnix) > 0 && r.Now().Unix() < max(disk.LastAttemptUnix, disk.LastChangedUnix)+int64(cfg.CooldownSeconds):
			status.State = "cooldown"
		case !reachable && status.Failures >= cfg.FailureThreshold:
			disk.LastAttemptUnix = r.Now().Unix()
			status.Failures = 0
			if err = r.Store.SaveRecovery(key, disk); err != nil {
				status.State = "error"
				status.Error = "无法保存换 IP 冷却状态"
				emit(disk)
				return
			}
			launch(true)
			status.State = phase
		case reachable:
			status.State = "healthy"
		default:
			status.State = "unreachable"
		}
		emit(disk)
	}
	probe()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			probe()
		case update := <-results:
			disk = update.disk
			phase = update.state
			status.State = phase
			status.Error = update.feedback
			if update.done {
				busy = false
				resumeAt = r.Now().Add(time.Minute)
			}
			if update.changed {
				status.Failures = 0
				if r.Changed != nil {
					r.Changed()
				}
			}
			emit(disk)
		}
	}
}

func (r *Runner) change(parent context.Context, key string, disk Durable, newAttempt bool, results chan<- jobResult) {
	ctx, cancel := context.WithTimeout(parent, r.OperationTimeout)
	defer cancel()
	send := func(state, feedback string, done, changed bool) {
		select {
		case results <- jobResult{disk: disk, state: state, feedback: feedback, done: done, changed: changed}:
		case <-parent.Done():
		}
	}
	save := func() bool {
		if err := r.Store.SaveRecovery(key, disk); err != nil {
			send("error", "无法保存换 IP 任务状态", true, false)
			return false
		}
		return true
	}
	if !newAttempt && disk.Pending && disk.LegacyTargetUnknown {
		send("uncertain", "旧换 IP 任务缺少实例记录，请确认任务结束后重置等待状态", true, false)
		return
	}
	if newAttempt || disk.Instance.ID == "" {
		instance, err := r.API.Resolve(ctx, r.Config)
		if err != nil {
			send("error", "无法解析小助理实例，请检查绑定标识、凭证及分享权限；补机期间将自动重试", true, false)
			return
		}
		disk.Instance = instance
		disk.LegacyTargetUnknown = false
		if !save() {
			return
		}
	}
	operation := r.Config.ForInstance(disk.Instance)
	if newAttempt {
		ip, err := r.API.IP(ctx, operation)
		if err != nil {
			send("error", "无法查询小助理实例，请检查凭证、地区和实例信息", true, false)
			return
		}
		disk.OldIP = ip
		disk.NewIP = ""
		disk.TaskTag = ""
		disk.Pending = true
		// Persist intent before PATCH: a cloud IP change may reboot the node before
		// the HTTP response arrives. Restarts reconcile instead of issuing it twice.
		if !save() {
			return
		}
		task, err := r.API.Change(ctx, operation)
		if err != nil {
			var apiError *APIError
			if errors.As(err, &apiError) && !apiError.Ambiguous {
				disk.Pending = false
				if !save() {
					return
				}
				send("error", "小助理拒绝换 IP 请求，请检查凭证、权限及实例状态", true, false)
				return
			}
			send("waiting", "请求结果待确认，正在查询实例 IP", false, false)
		} else {
			disk.TaskTag = task.Tag
			if task.Ended() && task.Status == "error" {
				disk.Pending = false
				if !save() {
					return
				}
				send("error", "小助理换 IP 任务失败", true, false)
				return
			}
			if !save() {
				return
			}
			send("waiting", "", false, false)
		}
	}
	var finishedAt time.Time
	for {
		if parent.Err() != nil {
			return
		}
		if r.Config.BindingMode == "profile" && (disk.Instance.Type == "" || disk.Instance.Type == r.Config.InstanceType) {
			current, err := r.API.Resolve(ctx, r.Config)
			if err == nil && current != disk.Instance {
				// A replacement is a different operation target, not completion of
				// the old target's PATCH. Retain the profile's cooldown and never
				// transplant its task tag or infer success from the new machine's IP.
				disk.Instance = current
				disk.Pending = false
				disk.TaskTag, disk.OldIP, disk.NewIP = "", "", ""
				disk.LastAttemptUnix = r.Now().Unix()
				if save() {
					send("cooldown", "实例档案已切换到新实例，冷却后重新检测", true, false)
				}
				return
			}
			if err != nil {
				// Do not classify a stale instance as current while the provider
				// has no replacement or profile access is temporarily unavailable.
				if !r.waitPoll(ctx, parent, results, disk) {
					return
				}
				continue
			}
		}
		ip, err := r.API.IP(ctx, operation)
		if err == nil && ip != disk.OldIP {
			disk.NewIP = ip
			disk.LastChangedUnix = r.Now().Unix()
			disk.Pending = false
			disk.TaskTag = ""
			if !save() {
				return
			}
			send("cooldown", "", true, true)
			return
		}
		if disk.TaskTag != "" && ctx.Err() == nil {
			task, found, err := r.API.Task(ctx, operation, disk.TaskTag)
			if err == nil && found && task.Ended() {
				if task.Status == "error" {
					disk.Pending = false
					disk.TaskTag = ""
					if !save() {
						return
					}
					send("error", "小助理换 IP 任务失败", true, false)
					return
				}
				if finishedAt.IsZero() {
					finishedAt = time.Now()
				}
				if time.Since(finishedAt) >= time.Minute {
					disk.Pending = false
					disk.TaskTag = ""
					if !save() {
						return
					}
					send("error", "小助理任务已结束，但未确认公网 IP 变化", true, false)
					return
				}
			}
		}
		if !r.waitPoll(ctx, parent, results, disk) {
			return
		}
	}
}

func (r *Runner) waitPoll(ctx, parent context.Context, results chan<- jobResult, disk Durable) bool {
	timer := time.NewTimer(r.PollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		if parent.Err() == nil {
			select {
			case results <- jobResult{disk: disk, state: "uncertain", feedback: "尚未确认换 IP 结果，将继续查询；不会重复提交请求", done: true}:
			case <-parent.Done():
			}
		}
		return false
	case <-timer.C:
		return true
	}
}
