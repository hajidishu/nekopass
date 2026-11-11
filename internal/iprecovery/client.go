package iprecovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Task struct {
	Tag        string          `json:"tag"`
	Status     string          `json:"status"`
	EndedAt    json.RawMessage `json:"endedAt"`
	EndedSnake json.RawMessage `json:"ended_at"`
}

func (t Task) Ended() bool {
	for _, v := range []json.RawMessage{t.EndedAt, t.EndedSnake} {
		if len(v) > 0 && string(v) != "null" && string(v) != "0" && string(v) != "false" && string(v) != `""` {
			return true
		}
	}
	return t.Status == "error"
}

type API interface {
	Resolve(context.Context, Config) (Instance, error)
	IP(context.Context, Config) (string, error)
	Change(context.Context, Config) (Task, error)
	Task(context.Context, Config, string) (Task, bool, error)
}

func (c *Client) Resolve(ctx context.Context, cfg Config) (Instance, error) {
	if cfg.BindingMode != "profile" {
		return Instance{Type: cfg.InstanceType, AccountID: cfg.AccountID, RegionName: cfg.RegionName, ID: cfg.InstanceID}, nil
	}
	var result struct {
		ID             string `json:"id"`
		InstanceID     string `json:"instance_id"`
		InstanceCamel  string `json:"instanceId"`
		Name           string `json:"instance_name"`
		NameCamel      string `json:"instanceName"`
		AccountID      string `json:"account_id"`
		AccountCamel   string `json:"accountId"`
		RegionName     string `json:"region_name"`
		RegionCamel    string `json:"regionName"`
		AccountInvalid bool   `json:"account_invalid"`
		InvalidCamel   bool   `json:"accountInvalid"`
	}
	path := "/ec2-instance-profiles/"
	if cfg.InstanceType == "lightsail" {
		path = "/lightsail-instance-profiles/"
	}
	// The profile is authoritative. Do not use a stale account or region saved
	// before replacement, including when the replacement moved across accounts.
	lookup := cfg
	lookup.AccountID, lookup.RegionName, lookup.InstanceID = "", "", ""
	if err := c.call(ctx, lookup, http.MethodGet, path+url.PathEscape(cfg.ProfileID), nil, &result); err != nil {
		return Instance{}, err
	}
	if result.ID != "" && result.ID != cfg.ProfileID || result.AccountInvalid || result.InvalidCamel {
		return Instance{}, errors.New("实例档案不可用，请检查档案和分享权限")
	}
	first := func(values ...string) string {
		for _, value := range values {
			if value != "" {
				return value
			}
		}
		return ""
	}
	id := first(result.InstanceID, result.InstanceCamel)
	if cfg.InstanceType == "lightsail" {
		id = first(result.Name, result.NameCamel)
	}
	instance := Instance{Type: cfg.InstanceType, AccountID: first(result.AccountID, result.AccountCamel), RegionName: first(result.RegionName, result.RegionCamel), ID: id}
	resolved := cfg.ForInstance(instance)
	if err := resolved.Normalize(); err != nil {
		return Instance{}, errors.New("实例档案暂未关联可用实例，等待补机完成或检查分享权限")
	}
	return instance, nil
}

type APIError struct {
	Status    int
	Ambiguous bool
}

func (e *APIError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("小助理请求失败（HTTP %d）", e.Status)
	}
	return "无法确认小助理请求结果"
}

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient() API {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{baseURL: "https://api.aws.sb", http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) call(ctx context.Context, cfg Config, method, path string, body any, out any) error {
	var input io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return errors.New("小助理请求内容无效")
		}
		input = bytes.NewReader(b)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, input)
	if err != nil {
		return errors.New("小助理请求地址无效")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cache-Control", "no-cache")
	if method == http.MethodGet {
		query := request.URL.Query()
		query.Set("r", strconv.FormatInt(time.Now().UnixNano(), 36))
		request.URL.RawQuery = query.Encode()
	}
	for name, value := range map[string]string{"X-Auth-Token": cfg.AuthToken, "X-Share-Group-Token": cfg.ShareGroupToken, "X-Account-Id": cfg.AccountID, "X-Region-Name": cfg.RegionName} {
		if value != "" {
			request.Header.Set(name, value)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		return &APIError{Ambiguous: method == http.MethodPatch}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{Status: response.StatusCode, Ambiguous: method == http.MethodPatch && (response.StatusCode >= 500 || response.StatusCode == 408)}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return &APIError{Ambiguous: method == http.MethodPatch}
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return &APIError{Ambiguous: method == http.MethodPatch}
	}
	return nil
}
func instancePath(cfg Config) string {
	if cfg.InstanceType == "lightsail" {
		return "/lightsail-instances/" + url.PathEscape(cfg.InstanceID)
	}
	return "/ec2-instances/" + url.PathEscape(cfg.InstanceID)
}
func (c *Client) IP(ctx context.Context, cfg Config) (string, error) {
	var result struct {
		IP    string `json:"ipAddress"`
		Snake string `json:"ip_address"`
	}
	if err := c.call(ctx, cfg, http.MethodGet, instancePath(cfg), nil, &result); err != nil {
		return "", err
	}
	for _, ip := range []string{result.IP, result.Snake} {
		if PublicIPv4(ip) {
			return ip, nil
		}
	}
	return "", errors.New("小助理尚未返回有效公网 IPv4")
}
func (c *Client) Change(ctx context.Context, cfg Config) (Task, error) {
	body := map[string]any{"static": cfg.StaticIP}
	if cfg.InstanceType == "ec2" {
		body["gfw_blocked_check"] = false
	}
	var task Task
	var out any = &task
	if cfg.InstanceType == "lightsail" {
		out = nil
	}
	err := c.call(ctx, cfg, http.MethodPatch, instancePath(cfg)+"/ip-address", body, out)
	if len(task.Tag) > 512 || strings.ContainsAny(task.Tag, "\r\n\x00") {
		return Task{}, &APIError{Ambiguous: true}
	}
	return task, err
}
func (c *Client) Task(ctx context.Context, cfg Config, tag string) (Task, bool, error) {
	var tasks []Task
	if err := c.call(ctx, cfg, http.MethodPost, "/filter-tasks", map[string]any{"tags": []string{tag}}, &tasks); err != nil {
		return Task{}, false, err
	}
	for _, t := range tasks {
		if t.Tag == tag {
			return t, true, nil
		}
	}
	return Task{}, false, nil
}
