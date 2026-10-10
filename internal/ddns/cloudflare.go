package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	APIBase string
	API     *http.Client
	IPv4    *http.Client
	IPv6    *http.Client
}

func NewClient() *Client {
	client := func(family string) *http.Client {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, family, address)
		}
		return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{APIBase: "https://api.cloudflare.com/client/v4", API: client("tcp"), IPv4: client("tcp4"), IPv6: client("tcp6")}
}

func (c *Client) Close() {
	for _, client := range []*http.Client{c.API, c.IPv4, c.IPv6} {
		if client != nil {
			client.CloseIdleConnections()
		}
	}
}

func (c *Client) Address(ctx context.Context, source string, v6 bool) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", errors.New("IP 获取地址无效")
	}
	client := c.IPv4
	if v6 {
		client = c.IPv6
	}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("无法获取公网 IP")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("公网 IP 服务返回错误")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 257))
	if err != nil || len(data) > 256 {
		return "", errors.New("公网 IP 响应无效")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(string(data)))
	if err != nil || address.Zone() != "" {
		return "", errors.New("公网 IP 响应不是有效地址")
	}
	address = address.Unmap()
	if address.Is6() != v6 || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("公网 IP 地址类型错误或不是公网地址")
	}
	return address.String(), nil
}

// AddressWithRetry tolerates temporary loss of connectivity during IP changes.
// Callers publish status only after this operation completes, never per attempt.
func (c *Client) AddressWithRetry(ctx context.Context, source string, v6 bool) (string, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		request, cancel := context.WithTimeout(ctx, 15*time.Second)
		address, err := c.Address(request, source, v6)
		cancel()
		if err == nil {
			return address, nil
		}
		last = err
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", last
}

func (c *Client) request(ctx context.Context, method, path, token string, payload any, result any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return errors.New("DNS 请求内容无效")
		}
		body = bytes.NewReader(data)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.APIBase+path, body)
	if err != nil {
		return errors.New("DNS 请求创建失败")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := c.API.Do(r)
	if err != nil {
		return errors.New("Cloudflare 连接失败")
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &envelope) != nil {
		return errors.New("Cloudflare 响应无效")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		if response.StatusCode == 401 || response.StatusCode == 403 {
			return errors.New("Cloudflare Token 无效或权限不足")
		}
		if response.StatusCode == 429 {
			return errors.New("Cloudflare 请求过于频繁，稍后重试")
		}
		return fmt.Errorf("Cloudflare DNS 操作失败（HTTP %d）", response.StatusCode)
	}
	if result != nil && json.Unmarshal(envelope.Result, result) != nil {
		return errors.New("Cloudflare 结果无效")
	}
	return nil
}

func (c *Client) Zone(ctx context.Context, cfg Config) (string, error) {
	if cfg.ZoneID != "" {
		return cfg.ZoneID, nil
	}
	labels := strings.Split(cfg.RecordName, ".")
	for offset := 0; offset < len(labels)-1; offset++ {
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		query := url.Values{"name": {strings.Join(labels[offset:], ".")}, "status": {"active"}}
		if err := c.request(ctx, "GET", "/zones?"+query.Encode(), cfg.Token, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) == 1 && zoneID.MatchString(zones[0].ID) && strings.EqualFold(zones[0].Name, strings.Join(labels[offset:], ".")) {
			return zones[0].ID, nil
		}
	}
	return "", errors.New("找不到 Cloudflare 域名区域，请检查 Zone ID 或 Zone 读取权限")
}

func (c *Client) Sync(ctx context.Context, cfg Config, zone, kind, address string) (bool, error) {
	query := url.Values{"type": {kind}, "name": {cfg.RecordName}, "per_page": {"100"}}
	var records []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
	}
	if err := c.request(ctx, "GET", "/zones/"+zone+"/dns_records?"+query.Encode(), cfg.Token, nil, &records); err != nil {
		return false, err
	}
	if len(records) > 1 {
		return false, errors.New("同名 DNS 记录有多条，请指定单条 A/AAAA 记录用于 DDNS")
	}
	payload := map[string]any{"type": kind, "name": cfg.RecordName, "content": address, "ttl": cfg.TTL, "proxied": false}
	if len(records) == 0 {
		return true, c.request(ctx, "POST", "/zones/"+zone+"/dns_records", cfg.Token, payload, nil)
	}
	record := records[0]
	if !zoneID.MatchString(record.ID) || record.Type != kind || !strings.EqualFold(strings.TrimSuffix(record.Name, "."), cfg.RecordName) {
		return false, errors.New("Cloudflare DNS 记录不匹配")
	}
	if record.Content == address && record.TTL == cfg.TTL && !record.Proxied {
		return false, nil
	}
	return true, c.request(ctx, "PATCH", "/zones/"+zone+"/dns_records/"+record.ID, cfg.Token, payload, nil)
}
