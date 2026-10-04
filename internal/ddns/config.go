package ddns

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type Config struct {
	Enabled         bool   `json:"enabled"`
	Provider        string `json:"provider"`
	RecordName      string `json:"record_name"`
	ZoneID          string `json:"zone_id"`
	Token           string `json:"token"`
	IPv4            bool   `json:"ipv4"`
	IPv6            bool   `json:"ipv6"`
	IntervalSeconds int    `json:"interval_seconds"`
	TTL             int    `json:"ttl"`
	IPv4URL         string `json:"ipv4_url"`
	IPv6URL         string `json:"ipv6_url"`
	UseForIngress   bool   `json:"use_for_ingress"`
	UseForEgress    bool   `json:"use_for_egress"`
}

func DefaultConfig() Config {
	return Config{Provider: "cloudflare", IPv4: true, IntervalSeconds: 300, TTL: 300, IPv4URL: "https://api.ipify.org", IPv6URL: "https://api6.ipify.org", UseForIngress: true, UseForEgress: true}
}

var zoneID = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func (c *Config) Normalize() error {
	c.RecordName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.RecordName), "."))
	c.ZoneID = strings.TrimSpace(c.ZoneID)
	c.Token = strings.TrimSpace(c.Token)
	d := DefaultConfig()
	if c.Provider == "" {
		c.Provider = d.Provider
	}
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = d.IntervalSeconds
	}
	if c.TTL == 0 {
		c.TTL = d.TTL
	}
	if c.IPv4URL == "" {
		c.IPv4URL = d.IPv4URL
	}
	if c.IPv6URL == "" {
		c.IPv6URL = d.IPv6URL
	}
	if c.Provider != "cloudflare" {
		return errors.New("目前支持 Cloudflare")
	}
	if c.IntervalSeconds < 60 || c.IntervalSeconds > 86400 {
		return errors.New("检查间隔须为 60–86400 秒")
	}
	if c.TTL != 1 && (c.TTL < 60 || c.TTL > 86400) {
		return errors.New("TTL 须为 1（自动）或 60–86400 秒")
	}
	if c.ZoneID != "" && !zoneID.MatchString(c.ZoneID) {
		return errors.New("Zone ID 须为 32 位十六进制字符")
	}
	if len(c.Token) > 512 || strings.ContainsAny(c.Token, "\r\n\x00") {
		return errors.New("Cloudflare Token 格式无效")
	}
	if c.RecordName != "" && !ValidDomain(c.RecordName) {
		return errors.New("DDNS 须填写完整域名，不含协议、端口或通配符")
	}
	for _, source := range []string{c.IPv4URL, c.IPv6URL} {
		u, err := url.Parse(source)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(source) > 2048 || strings.ContainsAny(source, "\r\n\x00") {
			return errors.New("IP 获取地址须为 HTTPS URL")
		}
	}
	if c.Enabled && (c.RecordName == "" || c.Token == "" || !c.IPv4 && !c.IPv6) {
		return errors.New("启用 DDNS 需要域名、Token，并至少选择一个 IP 类型")
	}
	return nil
}

func ValidDomain(name string) bool {
	if len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, ch := range part {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
