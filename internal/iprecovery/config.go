package iprecovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

const IntervalSeconds = 5

type Config struct {
	Enabled          bool   `json:"enabled"`
	TargetIP         string `json:"target_ip"`
	FailureThreshold int    `json:"failure_threshold"`
	CooldownSeconds  int    `json:"cooldown_seconds"`
	InstanceType     string `json:"instance_type"`
	BindingMode      string `json:"binding_mode"`
	ProfileID        string `json:"profile_id"`
	AuthToken        string `json:"auth_token"`
	ShareGroupToken  string `json:"share_group_token"`
	AccountID        string `json:"account_id"`
	RegionName       string `json:"region_name"`
	InstanceID       string `json:"instance_id"`
	StaticIP         bool   `json:"static_ip"`
	Generation       int64  `json:"-"`
	ResetSequence    int64  `json:"-"`
}

func DefaultConfig() Config {
	return Config{FailureThreshold: 6, CooldownSeconds: 300, InstanceType: "ec2", BindingMode: "instance"}
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)

func PublicIPv4(value string) bool {
	a, err := netip.ParseAddr(value)
	return err == nil && a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate()
}
func (c *Config) Normalize() error {
	c.TargetIP = strings.TrimSpace(c.TargetIP)
	c.AuthToken = strings.TrimSpace(c.AuthToken)
	c.ShareGroupToken = strings.TrimSpace(c.ShareGroupToken)
	c.AccountID = strings.TrimSpace(c.AccountID)
	c.RegionName = strings.TrimSpace(c.RegionName)
	c.InstanceID = strings.TrimSpace(c.InstanceID)
	c.ProfileID = strings.TrimSpace(c.ProfileID)
	if c.BindingMode == "" {
		c.BindingMode = "instance"
	}
	if c.BindingMode != "instance" && c.BindingMode != "profile" {
		return errors.New("绑定方式须为固定实例或跟随实例档案")
	}
	if c.InstanceType == "" {
		c.InstanceType = "ec2"
	}
	if c.FailureThreshold == 0 {
		c.FailureThreshold = 6
	}
	if c.CooldownSeconds == 0 {
		c.CooldownSeconds = 300
	}
	if c.InstanceType != "ec2" && c.InstanceType != "lightsail" {
		return errors.New("实例类型须为 EC2 或 Lightsail")
	}
	if c.FailureThreshold < 1 || c.FailureThreshold > 720 || c.CooldownSeconds < 30 || c.CooldownSeconds > 86400 {
		return errors.New("连续失败次数须为 1–720，冷却时间须为 30–86400 秒")
	}
	if c.TargetIP != "" && !PublicIPv4(c.TargetIP) {
		return errors.New("检测目标须为公网 IPv4 地址")
	}
	for _, v := range []string{c.AccountID, c.RegionName, c.InstanceID, c.ProfileID} {
		if v != "" && !identifier.MatchString(v) {
			return errors.New("账号、地区或实例标识格式无效")
		}
	}
	for _, v := range []string{c.AuthToken, c.ShareGroupToken} {
		if len(v) > 4096 {
			return errors.New("小助理凭证过长")
		}
		for _, r := range v {
			if r < 33 || r > 126 {
				return errors.New("小助理凭证不能包含空白或非 ASCII 字符")
			}
		}
	}
	if c.Enabled && (c.TargetIP == "" || c.AuthToken == "" && c.ShareGroupToken == "") {
		return errors.New("请填写检测 IP、实例信息以及小助理认证 Token 或分享组 Token")
	}
	if c.Enabled && c.BindingMode == "profile" && c.ProfileID == "" {
		return errors.New("请填写小助理实例档案 ID")
	}
	if c.Enabled && c.BindingMode == "instance" && (c.AccountID == "" && c.ShareGroupToken == "" || c.RegionName == "" || c.InstanceID == "") {
		return errors.New("请填写小助理账号、地区和实例标识；使用分享凭证时账号可留空")
	}
	return nil
}

// ResourceKey intentionally excludes credentials and config revision. Updating
// a token or threshold must not forget an in-flight cloud operation.
func (c Config) ResourceKey() string {
	resource := []string{c.InstanceType, c.AccountID, c.RegionName, c.InstanceID}
	if c.BindingMode == "profile" {
		resource = []string{c.InstanceType, "profile", c.ProfileID}
	}
	b, _ := json.Marshal(resource)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Instance is an immutable cloud operation target, without authentication secrets.
type Instance struct {
	Type       string `json:"instance_type"`
	AccountID  string `json:"account_id"`
	RegionName string `json:"region_name"`
	ID         string `json:"instance_id"`
}

func (c Config) ForInstance(instance Instance) Config {
	if instance.Type != "" {
		c.InstanceType = instance.Type
	}
	c.BindingMode = "instance"
	c.ProfileID = ""
	c.AccountID, c.RegionName, c.InstanceID = instance.AccountID, instance.RegionName, instance.ID
	return c
}
