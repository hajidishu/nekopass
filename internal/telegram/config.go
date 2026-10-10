package telegram

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const MaxID int64 = (1 << 52) - 1
const DeniedText = "你当前不是管理员，请在面板上将当前tg账号填入面板中"

type Config struct {
	Generation          int64   `json:"-"`
	Enabled             bool    `json:"enabled"`
	Token               string  `json:"token"`
	AdminIDs            []int64 `json:"admin_ids"`
	NotificationChatIDs []int64 `json:"notification_chat_ids"`
	StatisticsDays      int     `json:"statistics_days"`
}

func DefaultConfig() Config {
	return Config{AdminIDs: []int64{}, NotificationChatIDs: []int64{}, StatisticsDays: 7}
}

var tokenPattern = regexp.MustCompile(`^[1-9][0-9]{3,15}:[A-Za-z0-9_-]{20,128}$`)

func (c *Config) Normalize() error {
	if c.StatisticsDays == 0 {
		c.StatisticsDays = 7
	}
	c.Token = strings.TrimSpace(c.Token)
	if c.Enabled && c.Token == "" {
		return errors.New("启用 Telegram Bot 前请填写 Bot 密钥")
	}
	if c.Token != "" {
		if !tokenPattern.MatchString(c.Token) {
			return errors.New("Telegram Bot 密钥格式无效")
		}
		id, err := strconv.ParseInt(strings.SplitN(c.Token, ":", 2)[0], 10, 64)
		if err != nil || id > MaxID {
			return errors.New("Telegram Bot ID 无效")
		}
	}
	if len(c.AdminIDs) > 100 || len(c.NotificationChatIDs) > 100 {
		return errors.New("Telegram 管理员和通知目标各最多 100 个")
	}
	for _, id := range c.AdminIDs {
		if id <= 0 || id > MaxID {
			return errors.New("管理员 Telegram 用户 ID 须为正整数")
		}
	}
	for _, id := range c.NotificationChatIDs {
		if id == 0 || id > MaxID || id < -MaxID {
			return errors.New("Telegram 通知 Chat ID 无效")
		}
	}
	if c.StatisticsDays < 1 || c.StatisticsDays > 90 {
		return errors.New("IP 变更统计周期须为 1–90 天")
	}
	c.AdminIDs = append([]int64{}, c.AdminIDs...)
	slices.Sort(c.AdminIDs)
	c.AdminIDs = slices.Compact(c.AdminIDs)
	c.NotificationChatIDs = append([]int64{}, c.NotificationChatIDs...)
	slices.Sort(c.NotificationChatIDs)
	c.NotificationChatIDs = slices.Compact(c.NotificationChatIDs)
	return nil
}

func (c Config) Allows(user User, chat Chat) bool {
	return c.Enabled && !user.IsBot && user.ID > 0 && chat.Type == "private" && chat.ID == user.ID && slices.Contains(c.AdminIDs, user.ID)
}
