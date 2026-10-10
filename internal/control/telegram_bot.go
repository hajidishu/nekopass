package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nekopass/nekopass/internal/probe"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/release"
	"github.com/nekopass/nekopass/internal/telegram"
	"golang.org/x/time/rate"
)

type telegramStatus struct {
	State    string `json:"state"`
	Username string `json:"username,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (s *Server) telegramInfo() telegramStatus {
	if v := s.telegramStatus.Load(); v != nil {
		return *v
	}
	return telegramStatus{State: "starting"}
}
func (s *Server) samplePanelProbe(ctx context.Context) {
	sampler := probe.NewSampler()
	for ctx.Err() == nil {
		s.panelProbe.Store(sampler.Sample(&pb.NodeConfig{DiskPath: "/"}))
		if !telegramWait(ctx, 5*time.Second) {
			return
		}
	}
}
func telegramWait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Server) RunTelegramBot(ctx context.Context) {
	var running telegram.Config
	var stop context.CancelFunc
	var done chan struct{}
	defer func() {
		if stop != nil {
			stop()
			<-done
		}
	}()
	for ctx.Err() == nil {
		settings, err := s.readSettings(ctx)
		if err != nil {
			if !telegramWait(ctx, 2*time.Second) {
				return
			}
			continue
		}
		cfg := settings.Telegram
		if cfg.Normalize() != nil {
			cfg.Token = ""
		}
		if stop != nil && !reflect.DeepEqual(cfg, running) {
			stop()
			<-done
			stop = nil
		}
		if stop == nil {
			if !cfg.Enabled {
				s.telegramStatus.Store(&telegramStatus{State: "disabled"})
			} else if cfg.Token == "" {
				s.telegramStatus.Store(&telegramStatus{State: "not_configured"})
			} else {
				running = cfg
				session, cancel := context.WithCancel(ctx)
				stop = cancel
				done = make(chan struct{})
				go func(done chan struct{}) {
					defer close(done)
					var samplers sync.WaitGroup
					samplers.Add(1)
					go func() { defer samplers.Done(); s.samplePanelProbe(session) }()
					s.telegramSession(session, cfg)
					cancel()
					samplers.Wait()
				}(done)
			}
		}
		if !telegramWait(ctx, 2*time.Second) {
			return
		}
	}
}

func (s *Server) telegramSession(ctx context.Context, cfg telegram.Config) {
	api := s.telegramFactory(cfg.Token)
	for ctx.Err() == nil {
		start, cancel := context.WithTimeout(ctx, 10*time.Second)
		bot, err := api.Me(start)
		if err == nil && (!bot.IsBot || bot.ID <= 0) {
			err = errors.New("Telegram Bot 身份无效")
		}
		if err == nil {
			err = api.Prepare(start)
		}
		cancel()
		if err != nil {
			s.telegramStatus.Store(&telegramStatus{State: "error", Error: telegramSafeError(err)})
			if !telegramWait(ctx, 10*time.Second) {
				return
			}
			continue
		}
		var offset int64
		var lastUpdate time.Time
		err = s.Pool.QueryRow(ctx, "UPDATE telegram_state SET update_offset=CASE WHEN bot_id=$1 AND last_update_at>now()-interval '6 days' THEN update_offset ELSE 0 END,bot_id=$1 WHERE id=1 RETURNING update_offset,last_update_at", bot.ID).Scan(&offset, &lastUpdate)
		if err != nil {
			if !telegramWait(ctx, 3*time.Second) {
				return
			}
			continue
		}
		s.telegramStatus.Store(&telegramStatus{State: "connected", Username: bot.Username})
		worker, cancelWorker := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); s.telegramNotificationLoop(worker, api, cfg.Token) }()
		denied := rate.NewLimiter(rate.Every(time.Second), 5)
		for ctx.Err() == nil {
			// Telegram can randomize update IDs after a week with no updates.
			// Its pending queue expires in 24 hours, so an idle reset is safe.
			if time.Since(lastUpdate) > 6*24*time.Hour {
				offset = 0
			}
			updates, pollErr := api.Updates(ctx, offset)
			if pollErr != nil {
				s.telegramStatus.Store(&telegramStatus{State: "error", Username: bot.Username, Error: telegramSafeError(pollErr)})
				if !telegramWait(ctx, 3*time.Second) {
					break
				}
				continue
			}
			s.telegramStatus.Store(&telegramStatus{State: "connected", Username: bot.Username})
			received := len(updates) > 0
			if received {
				lastUpdate = time.Now()
			}
			for _, u := range updates {
				if u.ID < offset || u.ID < 0 || u.ID >= 1<<52 {
					continue
				}
				_ = s.handleTelegramUpdate(ctx, api, cfg.Token, bot, u, denied)
				offset = max(offset, u.ID+1)
			}
			for ctx.Err() == nil {
				_, err = s.Pool.Exec(ctx, "UPDATE telegram_state SET update_offset=$2,last_update_at=CASE WHEN $3 THEN now() ELSE last_update_at END WHERE id=1 AND bot_id=$1", bot.ID, offset, received)
				if err == nil {
					break
				}
				if !telegramWait(ctx, 2*time.Second) {
					break
				}
			}
		}
		cancelWorker()
		wg.Wait()
	}
}
func telegramSafeError(err error) string {
	var e *telegram.APIError
	if errors.As(err, &e) {
		switch e.Code {
		case 401:
			return "Bot 密钥无效，请在面板重新配置"
		case 409:
			return "Bot 正在被其他实例使用"
		case 429:
			return "Telegram 请求限流，正在重试"
		}
		return fmt.Sprintf("Telegram 请求失败（%d）", e.Code)
	}
	return "Telegram 暂时无法连接，正在重试"
}
func (s *Server) telegramNotificationLoop(ctx context.Context, api telegram.API, token string) {
	lastCleanup := time.Time{}
	for ctx.Err() == nil {
		_ = s.sendTelegramNotifications(ctx, api, token)
		if time.Since(lastCleanup) > time.Hour {
			_, _ = s.Pool.Exec(ctx, "DELETE FROM node_ip_events WHERE created_at<now()-interval '90 days'")
			lastCleanup = time.Now()
		}
		if !telegramWait(ctx, 3*time.Second) {
			return
		}
	}
}

func (s *Server) handleTelegramUpdate(ctx context.Context, api telegram.API, token string, bot telegram.User, u telegram.Update, denied *rate.Limiter) error {
	settings, err := s.readSettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Telegram.Enabled || settings.Telegram.Token != token {
		return nil
	}
	var from telegram.User
	var message *telegram.Message
	action := "home"
	callback := ""
	if u.Callback != nil {
		c := u.Callback
		from = c.From
		message = c.Message
		action = c.Data
		callback = c.ID
		if message == nil || c.InlineMessageID != "" || message.From == nil || message.From.ID != bot.ID || !message.From.IsBot || message.Date == 0 {
			return api.Answer(ctx, c.ID, telegram.DeniedText)
		}
	} else if u.Message != nil {
		message = u.Message
		if message.From == nil {
			return nil
		}
		from = *message.From
	} else {
		return nil
	}
	allowed := settings.Telegram.Allows(from, message.Chat) && message.SenderChat == nil && len(message.ForwardOrigin) == 0
	if !allowed {
		if denied != nil && !denied.Allow() {
			return nil
		}
		if callback != "" {
			return api.Answer(ctx, callback, telegram.DeniedText)
		}
		text := telegram.DeniedText
		if message.Chat.Type == "private" && message.Chat.ID == from.ID {
			text += fmt.Sprintf("\n你的 Telegram 用户 ID：<code>%d</code>", from.ID)
		} else if message.Chat.Type == "group" || message.Chat.Type == "supergroup" {
			text += fmt.Sprintf("\n当前群组 Chat ID：<code>%d</code>\n管理功能仅支持管理员私聊。", message.Chat.ID)
		}
		return api.Send(ctx, message.Chat.ID, text, nil)
	}
	if callback == "" {
		fields := strings.Fields(message.Text)
		if len(fields) == 0 {
			return nil
		}
		command := strings.SplitN(fields[0], "@", 2)[0]
		if command != "/start" && command != "/status" && command != "/nodes" {
			return nil
		}
		if command == "/nodes" {
			action = "nodes:0"
		}
	}
	var text string
	var keyboard *telegram.Keyboard
	switch {
	case action == "home":
		text, err = s.telegramHome(ctx, settings)
		keyboard = telegramHomeKeyboard(settings.PanelURL)
	case action == "notifications":
		text = fmt.Sprintf("<b>📬 通知设置</b>\n━━━━━━━━━━━━━━\n已配置 %d 个通知目标\nIP 统计周期：近 %d 天\n\n在面板「系统设置 → Telegram Bot」填写群组或用户的数字 Chat ID。群组只接收通知，管理操作仅限管理员私聊。", len(settings.Telegram.NotificationChatIDs), max(1, settings.Telegram.StatisticsDays))
		keyboard = telegramHomeKeyboard(settings.PanelURL)
	case strings.HasPrefix(action, "nodes:"):
		page, parseErr := strconv.Atoi(strings.TrimPrefix(action, "nodes:"))
		if parseErr != nil || page < 0 || page > 1000000 {
			if callback != "" {
				return api.Answer(ctx, callback, "分页参数无效")
			}
			return nil
		}
		text, keyboard, err = s.telegramNodes(ctx, page)
	default:
		if callback != "" {
			return api.Answer(ctx, callback, "按钮已失效，请重新发送 /start")
		}
		return nil
	}
	if err != nil {
		text = "暂时无法读取面板数据，请稍后重试。"
		keyboard = telegramHomeKeyboard(settings.PanelURL)
	}
	// Settings saves use the same mutex. Recheck immediately before sending data
	// so revocation cannot commit while an authorized send is in flight.
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	latest, readErr := s.readSettings(ctx)
	if readErr != nil {
		return readErr
	}
	if !latest.Telegram.Enabled || latest.Telegram.Token != token {
		return nil
	}
	if !latest.Telegram.Allows(from, message.Chat) {
		if callback != "" {
			return api.Answer(ctx, callback, telegram.DeniedText)
		}
		return api.Send(ctx, message.Chat.ID, telegram.DeniedText, nil)
	}
	send, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if callback != "" {
		_ = api.Answer(send, callback, "")
		return api.Edit(send, message.Chat.ID, message.ID, text, keyboard)
	}
	return api.Send(send, message.Chat.ID, text, keyboard)
}

func (s *Server) telegramHome(ctx context.Context, cfg SystemSettings) (string, error) {
	var users, rules, nodes, online int64
	err := s.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM rules),count(*),count(*) FILTER(WHERE last_seen>now()-interval '12 seconds') FROM nodes").Scan(&users, &rules, &nodes, &online)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("<b>🐾 %s · 面板概览</b>\n━━━━━━━━━━━━━━\n版本  <code>%s</code>\n用户  %d · 规则  %d\n节点  %d / %d 在线\n\n<b>🖥 面板机器</b>\n%s\n━━━━━━━━━━━━━━\n%s (UTC+8)", tgText(cfg.SiteName), tgText(release.Version), users, rules, online, nodes, telegramMetrics(s.panelProbe.Load()), time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02 15:04:05")), nil
}
func (s *Server) telegramNodes(ctx context.Context, page int) (string, *telegram.Keyboard, error) {
	var count int
	if err := s.Pool.QueryRow(ctx, "SELECT count(*) FROM nodes").Scan(&count); err != nil {
		return "", nil, err
	}
	pages := max(1, (count+1)/2)
	page = min(page, pages-1)
	rows, err := s.Pool.Query(ctx, `SELECT name,enabled,COALESCE(last_seen>now()-interval '12 seconds',false),CASE WHEN probe_received_at>now()-make_interval(secs=>GREATEST(probe_interval_seconds*3,15)) THEN probe ELSE NULL END,probe_received_at FROM nodes ORDER BY id LIMIT 2 OFFSET $1`, page*2)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	parts := []string{fmt.Sprintf("<b>📡 节点信息 · %d / %d</b>", page+1, pages)}
	for rows.Next() {
		var name string
		var enabled, online bool
		var data []byte
		var received *time.Time
		if err = rows.Scan(&name, &enabled, &online, &data, &received); err != nil {
			return "", nil, err
		}
		state := "🔴 离线"
		if online {
			state = "🟢 在线"
		}
		if !enabled {
			state = "⚪ 已停用"
		}
		var p *pb.Probe
		if len(data) > 0 {
			_ = json.Unmarshal(data, &p)
		}
		card := "━━━━━━━━━━━━━━\n<b>" + tgText(name) + "</b>  " + state + "\n" + telegramMetrics(p)
		if received != nil {
			card += "\n最近上报  " + received.In(time.FixedZone("UTC+8", 8*3600)).Format("01-02 15:04:05")
		}
		parts = append(parts, card)
	}
	if count == 0 {
		parts = append(parts, "暂无节点")
	}
	parts = append(parts, "\n点击按钮获取最新快照")
	return strings.Join(parts, "\n"), telegramNodesKeyboard(page, pages), rows.Err()
}
