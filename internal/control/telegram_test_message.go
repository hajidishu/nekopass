package control

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/nekopass/nekopass/internal/telegram"
)

type telegramTestResult struct {
	ChatID        int64  `json:"chat_id"`
	CurrentChatID int64  `json:"current_chat_id,omitempty"`
	ChatType      string `json:"chat_type,omitempty"`
	Sent          bool   `json:"sent"`
	Error         string `json:"error,omitempty"`
}

func telegramTestError(err error) string {
	if e, ok := err.(*telegram.APIError); ok {
		switch e.Code {
		case 400:
			return "聊天不存在或 Bot 未加入，请检查 Chat ID"
		case 401:
			return "Bot 密钥无效"
		case 403:
			return "Bot 无权发送，请先私聊 /start 或将 Bot 加入群组"
		case 429:
			return "Telegram 请求限流，请稍后重试"
		}
	}
	return "暂时无法发送，请稍后重试"
}

func (s *Server) testTelegramMessage(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Telegram *telegram.Config `json:"telegram"`
	}
	if !decode(w, r, &in) {
		return
	}
	var cfg telegram.Config
	if in.Telegram != nil {
		cfg = *in.Telegram
	} else {
		settings, err := s.readSettings(r.Context())
		if err != nil {
			s.dbError(w, err)
			return
		}
		cfg = settings.Telegram
	}
	if err := cfg.Normalize(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if cfg.Token == "" || len(cfg.NotificationChatIDs) == 0 {
		fail(w, 400, "请填写 Bot 密钥和至少一个通知目标 Chat ID")
		return
	}
	// A manually requested test is independent of the background enable switch.
	// Only numeric destinations supplied by the panel administrator are used.
	api := s.telegramFactory(cfg.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	results := make([]telegramTestResult, len(cfg.NotificationChatIDs))
	jobs := make(chan int, len(results))
	for i, id := range cfg.NotificationChatIDs {
		results[i] = telegramTestResult{ChatID: id, Error: "发送超时，请稍后重试"}
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	for worker := 0; worker < min(4, len(results)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := &results[index]
				task, finish := context.WithTimeout(ctx, 8*time.Second)
				chat, err := api.Chat(task, result.ChatID)
				if err == nil {
					kind := map[string]string{"private": "私聊", "group": "群组", "supergroup": "群组", "channel": "频道"}[chat.Type]
					if kind == "" || chat.ID == 0 || chat.ID > telegram.MaxID || chat.ID < -telegram.MaxID {
						err = fmt.Errorf("invalid chat")
					} else {
						result.CurrentChatID, result.ChatType = chat.ID, chat.Type
						label := "私聊 ID"
						if chat.Type != "private" {
							label = "群组 ID"
						}
						if chat.Type == "channel" {
							label = "频道 ID"
						}
						text := fmt.Sprintf("<b>🧪 Nekopass · Telegram 测试消息</b>\n━━━━━━━━━━━━━━\n聊天类型  %s\n%s  <code>%d</code>\nChat ID  <code>%d</code>\n测试时间  %s (UTC+8)\n━━━━━━━━━━━━━━\n✅ 测试消息发送成功", kind, label, chat.ID, chat.ID, time.Now().In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02 15:04:05"))
						err = api.Send(task, chat.ID, text, nil)
					}
				}
				finish()
				if err != nil {
					result.Error = telegramTestError(err)
				} else {
					result.Sent = true
					result.Error = ""
				}
			}
		}()
	}
	wg.Wait()
	sent := 0
	for _, result := range results {
		if result.Sent {
			sent++
		}
	}
	writeJSON(w, 200, map[string]any{"sent": sent, "failed": len(results) - sent, "results": results})
}
