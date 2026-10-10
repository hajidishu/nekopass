package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/nekopass/nekopass/internal/telegram"
)

type telegramTestAPI struct {
	fakeTelegram
	mu   sync.Mutex
	sent []string
}

func (f *telegramTestAPI) Chat(_ context.Context, id int64) (telegram.Chat, error) {
	if id == 45 {
		return telegram.Chat{}, &telegram.APIError{Code: 403}
	}
	return f.fakeTelegram.Chat(context.Background(), id)
}
func (f *telegramTestAPI) Send(_ context.Context, _ int64, text string, _ *telegram.Keyboard) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, text)
	return nil
}

func TestTelegramManualTestAuthorizationAndDisabledDraft(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	api := &telegramTestAPI{}
	f.s.telegramFactory = func(token string) telegram.API {
		if token != cfg.Telegram.Token {
			t.Error("wrong test token")
		}
		return api
	}
	draft := cfg.Telegram
	draft.Enabled = false
	draft.NotificationChatIDs = []int64{-100123, 43, 45}
	body := map[string]any{"telegram": draft}
	securityStatus(t, f.request(0, "admin/settings/telegram/test", "POST", body), 401)
	securityStatus(t, f.request(f.user, "admin/settings/telegram/test", "POST", body), 403)
	if len(api.sent) != 0 {
		t.Fatal("unauthorized test sent")
	}
	w := f.request(f.admin, "admin/settings/telegram/test", "POST", body)
	securityStatus(t, w, 200)
	var result struct {
		Sent, Failed int
		Results      []telegramTestResult
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Sent != 2 || result.Failed != 1 || len(result.Results) != 3 {
		t.Fatal("incorrect partial results", w.Body.String())
	}
	if len(api.sent) != 2 {
		t.Fatal("missing sends")
	}
	for _, text := range api.sent {
		if !strings.Contains(text, "Chat ID") || !strings.Contains(text, "UTC+8") || strings.Contains(text, cfg.Telegram.Token) || strings.Contains(text, cfg.SiteName) {
			t.Fatal("incorrect or sensitive test body")
		}
	}
	saved, err := f.s.readSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Telegram.Enabled || len(saved.Telegram.NotificationChatIDs) != 2 {
		t.Fatal("test changed saved settings")
	}
	draft.NotificationChatIDs = nil
	securityStatus(t, f.request(f.admin, "admin/settings/telegram/test", "POST", map[string]any{"telegram": draft}), 400)
	if strings.Contains(telegramTestError(errors.New(cfg.Telegram.Token)), cfg.Telegram.Token) {
		t.Fatal("credential leaked")
	}
}

func TestTelegramDisableRetainsConfigStopsQueriesAndInvalidatesDelivery(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	ctx := context.Background()
	oldHash := telegramDeliveryHash(cfg.Telegram)
	cfg.Telegram.Enabled = false
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", cfg), 200)
	saved, err := f.s.readSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Telegram.Enabled || saved.Telegram.Token != cfg.Telegram.Token || len(saved.Telegram.AdminIDs) != 1 {
		t.Fatal("disable lost configuration")
	}
	api := &fakeTelegram{}
	for _, u := range []telegram.Update{
		{Message: &telegram.Message{From: &telegram.User{ID: 42}, Chat: telegram.Chat{ID: 42, Type: "private"}, Text: "/start"}},
		{Callback: &telegram.Callback{ID: "invalid", From: telegram.User{ID: 42}, InlineMessageID: "invalid"}},
	} {
		if err := f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, telegram.User{ID: 12345, IsBot: true}, u, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(api.texts) != 0 {
		t.Fatal("disabled bot responded")
	}
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", "fixture-switch-"+Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = recordNodeIPs(ctx, tx, node, 1, 100, "1.1.1.1", "", "ok", "", saved); err != nil {
		t.Fatal(err)
	}
	if err = recordNodeIPs(ctx, tx, node, 1, 101, "2.2.2.2", "", "ok", "", saved); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err = f.p.QueryRow(ctx, "SELECT count(*) FROM telegram_deliveries d JOIN node_ip_events e ON e.id=d.event_id WHERE e.node_id=$1", node).Scan(&queued); err != nil || queued != 0 {
		t.Fatal("disabled bot queued notifications", err, queued)
	}
	cfg.Telegram.Enabled = true
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", cfg), 200)
	enabled, err := f.s.readSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Telegram.Enabled || telegramDeliveryHash(enabled.Telegram) == oldHash {
		t.Fatal("enable reused old delivery generation")
	}
	// An old settings snapshot can commit after disable canceled the queue.
	// Re-enabling must still reject such late arrivals.
	var event int64
	if err = f.p.QueryRow(ctx, "INSERT INTO node_ip_events(node_id,kind,old_ipv4,new_ipv4,ddns_state,record_name) VALUES($1,'ip_change','2.2.2.2','3.3.3.3','ok','') RETURNING id", node).Scan(&event); err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Exec(ctx, "INSERT INTO telegram_deliveries(event_id,chat_id,config_hash) VALUES($1,43,$2)", event, oldHash); err != nil {
		t.Fatal(err)
	}
	if err = f.s.sendTelegramNotifications(ctx, api, cfg.Telegram.Token); err != nil {
		t.Fatal(err)
	}
	if len(api.texts) != 0 {
		t.Fatal("old notification replayed after re-enable")
	}
	var state string
	if err = f.p.QueryRow(ctx, "SELECT state FROM telegram_deliveries WHERE event_id=$1", event).Scan(&state); err != nil || state != "canceled" {
		t.Fatal("old delivery not canceled", err, state)
	}
	generation := enabled.Telegram.Generation
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", enabled), 200)
	unchanged, err := f.s.readSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Telegram.Generation != generation {
		t.Fatal("unchanged settings invalidated deliveries")
	}
}
