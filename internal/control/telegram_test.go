package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/telegram"
)

type fakeTelegram struct {
	texts     []string
	chats     []int64
	edits     int
	keyboards []*telegram.Keyboard
}

func (f *fakeTelegram) Me(context.Context) (telegram.User, error) {
	return telegram.User{ID: 12345, IsBot: true}, nil
}
func (f *fakeTelegram) Chat(_ context.Context, id int64) (telegram.Chat, error) {
	kind := "private"
	if id < 0 {
		kind = "supergroup"
	}
	return telegram.Chat{ID: id, Type: kind}, nil
}
func (f *fakeTelegram) Prepare(context.Context) error                             { return nil }
func (f *fakeTelegram) Updates(context.Context, int64) ([]telegram.Update, error) { return nil, nil }
func (f *fakeTelegram) Send(_ context.Context, chat int64, text string, k *telegram.Keyboard) error {
	f.texts = append(f.texts, text)
	f.chats = append(f.chats, chat)
	f.keyboards = append(f.keyboards, k)
	return nil
}
func (f *fakeTelegram) Edit(ctx context.Context, chat, message int64, text string, k *telegram.Keyboard) error {
	f.edits++
	return f.Send(ctx, chat, text, k)
}
func (f *fakeTelegram) Answer(_ context.Context, _ string, text string) error {
	if text != "" {
		f.texts = append(f.texts, text)
	}
	return nil
}
func telegramFixtureConfig() telegram.Config {
	c := telegram.DefaultConfig()
	c.Enabled = true
	c.Token = "12345:" + strings.Repeat("x", 35)
	c.AdminIDs = []int64{42}
	c.NotificationChatIDs = []int64{43, -100123}
	return c
}
func saveTelegramFixture(t *testing.T, f *securityFixture) SystemSettings {
	t.Helper()
	ctx := context.Background()
	var original []byte
	if err := f.p.QueryRow(ctx, "SELECT config FROM site_settings WHERE id=1").Scan(&original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", original) })
	v := defaultSettings()
	v.Telegram = telegramFixtureConfig()
	v.SiteName = "fixture-panel"
	b, _ := json.Marshal(v)
	if _, err := f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", b); err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.readSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestTelegramPrivateAuthPaginationAndSettingsSecrecy(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	api := &fakeTelegram{}
	ctx := context.Background()
	bot := telegram.User{ID: 12345, IsBot: true}
	var baseline int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM nodes").Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	startPage := (baseline + 1) / 2
	for i := 0; i < 3+baseline%2; i++ {
		var id int64
		if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", fmt.Sprintf("fixture-tg-%d-%s", i, Secret()), Hash(Secret())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", id) })
	}
	update := func(user, chat int64, kind string) telegram.Update {
		return telegram.Update{Message: &telegram.Message{ID: 1, From: &telegram.User{ID: user}, Chat: telegram.Chat{ID: chat, Type: kind}, Text: "/start"}}
	}
	for _, u := range []telegram.Update{update(43, 43, "private"), update(42, -100123, "supergroup"), update(42, 43, "private"), update(42, 42, "group")} {
		before := len(api.texts)
		if err := f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, bot, u, nil); err != nil {
			t.Fatal(err)
		}
		if len(api.texts) != before+1 || !strings.Contains(api.texts[before], telegram.DeniedText) || strings.Contains(api.texts[before], "fixture-panel") {
			t.Fatal("unauthorized access disclosed panel")
		}
	}
	if err := f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, bot, update(42, 42, "private"), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(api.texts[len(api.texts)-1], "fixture-panel") || strings.Contains(api.texts[len(api.texts)-1], cfg.Telegram.Token) {
		t.Fatal("home not authorized or secret leaked")
	}
	msg := &telegram.Message{ID: 2, Date: 1, From: &bot, Chat: telegram.Chat{ID: 42, Type: "private"}}
	u := telegram.Update{Callback: &telegram.Callback{ID: "fixture", From: telegram.User{ID: 42}, Message: msg, Data: fmt.Sprintf("nodes:%d", startPage)}}
	if err := f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, bot, u, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Count(api.texts[len(api.texts)-1], "fixture-tg-") != 2 || api.edits != 1 {
		t.Fatal("nodes are not two per page")
	}
	u.Callback.Data = fmt.Sprintf("nodes:%d", startPage+1)
	if err := f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, bot, u, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Count(api.texts[len(api.texts)-1], "fixture-tg-") != 1 {
		t.Fatal("second page not correct")
	}
	u.Callback.From.ID = 43
	before := api.edits
	f.s.handleTelegramUpdate(ctx, api, cfg.Telegram.Token, bot, u, nil)
	if api.edits != before {
		t.Fatal("notification recipient accessed administrator callback")
	}
	for _, path := range []string{"site", "registration/config", "rule-nodes", "node-status"} {
		w := f.request(f.user, path, "GET", nil)
		if strings.Contains(w.Body.String(), cfg.Telegram.Token) {
			t.Fatal("bot credential leaked into user API", path)
		}
	}
	securityStatus(t, f.request(f.user, "admin/settings", "GET", nil), 403)
}

func TestTelegramIPCountDedupRecoveryAndRevokedTarget(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", "fixture-ip-change-"+Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	d := ddns.DefaultConfig()
	d.Enabled = true
	d.Token = "fixture-ddns-key"
	d.RecordName = "dynamic.example.test"
	raw, _ := json.Marshal(d)
	if _, err := f.p.Exec(ctx, "INSERT INTO node_ddns(node_id,generation,config) VALUES($1,1,$2)", node, raw); err != nil {
		t.Fatal(err)
	}
	apply := func(r *pb.DDNSStatus) {
		t.Helper()
		tx, err := f.p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err = acceptDDNSReport(ctx, tx, node, r); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	apply(&pb.DDNSStatus{Generation: 1, State: "ok", Ipv4: "1.1.1.1", CheckedUnix: 100})
	r := &pb.DDNSStatus{Generation: 1, State: "error", Ipv4: "1.1.1.1", ObservedIpv4: "2.2.2.2", CheckedUnix: 101, Error: "fixture-private-key-do-not-send"}
	apply(r)
	apply(r)
	apply(&pb.DDNSStatus{Generation: 1, State: "ok", Ipv4: "2.2.2.2", ObservedIpv4: "2.2.2.2", CheckedUnix: 102})
	var changes, events int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FILTER(WHERE kind='ip_change'),count(*) FROM node_ip_events WHERE node_id=$1", node).Scan(&changes, &events); err != nil || changes != 1 || events != 2 {
		t.Fatal("duplicate or recovery counted as IP change", err, changes, events)
	}
	api := &fakeTelegram{}
	if err := f.s.sendTelegramNotifications(ctx, api, cfg.Telegram.Token); err != nil {
		t.Fatal(err)
	}
	if len(api.texts) != 4 {
		t.Fatal("configured targets not delivered", len(api.texts))
	}
	for _, text := range api.texts {
		if !strings.Contains(text, "近 7 天已更换 1 次 IP") || strings.Contains(text, "fixture-private-key") || strings.Contains(text, d.Token) {
			t.Fatal("statistics missing or DDNS secret leaked")
		}
	}
	if !strings.Contains(api.texts[0], "同步失败") || !strings.Contains(api.texts[2], "已自动同步") {
		t.Fatal("DDNS result misrepresented")
	}
	apply(&pb.DDNSStatus{Generation: 1, State: "ok", Ipv4: "3.3.3.3", CheckedUnix: 103})
	cfg.Telegram.NotificationChatIDs = []int64{44}
	b, _ := json.Marshal(cfg)
	f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", b)
	before := len(api.texts)
	if err := f.s.sendTelegramNotifications(ctx, api, cfg.Telegram.Token); err != nil {
		t.Fatal(err)
	}
	if len(api.texts) != before {
		t.Fatal("revoked or newly added target received historical notification")
	}
	if _, err := f.p.Exec(ctx, "UPDATE node_ip_events SET created_at=now()-interval '8 days' WHERE node_id=$1 AND kind='ip_change'", node); err != nil {
		t.Fatal(err)
	}
	var recent int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM node_ip_events WHERE node_id=$1 AND kind='ip_change' AND created_at>=now()-interval '7 days'", node).Scan(&recent); err != nil || recent != 0 {
		t.Fatal("statistics not rolling", err)
	}
}

func TestTelegramFormattingEscapesAndKeyboard(t *testing.T) {
	e := telegramEvent{Name: "<script>&", Kind: "ip_change", Old4: "1.1.1.1", New4: "2.2.2.2", Record: "a.example", State: "ok", Changes: 4, Created: time.Now()}
	text := formatTelegramEvent(e, 7)
	if strings.Contains(text, "<script>") || !strings.Contains(text, "&lt;script&gt;") || !strings.Contains(text, "近 7 天已更换 4 次 IP") {
		t.Fatal("unsafe or incomplete notification")
	}
	if len(telegramNodesKeyboard(0, 2).Rows) != 2 || len(telegramHomeKeyboard("https://panel.example.test").Rows) != 3 {
		t.Fatal("keyboard incomplete")
	}
}

type pollingTelegram struct {
	fakeTelegram
	offset atomic.Int64
	ready  chan struct{}
}

func (p *pollingTelegram) Updates(ctx context.Context, offset int64) ([]telegram.Update, error) {
	p.offset.Store(offset)
	close(p.ready)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestTelegramSessionPersistsOffsetAndCancels(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	ctx := context.Background()
	var botID, offset int64
	var seen time.Time
	if err := f.p.QueryRow(ctx, "SELECT bot_id,update_offset,last_update_at FROM telegram_state WHERE id=1").Scan(&botID, &offset, &seen); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Exec(ctx, "UPDATE telegram_state SET bot_id=$1,update_offset=$2,last_update_at=$3 WHERE id=1", botID, offset, seen)
	})
	for _, v := range []struct {
		age  string
		want int64
	}{{"1 hour", 77}, {"8 days", 0}} {
		if _, err := f.p.Exec(ctx, "UPDATE telegram_state SET bot_id=12345,update_offset=77,last_update_at=now()-$1::interval WHERE id=1", v.age); err != nil {
			t.Fatal(err)
		}
		api := &pollingTelegram{ready: make(chan struct{})}
		f.s.telegramFactory = func(string) telegram.API { return api }
		run, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); f.s.telegramSession(run, cfg.Telegram) }()
		select {
		case <-api.ready:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("polling did not start")
		}
		if api.offset.Load() != v.want {
			cancel()
			t.Fatal("offset not restored or idle state not reset", api.offset.Load(), v.want)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("polling did not stop")
		}
	}
}

func TestPublicIPNotificationWithoutDDNS(t *testing.T) {
	f := newSecurityFixture(t)
	cfg := saveTelegramFixture(t, f)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", "fixture-public-"+Secret(), Hash(Secret())).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	apply := func(ip string, checked int64, wantError bool) {
		t.Helper()
		tx, err := f.p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		err = acceptPublicIPReport(ctx, tx, node, &pb.PublicIPStatus{Ipv4: ip, CheckedUnix: checked}, cfg)
		if wantError {
			if err == nil {
				t.Fatal("private IP accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	apply("1.1.1.1", 100, false)
	apply("2.2.2.2", 101, false)
	apply("2.2.2.2", 101, false)
	apply("127.0.0.1", 102, true)
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM node_ip_events WHERE node_id=$1 AND kind='ip_change'", node).Scan(&count); err != nil || count != 1 {
		t.Fatal("public IP count invalid", err, count)
	}
	api := &fakeTelegram{}
	if err := f.s.sendTelegramNotifications(ctx, api, cfg.Telegram.Token); err != nil {
		t.Fatal(err)
	}
	if len(api.texts) != 2 || !strings.Contains(api.texts[0], "未启用") {
		t.Fatal("non-DDNS notification not sent")
	}
}
