package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/telegram"
	"net/netip"
	"time"
)

func telegramDeliveryHash(c telegram.Config) string {
	data, _ := json.Marshal(struct {
		Token      string
		Chats      []int64
		Generation int64
	}{c.Token, c.NotificationChatIDs, c.Generation})
	return Hash(string(data))
}
func validReportedIP(s string, v6 bool) bool {
	if s == "" {
		return true
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.Is6() == v6 && a.IsGlobalUnicast() && !a.IsPrivate()
}
func recordNodeIPs(ctx context.Context, tx pgx.Tx, node, generation, checked int64, v4, v6, state, record string, settings SystemSettings) error {
	if checked <= 0 || v4 == "" && v6 == "" && state == "off" {
		return nil
	}
	if _, err := tx.Exec(ctx, "INSERT INTO node_ip_state(node_id) VALUES($1) ON CONFLICT DO NOTHING", node); err != nil {
		return err
	}
	var oldGen, oldChecked int64
	var old4, old6, oldState string
	if err := tx.QueryRow(ctx, "SELECT generation,checked_unix,ipv4,ipv6,ddns_state FROM node_ip_state WHERE node_id=$1 FOR UPDATE", node).Scan(&oldGen, &oldChecked, &old4, &old6, &oldState); err != nil {
		return err
	}
	if generation == oldGen && checked <= oldChecked {
		return nil
	}
	if v4 == "" {
		v4 = old4
	}
	if v6 == "" {
		v6 = old6
	}
	changed := old4 != "" && v4 != old4 || old6 != "" && v6 != old6
	failure := state == "error" || state == "partial"
	oldFailure := oldState == "error" || oldState == "partial"
	kind := ""
	if changed {
		kind = "ip_change"
	} else if failure && !oldFailure {
		kind = "ddns_error"
	} else if oldFailure && state == "ok" {
		kind = "ddns_recovered"
	}
	if _, err := tx.Exec(ctx, "UPDATE node_ip_state SET generation=$2,checked_unix=$3,ipv4=$4,ipv6=$5,ddns_state=$6 WHERE node_id=$1", node, generation, checked, v4, v6, state); err != nil {
		return err
	}
	if kind == "" {
		return nil
	}
	var event int64
	if err := tx.QueryRow(ctx, "INSERT INTO node_ip_events(node_id,kind,old_ipv4,new_ipv4,old_ipv6,new_ipv6,record_name,ddns_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id", node, kind, old4, v4, old6, v6, record, state).Scan(&event); err != nil {
		return err
	}
	cfg := settings.Telegram
	if cfg.Normalize() != nil || !cfg.Enabled || cfg.Token == "" {
		return nil
	}
	for _, chat := range cfg.NotificationChatIDs {
		if _, err := tx.Exec(ctx, "INSERT INTO telegram_deliveries(event_id,chat_id,config_hash) VALUES($1,$2,$3)", event, chat, telegramDeliveryHash(cfg)); err != nil {
			return err
		}
	}
	return nil
}

func acceptPublicIPReport(ctx context.Context, tx pgx.Tx, node int64, r *pb.PublicIPStatus, settings SystemSettings) error {
	if r == nil || !settings.Telegram.Enabled || settings.Telegram.Token == "" || len(settings.Telegram.NotificationChatIDs) == 0 {
		return nil
	}
	var enabled bool
	if err := tx.QueryRow(ctx, "SELECT COALESCE((SELECT config->>'enabled'='true' FROM node_ddns WHERE node_id=$1),false)", node).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return nil
	}
	if r.CheckedUnix <= 0 || !validReportedIP(r.Ipv4, false) || !validReportedIP(r.Ipv6, true) {
		return errors.New("公网 IP 上报无效")
	}
	return recordNodeIPs(ctx, tx, node, 0, r.CheckedUnix, r.Ipv4, r.Ipv6, "off", "", settings)
}

func (s *Server) sendTelegramNotifications(ctx context.Context, api telegram.API, token string) error {
	rows, err := s.Pool.Query(ctx, `SELECT e.id,e.node_id,d.chat_id,e.kind,n.name,e.old_ipv4,e.new_ipv4,e.old_ipv6,e.new_ipv6,e.record_name,e.ddns_state,e.created_at,d.config_hash,d.attempts FROM telegram_deliveries d JOIN node_ip_events e ON e.id=d.event_id JOIN nodes n ON n.id=e.node_id WHERE d.state='queued' AND d.next_attempt_at<=now() ORDER BY e.id,d.chat_id LIMIT 10`)
	if err != nil {
		return err
	}
	var events []telegramEvent
	for rows.Next() {
		var e telegramEvent
		if err = rows.Scan(&e.ID, &e.NodeID, &e.ChatID, &e.Kind, &e.Name, &e.Old4, &e.New4, &e.Old6, &e.New6, &e.Record, &e.State, &e.Created, &e.ConfigHash, &e.Attempts); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, e := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.settingsMu.Lock()
		cfg, readErr := s.readSettings(ctx)
		if readErr != nil {
			s.settingsMu.Unlock()
			return readErr
		}
		_ = cfg.Telegram.Normalize()
		if !cfg.Telegram.Enabled || cfg.Telegram.Token != token || telegramDeliveryHash(cfg.Telegram) != e.ConfigHash || time.Since(e.Created) > 24*time.Hour {
			s.settingsMu.Unlock()
			_, err = s.Pool.Exec(ctx, "UPDATE telegram_deliveries SET state='canceled' WHERE event_id=$1 AND chat_id=$2", e.ID, e.ChatID)
			if err != nil {
				return err
			}
			continue
		}
		if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM node_ip_events WHERE node_id=$1 AND kind='ip_change' AND created_at>=now()-make_interval(days=>$2)", e.NodeID, cfg.Telegram.StatisticsDays).Scan(&e.Changes); err != nil {
			s.settingsMu.Unlock()
			return err
		}
		sendCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		sendErr := api.Send(sendCtx, e.ChatID, formatTelegramEvent(e, cfg.Telegram.StatisticsDays), nil)
		cancel()
		s.settingsMu.Unlock()
		state := "sent"
		delay := min(3600, 15*(1<<min(e.Attempts, 7)))
		if sendErr != nil {
			state = "queued"
			if e.Attempts >= 7 {
				state = "failed"
			}
			var apiErr *telegram.APIError
			if errors.As(sendErr, &apiErr) {
				if apiErr.Code == 400 || apiErr.Code == 401 || apiErr.Code == 403 {
					state = "failed"
				}
				if apiErr.Code == 429 {
					delay = max(delay, min(3600, apiErr.RetryAfter))
				}
			}
		}
		if _, err = s.Pool.Exec(ctx, "UPDATE telegram_deliveries SET state=$3,attempts=attempts+1,next_attempt_at=now()+make_interval(secs=>$4) WHERE event_id=$1 AND chat_id=$2", e.ID, e.ChatID, state, delay); err != nil {
			return err
		}
	}
	return nil
}
