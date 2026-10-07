package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type UserReferralSettings struct {
	Enabled *bool   `json:"enabled"`
	Mode    string  `json:"mode"`
	Rate    *string `json:"rate"`
}

func referralRate(raw string) (int, error) {
	value, err := parseMoney(raw)
	if err != nil || value > 10000 {
		return 0, errors.New("返利比例须为 0–100，最多两位小数")
	}
	return int(value), nil
}

func (v *UserReferralSettings) validate() error {
	if v == nil {
		return nil
	}
	if v.Mode != "inherit" && v.Mode != "first" && v.Mode != "recurring" {
		return errors.New("返利类型无效")
	}
	if v.Rate != nil && *v.Rate != "" {
		_, err := referralRate(*v.Rate)
		return err
	}
	return nil
}

func saveUserReferral(ctx context.Context, tx pgx.Tx, id int64, v *UserReferralSettings) error {
	if v == nil {
		return nil
	}
	var rate *int
	if v.Rate != nil && *v.Rate != "" {
		n, _ := referralRate(*v.Rate)
		rate = &n
	}
	_, err := tx.Exec(ctx, "UPDATE users SET referral_enabled=$2,referral_mode=$3,referral_rate_bps=$4 WHERE id=$1", id, v.Enabled, v.Mode, rate)
	return err
}

// Called only by successful wallet-funded checkout, in the same transaction
// as debit/subscription/order. Never called for recharge or a replayed request.
func creditReferral(ctx context.Context, tx pgx.Tx, buyer, source int64, price int64, plan string) error {
	if price <= 0 {
		return nil
	}
	settings, err := readSystemSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !settings.ReferralEnabled {
		return nil
	}
	var inviter *int64
	if err = tx.QueryRow(ctx, "SELECT inviter_id FROM users WHERE id=$1", buyer).Scan(&inviter); err != nil {
		return err
	}
	if inviter == nil || *inviter == buyer {
		return nil
	}
	var enabled bool
	var individual *bool
	var mode string
	var rate *int
	if err = tx.QueryRow(ctx, "SELECT enabled,referral_enabled,referral_mode,referral_rate_bps FROM users WHERE id=$1 FOR UPDATE", *inviter).Scan(&enabled, &individual, &mode, &rate); err != nil {
		return err
	}
	if !enabled || individual != nil && !*individual {
		return nil
	}
	if mode == "inherit" {
		mode = settings.ReferralMode
	}
	bps, _ := referralRate(settings.ReferralRate)
	if rate != nil {
		bps = *rate
	}
	if mode == "first" {
		var earlier bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM shop_orders WHERE user_id=$1 AND id<>$2 AND status='paid' AND kind IN ('purchase','renewal') AND amount_cents>0)", buyer, source).Scan(&earlier); err != nil {
			return err
		}
		if earlier {
			return nil
		}
	}
	amount := price * int64(bps) / 10000
	if amount == 0 {
		return nil
	}
	balance, err := walletBalanceLocked(ctx, tx, *inviter)
	if err != nil {
		return err
	}
	if amount > maxMoneyCents-balance {
		return errors.New("邀请人余额超出上限")
	}
	var reward int64
	snapshot, _ := json.Marshal(map[string]any{"note": "邀请返利", "source_order_id": source, "rate": formatMoney(int64(bps)), "mode": mode})
	if err = tx.QueryRow(ctx, `INSERT INTO shop_orders(order_no,user_id,kind,plan_name,amount_cents,status,request_key,snapshot,paid_at) VALUES($1,$2,'rebate',$3,$4,'paid',$5,$6,now()) RETURNING id`, "I"+Secret()[:24], *inviter, plan, amount, "referral:"+formatID(source), snapshot).Scan(&reward); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO referral_rewards(source_order_id,inviter_id,invitee_id,reward_order_id,amount_cents,rate_bps,mode) VALUES($1,$2,$3,$4,$5,$6,$7)", source, *inviter, buyer, reward, amount, bps, mode); err != nil {
		return err
	}
	balance += amount
	if _, err = tx.Exec(ctx, "UPDATE wallet_accounts SET balance_cents=$2,updated_at=now() WHERE user_id=$1", *inviter, balance); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO wallet_entries(user_id,order_id,amount_cents,balance_after_cents,kind,note) VALUES($1,$2,$3,$4,'rebate','邀请返利')`, *inviter, reward, amount, balance)
	return err
}

func (s *Server) referrals(w http.ResponseWriter, r *http.Request) {
	v, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	if !v.ReferralEnabled {
		writeJSON(w, 200, map[string]any{"enabled": false, "message": "此站点未开启邀请返利功能"})
		return
	}
	var code, mode string
	var individual *bool
	var rate *int
	uid := current(r).ID
	if err = s.Pool.QueryRow(r.Context(), "SELECT invite_code,referral_enabled,referral_mode,referral_rate_bps FROM users WHERE id=$1", uid).Scan(&code, &individual, &mode, &rate); err != nil {
		s.dbError(w, err)
		return
	}
	if mode == "inherit" {
		mode = v.ReferralMode
	}
	bps, _ := referralRate(v.ReferralRate)
	if rate != nil {
		bps = *rate
	}
	var count, total int64
	if err = s.Pool.QueryRow(r.Context(), "SELECT (SELECT count(*) FROM users WHERE inviter_id=$1),COALESCE((SELECT sum(amount_cents) FROM referral_rewards WHERE inviter_id=$1),0)", uid).Scan(&count, &total); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "eligible": individual == nil || *individual, "code": code, "mode": mode, "rate": formatMoney(int64(bps)), "invited_count": count, "earned_cents": total})
}
