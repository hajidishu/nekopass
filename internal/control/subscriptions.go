package control

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"time"
)

var billingZone = time.FixedZone("CST", 8*60*60)

// Month arithmetic clamps the day to the target month rather than Go AddDate's
// overflow into the following month. The anchor prevents February drift.
func addBillingMonths(t time.Time, months int) time.Time {
	t = t.In(billingZone)
	first := time.Date(t.Year(), t.Month()+time.Month(months), 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), billingZone)
	last := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, billingZone).Day()
	return time.Date(first.Year(), first.Month(), min(t.Day(), last), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), billingZone)
}

type subscriptionState struct {
	PlanID                     int64
	Managed                    bool
	Expires, NextReset, Anchor *time.Time
	ResetIndex                 int
	Epoch                      int64
}

func subscriptionForUpdate(ctx context.Context, tx pgx.Tx, uid int64) (subscriptionState, error) {
	var sub subscriptionState
	err := tx.QueryRow(ctx, `SELECT COALESCE(plan_id,0),subscription_managed,subscription_expires_at,next_reset_at,reset_anchor_at,reset_index,quota_epoch FROM users WHERE id=$1 AND enabled FOR UPDATE`, uid).Scan(&sub.PlanID, &sub.Managed, &sub.Expires, &sub.NextReset, &sub.Anchor, &sub.ResetIndex, &sub.Epoch)
	return sub, err
}

func purchasedDates(now time.Time, sub subscriptionState, samePlan bool, cycle string) (*time.Time, *time.Time, error) {
	months, ok := billingMonths[cycle]
	if !ok {
		return nil, nil, errors.New("不支持的付款周期")
	}
	if months == 0 {
		return nil, nil, nil
	} // One-time quota: permanent, no automatic resets.
	base := now
	if samePlan && sub.Managed && sub.Expires != nil && sub.Expires.After(now) && sub.NextReset != nil && sub.NextReset.After(now) {
		// Discard only the unconsumed part of the current quota period. Future
		// paid time remains, followed by the newly purchased duration.
		base = sub.Expires.Add(-sub.NextReset.Sub(now))
	}
	expires := addBillingMonths(base, months)
	if expires.After(addBillingMonths(now, 1200)) {
		return nil, nil, errors.New("累计套餐时长不能超过 100 年")
	}
	next := addBillingMonths(now, 1)
	if next.After(expires) {
		next = expires
	}
	return &expires, &next, nil
}

func resetDueSubscription(ctx context.Context, tx pgx.Tx, uid int64, sub *subscriptionState, now time.Time) (bool, error) {
	if !sub.Managed || sub.NextReset == nil || sub.NextReset.After(now) {
		return false, nil
	}
	if sub.Expires == nil || !sub.Expires.After(now) {
		_, e := tx.Exec(ctx, "UPDATE users SET next_reset_at=NULL WHERE id=$1", uid)
		sub.NextReset = nil
		return false, e
	}
	if sub.Anchor == nil {
		return false, errors.New("subscription reset anchor missing")
	}
	index := sub.ResetIndex
	var next time.Time
	for {
		index++
		next = addBillingMonths(*sub.Anchor, index)
		if next.After(now) {
			break
		}
		if index > 120000 {
			return false, errors.New("invalid reset index")
		}
	}
	if next.After(*sub.Expires) {
		next = *sub.Expires
	}
	_, e := tx.Exec(ctx, "UPDATE users SET quota_epoch=quota_epoch+1,next_reset_at=$2,reset_index=$3 WHERE id=$1", uid, next, index)
	if e == nil {
		sub.Epoch++
		sub.NextReset = &next
		sub.ResetIndex = index
	}
	return true, e
}

func (s *Server) RunSubscriptionClock(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if e := s.resetDueSubscriptions(ctx, time.Now()); e != nil && ctx.Err() == nil {
			slog.Error("subscription reset", "error", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) resetDueSubscriptions(ctx context.Context, now time.Time) error {
	tx, e := s.ruleTx(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, "SELECT id FROM users WHERE enabled AND subscription_managed AND next_reset_at<=$1 ORDER BY id LIMIT 200", now)
	if e != nil {
		return e
	}
	ids, e := pgx.CollectRows(rows, pgx.RowTo[int64])
	if e != nil {
		return e
	}
	changed := false
	for _, id := range ids {
		sub, e := subscriptionForUpdate(ctx, tx, id)
		if e != nil {
			return e
		}
		c, e := resetDueSubscription(ctx, tx, id, &sub, now)
		if e != nil {
			return e
		}
		changed = changed || c
	}
	if changed {
		return finishRules(ctx, tx)
	}
	return tx.Commit(ctx)
}
