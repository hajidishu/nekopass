package control

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestDashboardHourlySplitsPreserveBytesAndBoundStorage(t *testing.T) {
	end := time.Date(2026, 11, 10, 0, 0, 5, 0, probeLocation)
	parts := splitDashboardHours(end.Add(-10*time.Second), end, 101, 203)
	if len(parts) != 2 || parts[0].RX != 50 || parts[1].RX != 51 || parts[0].TX != 101 || parts[1].TX != 102 || parts[0].ObservedNS != int64(5*time.Second) {
		t.Fatal(parts)
	}
	parts = splitDashboardHours(end.Add(-time.Second), end, math.MaxInt64, math.MaxInt64)
	if len(parts) != 1 || parts[0].RX != math.MaxInt64 {
		t.Fatal("large counters overflowed", parts)
	}
	parts = splitDashboardHours(end.Add(-40*24*time.Hour), end, 10000000, 20000000)
	if len(parts) > 48 || len(parts) == 0 {
		t.Fatal("unbounded hourly retention", len(parts))
	}
	for _, p := range parts {
		if p.RX < 0 || p.TX < 0 || p.ObservedNS <= 0 || p.ObservedNS > int64(time.Hour) {
			t.Fatal("invalid bucket", p)
		}
	}
	if len(splitDashboardHours(end, end, 1, 1)) != 0 {
		t.Fatal("zero duration manufactured a rate")
	}
}

func TestAdminDashboardAuthorizationMoneyAndDurableTraffic(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	now := time.Now()
	local := now.In(probeLocation)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, probeLocation)
	securityStatus(t, f.request(0, "admin/dashboard", "GET", nil), 401)
	securityStatus(t, f.request(f.user, "admin/dashboard", "GET", nil), 403)
	securityStatus(t, f.request(f.admin, "admin/dashboard?range=bad", "GET", nil), 400)
	var baselineMoney, baselineCount int64
	if err := f.p.QueryRow(ctx, "SELECT COALESCE(sum(amount_cents),0)::bigint,count(*) FROM shop_orders WHERE kind='recharge' AND status='paid' AND paid_at>=$1 AND paid_at<=$2", day, now).Scan(&baselineMoney, &baselineCount); err != nil {
		t.Fatal(err)
	}
	initialResponse := f.request(f.admin, "admin/dashboard", "GET", nil)
	securityStatus(t, initialResponse, 200)
	var initial dashboardResponse
	if err := json.Unmarshal(initialResponse.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Stats.RechargeCents != baselineMoney || initial.Stats.RechargeOrders != baselineCount {
		t.Fatal("empty recharge aggregates became a maximum value", initial.Stats)
	}
	if initial.Stats.OnlineNodes == 0 && initial.Stats.Connections != 0 {
		t.Fatal("empty connection aggregate became a maximum value")
	}
	if !initial.Stats.TrafficReady && (initial.Stats.TodayRX != 0 || initial.Stats.TodayTX != 0) {
		t.Fatal("unmeasured traffic became a maximum value")
	}
	for _, o := range []struct {
		kind, status string
		amount       int64
		created      time.Time
		paid         any
	}{
		{"recharge", "paid", 10000, day.Add(-time.Hour), day.Add(now.Sub(day) / 2)},
		{"recharge", "paid", 2500, day.Add(now.Sub(day) / 3), day.Add(now.Sub(day) / 2)},
		{"recharge", "pending", 70000, now, nil},
		{"purchase", "paid", 90000, now, now},
		{"rebate", "paid", 1000, now, now},
		{"recharge", "paid", 3000, day.Add(-2 * time.Hour), day.Add(-time.Hour)},
	} {
		if _, err := f.p.Exec(ctx, "INSERT INTO shop_orders(order_no,user_id,kind,status,amount_cents,request_key,created_at,paid_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", Secret(), f.user, o.kind, o.status, o.amount, Secret(), o.created, o.paid); err != nil {
			t.Fatal(err)
		}
	}
	var node, disabled int64
	key := Secret()
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token,last_seen,active_connections) VALUES('dashboard-live',$1,$2,now(),7) RETURNING id", Hash(key), key).Scan(&node); err != nil {
		t.Fatal(err)
	}
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,enabled,active_connections) VALUES('dashboard-disabled',$1,false,999) RETURNING id", Secret()).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Exec(ctx, "DELETE FROM nodes WHERE id=ANY($1)", []int64{node, disabled}) })
	p := &pb.Probe{SampledAt: now.Add(-5 * time.Second).Unix(), BootId: "fixture-dashboard-private-boot", NetworkCountersReady: true, NetworkCounters: []*pb.InterfaceTraffic{{Name: "fixture-private-interface", RxBytes: 1000, TxBytes: 2000}}, CpuReady: true, CpuPercent: 12, MemoryReady: true, MemoryUsed: 40, MemoryTotal: 100}
	apply := func(at time.Time) {
		t.Helper()
		tr, err := f.p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tr.Rollback(ctx)
		if err = acceptProbe(ctx, tr, node, p, at); err != nil {
			t.Fatal(err)
		}
		if err = tr.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	apply(now.Add(-5 * time.Second))
	p.SampledAt = now.Unix()
	p.NetworkCounters[0].RxBytes += 1000000
	p.NetworkCounters[0].TxBytes += 2000000
	apply(now)
	f.s.panelProbe.Store(p)
	get := func(period string) dashboardResponse {
		t.Helper()
		w := f.request(f.admin, "admin/dashboard?range="+period, "GET", nil)
		securityStatus(t, w, 200)
		for _, secret := range []string{key, p.BootId, "fixture-private-interface", "token_hash", "private_key", "network_counters"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("dashboard exposed private node material", secret)
			}
		}
		var d dashboardResponse
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := get("24h")
	if d.Stats.RechargeCents != baselineMoney+12500 || d.Stats.RechargeOrders != baselineCount+2 {
		t.Fatal("recharges double counted purchases, pending orders or wrong day", d.Stats)
	}
	if len(d.Nodes) > 5 || len(d.Orders) > 4 || !d.Stats.TrafficReady || len(d.Traffic) == 0 || len(d.Traffic) > 25 {
		t.Fatal("unbounded or missing dashboard data", d)
	}
	if d.Host == nil || d.Host.BootId != "" || len(d.Host.NetworkCounters) != 0 {
		t.Fatal("host metrics missing or private")
	}
	for _, v := range d.Nodes {
		if (!v.Online && v.Metrics != nil) || len(v.History) > 24 {
			t.Fatal("stale node shown as measured or unbounded history")
		}
	}
	var rx, txBytes, observed int64
	if err := f.p.QueryRow(ctx, "SELECT sum(rx_bytes)::bigint,sum(tx_bytes)::bigint,sum(observed_ns)::bigint FROM node_probe_traffic_hourly WHERE node_id=$1", node).Scan(&rx, &txBytes, &observed); err != nil || rx != 1000000 || txBytes != 2000000 || observed != int64(5*time.Second) {
		t.Fatal("hourly traffic disagrees with real counters", rx, txBytes, observed, err)
	}
	f.s = New(f.p)
	f.h = f.s.Handler(http.NotFoundHandler())
	if len(get("24h").Traffic) != len(d.Traffic) {
		t.Fatal("restart lost durable hourly data")
	}
	for _, period := range []string{"7d", "30d"} {
		d = get(period)
		if d.Unit != "bytes" || len(d.Traffic) > 30 || len(d.Traffic) == 0 {
			t.Fatal("daily history missing", period, d)
		}
	}
	// A measured idle period remains zero, instead of a missing sample.
	p.SampledAt = now.Add(time.Second).Unix()
	apply(now.Add(time.Second))
	if err := f.p.QueryRow(ctx, "SELECT sum(observed_ns)::bigint FROM node_probe_traffic_hourly WHERE node_id=$1", node).Scan(&observed); err != nil || observed != int64(6*time.Second) {
		t.Fatal("idle samples lost coverage", observed, err)
	}
	// Stale probe replay cannot duplicate either bytes or duration.
	apply(now.Add(time.Second))
	if err := f.p.QueryRow(ctx, "SELECT sum(observed_ns)::bigint FROM node_probe_traffic_hourly WHERE node_id=$1", node).Scan(&observed); err != nil || observed != int64(6*time.Second) {
		t.Fatal("probe replay duplicated hourly coverage", observed, err)
	}
}

func TestTicketStatusFilterKeepsUserOwnership(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	for _, v := range []struct {
		user     int64
		status   string
		priority string
	}{{f.user, "waiting_staff", "high"}, {f.user, "closed", "high"}, {f.other, "waiting_staff", "high"}, {f.user, "waiting_staff", "low"}, {f.user, "waiting_staff", "medium"}} {
		if _, err := f.p.Exec(ctx, "INSERT INTO tickets(user_id,title,priority,status) VALUES($1,'fixture filter',$3,$2)", v.user, v.status, v.priority); err != nil {
			t.Fatal(err)
		}
	}
	w := f.request(f.user, "tickets?status=waiting_staff", "GET", nil)
	securityStatus(t, w, 200)
	var result struct {
		Total int64 `json:"total"`
		Items []struct {
			User     int64  `json:"user_id"`
			Status   string `json:"status"`
			Priority string `json:"priority"`
		} `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Total != 3 || len(result.Items) != 3 {
		t.Fatal("status filter bypassed owner scope", w.Body.String())
	}
	for _, item := range result.Items {
		if item.User != f.user || item.Status != "waiting_staff" {
			t.Fatal("status filter exposed another user's ticket")
		}
	}
	for _, priority := range []string{"high", "medium", "low"} {
		w = f.request(f.user, "tickets?status=waiting_staff&priority="+priority, "GET", nil)
		securityStatus(t, w, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].User != f.user || result.Items[0].Status != "waiting_staff" || result.Items[0].Priority != priority {
			t.Fatal("priority filter bypassed owner or status scope", w.Body.String())
		}
	}
	w = f.request(f.admin, "admin/dashboard", "GET", nil)
	securityStatus(t, w, 200)
	var summary dashboardResponse
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Stats.WaitingTickets != summary.Stats.HighTickets+summary.Stats.MediumTickets+summary.Stats.LowTickets || summary.Stats.HighTickets < 2 || summary.Stats.MediumTickets < 1 || summary.Stats.LowTickets < 1 {
		t.Fatal("pending ticket counts are inconsistent", summary.Stats)
	}
	securityStatus(t, f.request(f.admin, "admin/tickets?status=bad", "GET", nil), 400)
	securityStatus(t, f.request(f.admin, "admin/tickets?priority=bad", "GET", nil), 400)
}
