package control

import (
	"context"
	"encoding/json"
	"math/bits"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

type dashboardHour struct {
	At                 time.Time
	RX, TX, ObservedNS int64
}

// Hourly rates retain at most 48 buckets per node. Missing periods stay missing;
// old daily totals are never expanded into an invented hourly traffic pattern.
func splitDashboardHours(start, end time.Time, rx, tx int64) []dashboardHour {
	if !end.After(start) {
		return nil
	}
	total := end.Sub(start)
	hour := start.Truncate(time.Hour)
	cutoff := end.Truncate(time.Hour).Add(-47 * time.Hour)
	if hour.Before(cutoff) {
		hour = cutoff
	}
	proportion := func(n int64, d time.Duration) int64 {
		if d <= 0 {
			return 0
		}
		if d >= total {
			return n
		}
		hi, lo := bits.Mul64(uint64(n), uint64(d))
		v, _ := bits.Div64(hi, lo, uint64(total))
		return int64(v)
	}
	result := []dashboardHour{}
	for hour.Before(end) {
		next := hour.Add(time.Hour)
		left, right := maxTime(start, hour), minTime(end, next)
		if right.After(left) {
			result = append(result, dashboardHour{hour, proportion(rx, right.Sub(start)) - proportion(rx, left.Sub(start)), proportion(tx, right.Sub(start)) - proportion(tx, left.Sub(start)), int64(right.Sub(left))})
		}
		hour = next
	}
	return result
}

type dashboardStats struct {
	Users          int64 `json:"users"`
	NewUsers       int64 `json:"new_users"`
	Nodes          int64 `json:"nodes"`
	EnabledNodes   int64 `json:"enabled_nodes"`
	OnlineNodes    int64 `json:"online_nodes"`
	OfflineNodes   int64 `json:"offline_nodes"`
	Rules          int64 `json:"rules"`
	Connections    int64 `json:"connections"`
	RechargeCents  int64 `json:"recharge_cents"`
	RechargeOrders int64 `json:"recharge_orders"`
	WaitingTickets int64 `json:"waiting_tickets"`
	HighTickets    int64 `json:"high_tickets"`
	MediumTickets  int64 `json:"medium_tickets"`
	LowTickets     int64 `json:"low_tickets"`
	TodayRX        int64 `json:"today_rx"`
	TodayTX        int64 `json:"today_tx"`
	TrafficReady   bool  `json:"traffic_ready"`
}
type dashboardTrafficPoint struct {
	At int64    `json:"at"`
	RX *float64 `json:"rx"`
	TX *float64 `json:"tx"`
}
type dashboardNode struct {
	ID      int64               `json:"id"`
	Name    string              `json:"name"`
	Enabled bool                `json:"enabled"`
	Online  bool                `json:"online"`
	Metrics *pb.Probe           `json:"metrics"`
	History []probeHistoryPoint `json:"history"`
}
type dashboardOrder struct {
	ID       int64     `json:"id"`
	Number   string    `json:"order_no"`
	UserID   int64     `json:"user_id"`
	Username string    `json:"username"`
	Kind     string    `json:"kind"`
	Amount   int64     `json:"amount_cents"`
	Status   string    `json:"status"`
	Created  time.Time `json:"created_at"`
}
type dashboardResponse struct {
	Generated time.Time               `json:"generated_at"`
	Timezone  string                  `json:"timezone"`
	Range     string                  `json:"range"`
	Unit      string                  `json:"unit"`
	Stats     dashboardStats          `json:"stats"`
	Traffic   []dashboardTrafficPoint `json:"traffic"`
	Nodes     []dashboardNode         `json:"nodes"`
	Orders    []dashboardOrder        `json:"orders"`
	Host      *pb.Probe               `json:"host"`
}

func dashboardPublicProbe(p *pb.Probe) *pb.Probe {
	if p == nil || !validProbe(p) {
		return nil
	}
	v := proto.Clone(p).(*pb.Probe)
	v.BootId = ""
	v.NetworkCounters = nil
	v.NetworkCountersReady = false
	return v
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	period := r.URL.Query().Get("range")
	if period == "" {
		period = "24h"
	}
	if period != "24h" && period != "7d" && period != "30d" {
		fail(w, 400, "时间范围须为 24h、7d 或 30d")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(ctx)
	now := time.Now()
	local := now.In(probeLocation)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, probeLocation)
	out := dashboardResponse{Generated: now, Timezone: "Asia/Shanghai", Range: period, Unit: "mbps", Traffic: []dashboardTrafficPoint{}, Nodes: []dashboardNode{}, Orders: []dashboardOrder{}, Host: dashboardPublicProbe(s.panelProbe.Load())}
	v := &out.Stats
	err = tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM users),(SELECT count(*) FROM users WHERE created_at>=$2 AND created_at<=$1),
 (SELECT count(*) FROM nodes),(SELECT count(*) FROM nodes WHERE enabled),
 (SELECT count(*) FROM nodes WHERE enabled AND last_seen>$1::timestamptz-interval '12 seconds'),
 (SELECT count(*) FROM nodes WHERE enabled AND (last_seen IS NULL OR last_seen<=$1::timestamptz-interval '12 seconds')),
 (SELECT count(*) FROM rules),COALESCE((SELECT LEAST(COALESCE(sum(active_connections)::numeric,0),9223372036854775807)::bigint FROM nodes WHERE enabled AND last_seen>$1::timestamptz-interval '12 seconds'),0),
 COALESCE((SELECT LEAST(COALESCE(sum(amount_cents)::numeric,0),9223372036854775807)::bigint FROM shop_orders WHERE kind='recharge' AND status='paid' AND paid_at>=$2 AND paid_at<=$1),0),
 (SELECT count(*) FROM shop_orders WHERE kind='recharge' AND status='paid' AND paid_at>=$2 AND paid_at<=$1),
 (SELECT count(*) FROM tickets WHERE status='waiting_staff'),(SELECT count(*) FROM tickets WHERE status='waiting_staff' AND priority='high'),
 (SELECT count(*) FROM tickets WHERE status='waiting_staff' AND priority='medium'),(SELECT count(*) FROM tickets WHERE status='waiting_staff' AND priority='low'),
 COALESCE((SELECT LEAST(COALESCE(sum(rx_bytes)::numeric,0),9223372036854775807)::bigint FROM node_probe_traffic_daily WHERE day=$3::date),0),
 COALESCE((SELECT LEAST(COALESCE(sum(tx_bytes)::numeric,0),9223372036854775807)::bigint FROM node_probe_traffic_daily WHERE day=$3::date),0),
 EXISTS(SELECT 1 FROM node_probe_counters)`, now, day, day.Format("2006-01-02")).Scan(&v.Users, &v.NewUsers, &v.Nodes, &v.EnabledNodes, &v.OnlineNodes, &v.OfflineNodes, &v.Rules, &v.Connections, &v.RechargeCents, &v.RechargeOrders, &v.WaitingTickets, &v.HighTickets, &v.MediumTickets, &v.LowTickets, &v.TodayRX, &v.TodayTX, &v.TrafficReady)
	if err != nil {
		s.dbError(w, err)
		return
	}
	var rows pgx.Rows
	if period == "24h" {
		rows, err = tx.Query(ctx, `SELECT bucket_at,sum(rx_bytes::numeric*8000/observed_ns)::double precision,sum(tx_bytes::numeric*8000/observed_ns)::double precision FROM node_probe_traffic_hourly WHERE bucket_at>=$1 AND bucket_at<=$2 GROUP BY bucket_at ORDER BY bucket_at LIMIT 25`, now.Truncate(time.Hour).Add(-24*time.Hour), now)
	} else {
		days := 7
		if period == "30d" {
			days = 30
		}
		out.Unit = "bytes"
		rows, err = tx.Query(ctx, `SELECT day::timestamp AT TIME ZONE 'Asia/Shanghai',LEAST(COALESCE(sum(rx_bytes)::numeric,0),9223372036854775807)::double precision,LEAST(COALESCE(sum(tx_bytes)::numeric,0),9223372036854775807)::double precision FROM node_probe_traffic_daily WHERE day BETWEEN $1::date AND $2::date GROUP BY day ORDER BY day LIMIT 30`, day.AddDate(0, 0, -days+1).Format("2006-01-02"), day.Format("2006-01-02"))
	}
	if err != nil {
		s.dbError(w, err)
		return
	}
	for rows.Next() {
		var at time.Time
		var point dashboardTrafficPoint
		if err = rows.Scan(&at, &point.RX, &point.TX); err != nil {
			rows.Close()
			s.dbError(w, err)
			return
		}
		point.At = at.Unix()
		out.Traffic = append(out.Traffic, point)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		s.dbError(w, err)
		return
	}
	rows, err = tx.Query(ctx, `SELECT n.id,n.name,n.enabled,COALESCE(n.enabled AND n.last_seen>$1::timestamptz-interval '12 seconds',false),n.probe,n.probe_received_at,n.probe_interval_seconds,COALESCE(h.history,'[]'::jsonb)
 FROM (SELECT * FROM nodes ORDER BY (enabled AND (last_seen IS NULL OR last_seen<=$1::timestamptz-interval '12 seconds')) DESC,enabled DESC,name,id LIMIT 5) n
 LEFT JOIN LATERAL (SELECT jsonb_agg(jsonb_build_object('at',floor(extract(epoch FROM reported_at))::bigint,'cpu',cpu_percent,'memory',memory_percent,'disk',disk_percent,'disk_read',disk_read_bytes_per_second,'disk_write',disk_write_bytes_per_second) ORDER BY reported_at) AS history FROM (SELECT * FROM node_probe_history WHERE node_id=n.id AND reported_at>$1::timestamptz-interval '10 minutes' ORDER BY reported_at DESC LIMIT 24) p) h ON true
 ORDER BY (n.enabled AND (n.last_seen IS NULL OR n.last_seen<=$1::timestamptz-interval '12 seconds')) DESC,n.enabled DESC,n.name,n.id`, now)
	if err != nil {
		s.dbError(w, err)
		return
	}
	for rows.Next() {
		var n dashboardNode
		var raw, history []byte
		var received *time.Time
		var interval int
		if err = rows.Scan(&n.ID, &n.Name, &n.Enabled, &n.Online, &raw, &received, &interval, &history); err != nil {
			rows.Close()
			s.dbError(w, err)
			return
		}
		n.History = []probeHistoryPoint{}
		if n.Online {
			var p pb.Probe
			if received != nil && !received.After(now) && now.Sub(*received) <= time.Duration(max(20, interval*2))*time.Second && json.Unmarshal(raw, &p) == nil {
				n.Metrics = dashboardPublicProbe(&p)
			}
			if err = json.Unmarshal(history, &n.History); err != nil {
				rows.Close()
				s.dbError(w, err)
				return
			}
		}
		out.Nodes = append(out.Nodes, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		s.dbError(w, err)
		return
	}
	rows, err = tx.Query(ctx, `SELECT o.id,o.order_no,o.user_id,u.username,o.kind,o.amount_cents,o.status,o.created_at FROM shop_orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 4`)
	if err != nil {
		s.dbError(w, err)
		return
	}
	for rows.Next() {
		var o dashboardOrder
		if err = rows.Scan(&o.ID, &o.Number, &o.UserID, &o.Username, &o.Kind, &o.Amount, &o.Status, &o.Created); err != nil {
			rows.Close()
			s.dbError(w, err)
			return
		}
		out.Orders = append(out.Orders, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(ctx); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
