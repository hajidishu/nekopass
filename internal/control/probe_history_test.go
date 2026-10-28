package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestProbeTrafficDayBoundaries(t *testing.T) {
	end := time.Date(2026, 10, 29, 0, 0, 5, 0, probeLocation)
	days := splitProbeTraffic(end.Add(-10*time.Second), end, 101, 203)
	if len(days) != 2 || days[0].RX != 50 || days[1].RX != 51 || days[0].TX != 101 || days[1].TX != 102 {
		t.Fatal(days)
	}
	for _, start := range []time.Time{end, end.Add(time.Second), end.Add(-40 * 24 * time.Hour)} {
		days = splitProbeTraffic(start, end, 100000, 200000)
		if len(days) == 0 || len(days) > 30 {
			t.Fatal("unbounded daily history", len(days))
		}
		for _, d := range days {
			if d.RX < 0 || d.TX < 0 {
				t.Fatal("negative allocation")
			}
		}
	}
	days = splitProbeTraffic(end.Add(-time.Second), end, math.MaxInt64, math.MaxInt64)
	if len(days) != 1 || days[0].RX != math.MaxInt64 {
		t.Fatal("large byte count overflow", days)
	}
}

func TestProbeValidatesNewFields(t *testing.T) {
	base := func() *pb.Probe {
		return &pb.Probe{SampledAt: 1, BootId: "boot-fixture", NetworkCountersReady: true, NetworkCounters: []*pb.InterfaceTraffic{{Name: "eth0", RxBytes: 100, TxBytes: 200}}}
	}
	if !validProbe(base()) {
		t.Fatal("valid counters rejected")
	}
	for _, change := range []func(*pb.Probe){
		func(p *pb.Probe) { p.DiskReadBytesPerSecond = math.NaN() }, func(p *pb.Probe) { p.DiskWriteBytesPerSecond = -1 }, func(p *pb.Probe) { p.UptimeSeconds = -1 },
		func(p *pb.Probe) { p.BootId = "" }, func(p *pb.Probe) { p.NetworkCounters[0].RxBytes = -1 }, func(p *pb.Probe) { p.NetworkCounters = append(p.NetworkCounters, p.NetworkCounters[0]) },
		func(p *pb.Probe) {
			p.NetworkCounters[0].RxBytes = math.MaxInt64
			p.NetworkCounters = append(p.NetworkCounters, &pb.InterfaceTraffic{Name: "eth1", RxBytes: 1})
		},
	} {
		p := base()
		change(p)
		if validProbe(p) {
			t.Fatal("invalid probe accepted")
		}
	}
}

func TestProbePersistentTrafficHistoryAndPrivacy(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,public_address) VALUES($1,$2,'203.0.113.91') RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	group := testAuthorize(t, f.p, f.user, node)
	base := time.Now().Add(-2 * time.Minute)
	apply := func(at time.Time, boot, name string, rx, txBytes int64) {
		t.Helper()
		p := &pb.Probe{SampledAt: at.Unix(), CpuReady: true, CpuPercent: 25, MemoryReady: true, MemoryTotal: 100, MemoryUsed: 40, DiskReady: true, DiskTotal: 100, DiskUsed: 60, UptimeReady: true, UptimeSeconds: 100, BootId: boot, NetworkCountersReady: true, NetworkCounters: []*pb.InterfaceTraffic{{Name: name, RxBytes: rx, TxBytes: txBytes}}, DiskIoReady: true, DiskReadBytesPerSecond: 2e6, DiskWriteBytesPerSecond: 3e6}
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
	totals := func(wantRX, wantTX int64) {
		t.Helper()
		var rx, txBytes int64
		if err := f.p.QueryRow(ctx, "SELECT COALESCE(sum(rx_bytes),0)::bigint,COALESCE(sum(tx_bytes),0)::bigint FROM node_probe_traffic_daily WHERE node_id=$1", node).Scan(&rx, &txBytes); err != nil || rx != wantRX || txBytes != wantTX {
			t.Fatalf("got %d/%d, want %d/%d; %v", rx, txBytes, wantRX, wantTX, err)
		}
	}
	apply(base, "boot-a", "eth0", 1000, 2000)
	totals(0, 0)
	apply(base.Add(time.Second), "boot-a", "eth0", 1100, 2200)
	totals(100, 200)
	apply(base.Add(time.Second), "boot-a", "eth0", 1100, 2200)
	totals(100, 200) // Cached heartbeat is not counted twice.
	apply(base, "boot-a", "eth0", 9999, 9999)
	totals(100, 200) // Stale sample is ignored.
	apply(base.Add(2*time.Second), "boot-a", "eth0", 10, 20)
	totals(110, 220) // Counter reset.
	apply(base.Add(3*time.Second), "boot-b", "eth0", 30, 40)
	totals(140, 260) // Reboot.
	apply(base.Add(4*time.Second), "boot-b", "eth1", 50000, 60000)
	totals(140, 260) // New interface is baselined.
	apply(base.Add(5*time.Second), "boot-b", "eth1", 50010, 60020)
	totals(150, 280)
	// A new controller object reads durable baselines, rather than starting over.
	f.s = New(f.p)
	for i := 6; i < 140; i++ {
		apply(base.Add(time.Duration(i)*time.Second), "boot-b", "eth1", 50010, 60020)
	}
	var count int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM node_probe_history WHERE node_id=$1", node).Scan(&count); err != nil || count != 120 {
		t.Fatal("history was not bounded", count, err)
	}
	path := fmt.Sprintf("node-status/%d/history", node)
	securityStatus(t, f.request(0, path, "GET", nil), 401)
	securityStatus(t, f.request(f.other, path, "GET", nil), 404)
	w := f.request(f.user, path, "GET", nil)
	securityStatus(t, w, 200)
	var points []probeHistoryPoint
	if json.Unmarshal(w.Body.Bytes(), &points) != nil || len(points) != 120 || points[0].CPU == nil || *points[0].CPU != 25 {
		t.Fatal("chart history unreadable")
	}
	if points[0].DiskRead == nil || *points[0].DiskRead != 2e6 || points[0].DiskWrite == nil || *points[0].DiskWrite != 3e6 {
		t.Fatal("disk read/write history missing")
	}
	if _, err := f.p.Exec(ctx, "UPDATE node_probe_history SET disk_read_bytes_per_second=NULL,disk_write_bytes_per_second=NULL WHERE node_id=$1 AND reported_at=(SELECT min(reported_at) FROM node_probe_history WHERE node_id=$1)", node); err != nil {
		t.Fatal(err)
	}
	w = f.request(f.user, path, "GET", nil)
	securityStatus(t, w, 200)
	if json.Unmarshal(w.Body.Bytes(), &points) != nil || points[0].DiskRead != nil || points[0].DiskWrite != nil || points[len(points)-1].DiskRead == nil {
		t.Fatal("missing legacy I/O samples were turned into zeroes")
	}
	w = f.request(f.user, "node-status", "GET", nil)
	securityStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "traffic_30d_tx_bytes") || !strings.Contains(w.Body.String(), "uptime_seconds") {
		t.Fatal("new probe fields missing")
	}
	for _, value := range []string{"203.0.113.91", "boot-b", "network_counters", "eth1", "public_address", "token_hash"} {
		if strings.Contains(w.Body.String(), value) {
			t.Fatal("private probe data leaked", value)
		}
	}
	var preceding int
	if err := f.p.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id<$1", node).Scan(&preceding); err != nil {
		t.Fatal(err)
	}
	text, _, err := f.s.telegramNodes(ctx, preceding/2)
	if err != nil || !strings.Contains(text, "今日流量") || !strings.Contains(text, "首次上线") || !strings.Contains(text, "主磁盘 I/O") {
		t.Fatal("Telegram node details missing", err)
	}
	if _, err := f.p.Exec(ctx, "DELETE FROM user_node_groups WHERE user_id=$1 AND group_id=$2", f.user, group); err != nil {
		t.Fatal(err)
	}
	securityStatus(t, f.request(f.user, path, "GET", nil), 404)
}

func TestProbeFirstConnectionIsStable(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	stream := &StreamServer{Server: f.s}
	instance := Secret()
	var first, timeAgain time.Time
	for i, target := range []*time.Time{&first, &timeAgain} {
		if _, err := stream.exchange(ctx, f.p, node, &pb.AgentMessage{InstanceId: instance, ProtocolVersion: pb.CurrentVersion, AppliedRevision: int64(i)}); err != nil {
			t.Fatal(err)
		}
		if err := f.p.QueryRow(ctx, "SELECT first_connected_at FROM nodes WHERE id=$1", node).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	if first.IsZero() || !first.Equal(timeAgain) {
		t.Fatal("first connection was overwritten")
	}
}

func TestProbeTrafficCalendarWindow(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash) VALUES($1,$2) RETURNING id", Secret(), Secret()).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "DELETE FROM nodes WHERE id=$1", node) })
	testAuthorize(t, f.p, f.user, node)
	for _, d := range []struct {
		age    int
		rx, tx int64
	}{{0, 20, 30}, {1, 40, 50}, {29, 60, 70}, {30, 1000, 1000}} {
		if _, err := f.p.Exec(ctx, "INSERT INTO node_probe_traffic_daily(node_id,day,rx_bytes,tx_bytes) VALUES($1,(now() AT TIME ZONE 'Asia/Shanghai')::date-$2::integer,$3,$4)", node, d.age, d.rx, d.tx); err != nil {
			t.Fatal(err)
		}
	}
	w := f.request(f.user, "node-status", "GET", nil)
	securityStatus(t, w, 200)
	var nodes []struct {
		TodayRX int64 `json:"traffic_today_rx_bytes"`
		TodayTX int64 `json:"traffic_today_tx_bytes"`
		MonthRX int64 `json:"traffic_30d_rx_bytes"`
		MonthTX int64 `json:"traffic_30d_tx_bytes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil || len(nodes) != 1 {
		t.Fatal("node traffic not readable", err)
	}
	if n := nodes[0]; n.TodayRX != 20 || n.TodayTX != 30 || n.MonthRX != 120 || n.MonthTX != 150 {
		t.Fatal("today or thirty-day boundary incorrect", n)
	}
}
