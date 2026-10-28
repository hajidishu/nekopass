package control

import (
	"context"
	"encoding/json"
	"errors"
	"math/bits"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

var probeLocation = time.FixedZone("UTC+8", 8*3600)

// At most thirty daily rows and 120 chart points are retained per node.
const probeNodeColumns = `n.first_connected_at,n.last_seen AS last_report_at,
 COALESCE((n.probe->>'uptime_seconds')::bigint,0) AS uptime_seconds,
 COALESCE((n.probe->>'uptime_ready')::boolean,false) AS uptime_ready,
 (pc.node_id IS NOT NULL) AS traffic_ready,
 COALESCE(pt.today_rx,0)::bigint AS traffic_today_rx_bytes,COALESCE(pt.today_tx,0)::bigint AS traffic_today_tx_bytes,
 COALESCE(pt.month_rx,0)::bigint AS traffic_30d_rx_bytes,COALESCE(pt.month_tx,0)::bigint AS traffic_30d_tx_bytes`

const probeNodeJoins = ` LEFT JOIN node_probe_counters pc ON pc.node_id=n.id
 LEFT JOIN LATERAL (SELECT
 sum(rx_bytes) FILTER(WHERE day=(now() AT TIME ZONE 'Asia/Shanghai')::date) AS today_rx,
 sum(tx_bytes) FILTER(WHERE day=(now() AT TIME ZONE 'Asia/Shanghai')::date) AS today_tx,
 sum(rx_bytes) AS month_rx,sum(tx_bytes) AS month_tx
 FROM node_probe_traffic_daily WHERE node_id=n.id AND day BETWEEN (now() AT TIME ZONE 'Asia/Shanghai')::date-29 AND (now() AT TIME ZONE 'Asia/Shanghai')::date) pt ON true `

type probeCounter struct {
	RX int64 `json:"rx"`
	TX int64 `json:"tx"`
}
type probeTrafficDay struct {
	Day    time.Time
	RX, TX int64
}

// Split samples spanning midnight proportionally while preserving exact totals.
// Ordinary intervals are seconds; a disconnected controller can span days.
func splitProbeTraffic(start, end time.Time, rx, tx int64) []probeTrafficDay {
	if !end.After(start) {
		start = end.Add(-time.Nanosecond)
	}
	total := end.Sub(start)
	first := start.In(probeLocation)
	day := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, probeLocation)
	last := end.In(probeLocation)
	cutoff := time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, probeLocation).AddDate(0, 0, -29)
	if day.Before(cutoff) {
		day = cutoff
	}
	result := []probeTrafficDay{}
	proportion := func(n int64, d time.Duration) int64 {
		if d <= 0 {
			return 0
		}
		if d >= total {
			return n
		}
		hi, lo := bits.Mul64(uint64(n), uint64(d))
		value, _ := bits.Div64(hi, lo, uint64(total))
		return int64(value)
	}
	for day.Before(end) {
		next := day.AddDate(0, 0, 1)
		left, right := maxTime(day, start), minTime(next, end)
		if right.After(left) {
			// Subtract cumulative allocations so no rounding remainder is lost.
			r := proportion(rx, right.Sub(start)) - proportion(rx, left.Sub(start))
			w := proportion(tx, right.Sub(start)) - proportion(tx, left.Sub(start))
			result = append(result, probeTrafficDay{day, r, w})
		}
		day = next
	}
	return result
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func acceptProbe(ctx context.Context, tx pgx.Tx, node int64, p *pb.Probe, now time.Time) error {
	var previous []byte
	if err := tx.QueryRow(ctx, "SELECT probe FROM nodes WHERE id=$1 FOR UPDATE", node).Scan(&previous); err != nil {
		return err
	}
	var old pb.Probe
	_ = json.Unmarshal(previous, &old)
	if old.SampledAt >= p.SampledAt && !p.NetworkCountersReady {
		return nil
	}
	if p.NetworkCountersReady {
		var oldBoot string
		var sampled int64
		var received time.Time
		var data []byte
		err := tx.QueryRow(ctx, "SELECT boot_id,sampled_at,received_at,counters FROM node_probe_counters WHERE node_id=$1", node).Scan(&oldBoot, &sampled, &received, &data)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		hasPrevious := err == nil
		if old.SampledAt >= p.SampledAt && hasPrevious && oldBoot == p.BootId && !(old.UptimeReady && p.UptimeReady && p.UptimeSeconds > old.UptimeSeconds) {
			return nil
		}
		oldCounters := map[string]probeCounter{}
		if hasPrevious {
			if err = json.Unmarshal(data, &oldCounters); err != nil {
				return err
			}
		}
		current := map[string]probeCounter{}
		var rx, txBytes int64
		for _, counter := range p.NetworkCounters {
			v := probeCounter{counter.RxBytes, counter.TxBytes}
			current[counter.Name] = v
			if !hasPrevious {
				continue
			}
			prior, ok := oldCounters[counter.Name]
			if oldBoot != p.BootId {
				rx += v.RX
				txBytes += v.TX
				continue
			}
			if !ok {
				continue
			} // A newly selected interface starts a fresh baseline.
			if v.RX >= prior.RX {
				rx += v.RX - prior.RX
			} else {
				rx += v.RX
			}
			if v.TX >= prior.TX {
				txBytes += v.TX - prior.TX
			} else {
				txBytes += v.TX
			}
		}
		if hasPrevious && (rx > 0 || txBytes > 0) {
			start := received
			if oldBoot != p.BootId && p.UptimeReady {
				// Limit conversion to the retained interval before making a Duration.
				boot := now.Add(-time.Duration(min(p.UptimeSeconds, int64(31*86400))) * time.Second)
				start = maxTime(start, boot)
			}
			for _, day := range splitProbeTraffic(start, now, rx, txBytes) {
				_, err = tx.Exec(ctx, `INSERT INTO node_probe_traffic_daily(node_id,day,rx_bytes,tx_bytes) VALUES($1,$2::date,$3,$4)
 ON CONFLICT(node_id,day) DO UPDATE SET rx_bytes=LEAST(9223372036854775807::numeric,node_probe_traffic_daily.rx_bytes::numeric+excluded.rx_bytes)::bigint,tx_bytes=LEAST(9223372036854775807::numeric,node_probe_traffic_daily.tx_bytes::numeric+excluded.tx_bytes)::bigint`, node, day.Day.Format("2006-01-02"), day.RX, day.TX)
				if err != nil {
					return err
				}
			}
		}
		data, err = json.Marshal(current)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO node_probe_counters(node_id,boot_id,sampled_at,received_at,counters) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(node_id) DO UPDATE SET boot_id=excluded.boot_id,sampled_at=excluded.sampled_at,received_at=excluded.received_at,counters=excluded.counters`, node, p.BootId, p.SampledAt, now, data)
		if err != nil {
			return err
		}
	}
	public := proto.Clone(p).(*pb.Probe)
	public.BootId = ""
	public.NetworkCounters = nil
	public.NetworkCountersReady = false
	data, err := json.Marshal(public)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE nodes SET probe=$2,probe_received_at=$3 WHERE id=$1", node, data, now); err != nil {
		return err
	}
	var cpu, memory, disk, diskRead, diskWrite *float64
	if p.CpuReady {
		v := p.CpuPercent
		cpu = &v
	}
	if p.MemoryReady && p.MemoryTotal > 0 {
		v := 100 * float64(p.MemoryUsed) / float64(p.MemoryTotal)
		memory = &v
	}
	if p.DiskReady && p.DiskTotal > 0 {
		v := 100 * float64(p.DiskUsed) / float64(p.DiskTotal)
		disk = &v
	}
	if p.DiskIoReady {
		diskRead, diskWrite = &p.DiskReadBytesPerSecond, &p.DiskWriteBytesPerSecond
	}
	if _, err = tx.Exec(ctx, "INSERT INTO node_probe_history(node_id,reported_at,cpu_percent,memory_percent,disk_percent,disk_read_bytes_per_second,disk_write_bytes_per_second) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING", node, now, cpu, memory, disk, diskRead, diskWrite); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM node_probe_history WHERE node_id=$1 AND (reported_at<$2 OR reported_at<(SELECT reported_at FROM node_probe_history WHERE node_id=$1 ORDER BY reported_at DESC OFFSET 119 LIMIT 1))`, node, now.Add(-10*time.Minute)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "DELETE FROM node_probe_traffic_daily WHERE node_id=$1 AND day<$2::date", node, now.In(probeLocation).AddDate(0, 0, -29).Format("2006-01-02"))
	return err
}

type probeHistoryPoint struct {
	At        int64    `json:"at"`
	CPU       *float64 `json:"cpu"`
	Memory    *float64 `json:"memory"`
	Disk      *float64 `json:"disk"`
	DiskRead  *float64 `json:"disk_read"`
	DiskWrite *float64 `json:"disk_write"`
}

func (s *Server) nodeProbeHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(w, r)
	if !ok {
		return
	}
	var allowed bool
	err := s.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_entitlements u JOIN plans p ON p.id=u.plan_id AND p.enabled
 JOIN user_node_groups ug ON ug.user_id=u.id JOIN node_groups g ON g.id=ug.group_id AND g.enabled JOIN node_group_members m ON m.group_id=g.id
 WHERE u.id=$1 AND u.enabled AND (u.expires_at IS NULL OR u.expires_at>now()) AND m.node_id=$2)`, current(r).ID, id).Scan(&allowed)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if !allowed {
		fail(w, 404, "节点不存在或无权查看")
		return
	}
	rows, err := s.Pool.Query(r.Context(), "SELECT reported_at,cpu_percent,memory_percent,disk_percent,disk_read_bytes_per_second,disk_write_bytes_per_second FROM (SELECT * FROM node_probe_history WHERE node_id=$1 ORDER BY reported_at DESC LIMIT 120) h ORDER BY reported_at", id)
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer rows.Close()
	points := []probeHistoryPoint{}
	for rows.Next() {
		var at time.Time
		var p probeHistoryPoint
		if err = rows.Scan(&at, &p.CPU, &p.Memory, &p.Disk, &p.DiskRead, &p.DiskWrite); err != nil {
			s.dbError(w, err)
			return
		}
		p.At = at.Unix()
		points = append(points, p)
	}
	if err = rows.Err(); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, points)
}
