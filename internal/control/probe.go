package control

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"math"
	"strings"
)

func validProbe(p *pb.Probe) bool {
	for _, v := range []float64{p.CpuPercent, p.RxMbps, p.TxMbps, p.Load1, p.Load5, p.Load15, p.DiskReadBytesPerSecond, p.DiskWriteBytesPerSecond} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false
		}
	}
	if p.UptimeSeconds < 0 || len(p.BootId) > 128 || len(p.DiskDevice) > 128 || strings.ContainsAny(p.BootId+p.DiskDevice, "\r\n\x00") || len(p.NetworkCounters) > 128 {
		return false
	}
	seen := map[string]bool{}
	var rx, tx int64
	for _, v := range p.NetworkCounters {
		if v == nil || v.Name == "" || len(v.Name) > 128 || strings.ContainsAny(v.Name, "\r\n\x00") || seen[v.Name] || v.RxBytes < 0 || v.TxBytes < 0 || v.RxBytes > math.MaxInt64-rx || v.TxBytes > math.MaxInt64-tx {
			return false
		}
		seen[v.Name] = true
		rx += v.RxBytes
		tx += v.TxBytes
	}
	if p.NetworkCountersReady && (p.BootId == "" || len(p.NetworkCounters) == 0) {
		return false
	}
	return p.SampledAt > 0 && p.CpuPercent <= 100 && p.MemoryTotal >= 0 && p.MemoryUsed >= 0 && p.MemoryUsed <= p.MemoryTotal && p.DiskTotal >= 0 && p.DiskUsed >= 0 && p.DiskUsed <= p.DiskTotal && p.TcpConnections >= 0 && p.UdpSockets >= 0
}
