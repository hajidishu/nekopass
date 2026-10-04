package control

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"math"
)

func validProbe(p *pb.Probe) bool {
	for _, v := range []float64{p.CpuPercent, p.RxMbps, p.TxMbps, p.Load1, p.Load5, p.Load15} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false
		}
	}
	return p.SampledAt > 0 && p.CpuPercent <= 100 && p.MemoryTotal >= 0 && p.MemoryUsed >= 0 && p.MemoryUsed <= p.MemoryTotal && p.DiskTotal >= 0 && p.DiskUsed >= 0 && p.DiskUsed <= p.DiskTotal && p.TcpConnections >= 0 && p.UdpSockets >= 0
}
