//go:build linux

package probe

import (
	"bufio"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type netBytes struct{ rx, tx uint64 }
type Sampler struct {
	total, idle uint64
	last        time.Time
	network     map[string]netBytes
	cpuSeen     bool
}

func NewSampler() *Sampler { return &Sampler{} }
func cpuTicks(data string) (uint64, uint64, bool) {
	line := strings.SplitN(data, "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	var total, idle uint64
	for i := 1; i < min(len(f), 9); i++ {
		v, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return 0, 0, false
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, true
}
func memoryBytes(data string) (int64, int64, bool) {
	values := map[string]int64{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			n, e := strconv.ParseInt(f[1], 10, 64)
			if e == nil {
				values[strings.TrimSuffix(f[0], ":")] = n * 1024
			}
		}
	}
	total := values["MemTotal"]
	avail, ok := values["MemAvailable"]
	return total, max(int64(0), total-avail), ok && total > 0 && avail <= total
}
func networkCounters(data string) map[string]netBytes {
	out := map[string]netBytes{}
	for _, line := range strings.Split(data, "\n") {
		pos := strings.LastIndex(line, ":")
		if pos < 0 {
			continue
		}
		name := strings.TrimSpace(line[:pos])
		f := strings.Fields(line[pos+1:])
		if len(f) < 16 {
			continue
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 == nil && e2 == nil {
			out[name] = netBytes{rx, tx}
		}
	}
	return out
}
func defaultInterfaces(all map[string]netBytes) []string {
	if data, e := os.ReadFile("/proc/net/route"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) > 3 && f[1] == "00000000" {
				if _, ok := all[f[0]]; ok {
					return []string{f[0]}
				}
			}
		}
	}
	out := []string{}
	for name := range all {
		if name != "lo" && !strings.HasPrefix(name, "veth") && !strings.HasPrefix(name, "br-") {
			out = append(out, name)
		}
	}
	return out
}
func countSockets(path string, tcp bool) (int64, bool) {
	f, e := os.Open(path)
	if e != nil {
		return 0, false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var n int64
	for scanner.Scan() {
		v := strings.Fields(scanner.Text())
		if len(v) > 3 && v[0] != "sl" {
			if !tcp || v[3] == "01" {
				n++
			}
		}
	}
	return n, scanner.Err() == nil
}
func (s *Sampler) Sample(c *pb.NodeConfig) *pb.Probe {
	now := time.Now()
	p := &pb.Probe{SampledAt: now.Unix()}
	if data, e := os.ReadFile("/proc/stat"); e == nil {
		total, idle, ok := cpuTicks(string(data))
		if ok {
			if s.cpuSeen && total > s.total && idle >= s.idle {
				p.CpuPercent = max(0, min(100, 100*(1-float64(idle-s.idle)/float64(total-s.total))))
				p.CpuReady = true
			}
			s.total = total
			s.idle = idle
			s.cpuSeen = true
		}
	}
	if data, e := os.ReadFile("/proc/meminfo"); e == nil {
		p.MemoryTotal, p.MemoryUsed, p.MemoryReady = memoryBytes(string(data))
	}
	var disk syscall.Statfs_t
	if e := syscall.Statfs(c.DiskPath, &disk); e == nil {
		p.DiskTotal = int64(disk.Blocks) * disk.Bsize
		p.DiskUsed = int64(disk.Blocks-disk.Bfree) * disk.Bsize
		p.DiskReady = p.DiskTotal > 0
	}
	if data, e := os.ReadFile("/proc/net/dev"); e == nil {
		all := networkCounters(string(data))
		names := c.NetworkInterfaces
		if len(names) == 0 {
			names = defaultInterfaces(all)
		}
		elapsed := now.Sub(s.last).Seconds()
		ready := !s.last.IsZero() && len(names) > 0
		var rx, tx uint64
		seen := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			v, ok := all[name]
			old, had := s.network[name]
			if !ok || !had || v.rx < old.rx || v.tx < old.tx {
				ready = false
				continue
			}
			rx += v.rx - old.rx
			tx += v.tx - old.tx
		}
		if ready && elapsed > 0 {
			p.RxMbps = float64(rx) * 8 / elapsed / 1e6
			p.TxMbps = float64(tx) * 8 / elapsed / 1e6
			p.NetworkReady = true
		}
		s.network = all
		s.last = now
	}
	tcp, tcpOK := countSockets("/proc/net/tcp", true)
	tcp6, _ := countSockets("/proc/net/tcp6", true)
	udp, udpOK := countSockets("/proc/net/udp", false)
	udp6, _ := countSockets("/proc/net/udp6", false)
	p.TcpConnections = tcp + tcp6
	p.UdpSockets = udp + udp6
	p.ConnectionsReady = tcpOK && udpOK
	if data, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(data))
		if len(f) >= 3 {
			a, e1 := strconv.ParseFloat(f[0], 64)
			b, e2 := strconv.ParseFloat(f[1], 64)
			d, e3 := strconv.ParseFloat(f[2], 64)
			if e1 == nil && e2 == nil && e3 == nil {
				p.Load1 = a
				p.Load5 = b
				p.Load15 = d
				p.LoadReady = true
			}
		}
	}
	return p
}
