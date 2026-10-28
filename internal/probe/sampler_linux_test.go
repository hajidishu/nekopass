//go:build linux

package probe

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"testing"
	"time"
)

func TestProbeParsers(t *testing.T) {
	total, idle, ok := cpuTicks("cpu 10 20 30 40 5 6 7 8 100 100\ncpu0 0 0\n")
	if !ok || total != 126 || idle != 45 {
		t.Fatal(total, idle, ok)
	}
	memory, used, ok := memoryBytes("MemTotal: 100 kB\nMemAvailable: 60 kB\n")
	if !ok || memory != 102400 || used != 40960 {
		t.Fatal(memory, used, ok)
	}
	if _, _, ok = memoryBytes("MemTotal: 100 kB\n"); ok {
		t.Fatal("missing memory data treated as zero")
	}
	c := networkCounters(" eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n")
	if c["eth0"].rx != 1000 || c["eth0"].tx != 2000 {
		t.Fatal(c)
	}
}
func TestLiveProbe(t *testing.T) {
	s := NewSampler()
	c := &pb.NodeConfig{DiskPath: "/"}
	s.Sample(c)
	time.Sleep(30 * time.Millisecond)
	p := s.Sample(c)
	if !p.CpuReady || !p.MemoryReady || !p.DiskReady || !p.NetworkReady || !p.LoadReady || !p.ConnectionsReady || p.MemoryTotal <= 0 || p.DiskTotal <= 0 {
		t.Fatalf("incomplete native Linux probe: %v", p)
	}
	if p.CpuPercent < 0 || p.CpuPercent > 100 {
		t.Fatal("CPU range")
	}
	if !p.UptimeReady || p.UptimeSeconds < 0 || p.BootId == "" || !p.NetworkCountersReady || len(p.NetworkCounters) == 0 {
		t.Fatal("uptime or cumulative counters missing", p)
	}
	if _, err := diskStatPath("/"); err == nil && (!p.DiskIoReady || p.DiskDevice == "") {
		t.Fatal("main disk I/O missing", p)
	}
}

func TestDiskAndUptimeParsers(t *testing.T) {
	r, w, ok := diskCounters("1 0 8 1 2 0 16 1 0 0 0")
	if !ok || r != 4096 || w != 8192 {
		t.Fatal(r, w, ok)
	}
	for _, v := range []string{"", "1 2", "1 0 bad 1 2 0 1", "1 0 18446744073709551615 1 2 0 1"} {
		if _, _, ok := diskCounters(v); ok {
			t.Fatal("invalid disk statistics accepted")
		}
	}
	if n, ok := uptimeSeconds("123.99 100.00"); !ok || n != 123 {
		t.Fatal(n, ok)
	}
	for _, v := range []string{"", "-1", "NaN", "Inf", "1e99"} {
		if _, ok := uptimeSeconds(v); ok {
			t.Fatal("invalid uptime accepted", v)
		}
	}
}
