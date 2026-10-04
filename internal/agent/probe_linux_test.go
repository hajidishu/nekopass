//go:build linux

package agent

import (
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
	s := newProbeSampler()
	c := defaultNodeConfig()
	s.sample(c)
	time.Sleep(30 * time.Millisecond)
	p := s.sample(c)
	if !p.CpuReady || !p.MemoryReady || !p.DiskReady || !p.NetworkReady || !p.LoadReady || !p.ConnectionsReady || p.MemoryTotal <= 0 || p.DiskTotal <= 0 {
		t.Fatalf("incomplete native Linux probe: %v", p)
	}
	if p.CpuPercent < 0 || p.CpuPercent > 100 {
		t.Fatal("CPU range")
	}
}
