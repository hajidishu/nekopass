//go:build linux

package probe

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"golang.org/x/sys/unix"
)

func uptimeSeconds(data string) (int64, bool) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v >= float64(math.MaxInt64) {
		return 0, false
	}
	return int64(v), true
}

func diskCounters(data string) (uint64, uint64, bool) {
	fields := strings.Fields(data)
	if len(fields) < 7 {
		return 0, 0, false
	}
	read, e1 := strconv.ParseUint(fields[2], 10, 64)
	write, e2 := strconv.ParseUint(fields[6], 10, 64)
	if e1 != nil || e2 != nil || read > math.MaxUint64/512 || write > math.MaxUint64/512 {
		return 0, 0, false
	}
	// Linux block statistics count sectors in 512-byte units, including 4K disks.
	return read * 512, write * 512, true
}

func diskStatPath(path string) (string, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return "", err
	}
	device := "/sys/dev/block/" + strconv.FormatUint(uint64(unix.Major(uint64(stat.Dev))), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(uint64(stat.Dev))), 10)
	device, err := filepath.EvalSymlinks(device)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(device, "partition")); err == nil {
		device = filepath.Dir(device)
	}
	return filepath.Join(device, "stat"), nil
}

func (s *Sampler) sampleDiskIO(path string, now time.Time, p *pb.Probe) {
	statPath, err := diskStatPath(path)
	if err != nil {
		s.diskTime = time.Time{}
		return
	}
	data, err := os.ReadFile(statPath)
	if err != nil {
		s.diskTime = time.Time{}
		return
	}
	read, write, ok := diskCounters(string(data))
	if !ok {
		s.diskTime = time.Time{}
		return
	}
	p.DiskDevice = filepath.Base(filepath.Dir(statPath))
	if s.diskDevice == statPath && !s.diskTime.IsZero() && now.After(s.diskTime) && read >= s.diskRead && write >= s.diskWrite {
		seconds := now.Sub(s.diskTime).Seconds()
		p.DiskReadBytesPerSecond = float64(read-s.diskRead) / seconds
		p.DiskWriteBytesPerSecond = float64(write-s.diskWrite) / seconds
		p.DiskIoReady = true
	}
	s.diskDevice, s.diskRead, s.diskWrite, s.diskTime = statPath, read, write, now
}
