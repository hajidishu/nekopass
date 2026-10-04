package agent

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func testAccount(t *testing.T, quota, speed int64) (*State, *Account) {
	t.Helper()
	s, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := newAccount(1, DiskUser{}, s)
	if err = a.configure(&pb.UserPolicy{Id: 1, Enabled: true, Issued: quota, SpeedBps: speed, MaxConnections: 100}); err != nil {
		t.Fatal(err)
	}
	return s, a
}
func TestConcurrentQuotaNeverOverspends(t *testing.T) {
	_, a := testAccount(t, 1234567, 1<<30)
	var total atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := a.take(ctx, BufferSize)
				if err != nil {
					return
				}
				total.Add(int64(n))
				a.count(n)
			}
		}()
	}
	wg.Wait()
	if total.Load() != 1234567 {
		t.Fatalf("got %d", total.Load())
	}
	if a.disk.Traffic != 1234567 || a.disk.Spent != 1234567 {
		t.Fatalf("invalid accounting: %+v", a.disk)
	}
}
func TestRestartCannotReplayReservation(t *testing.T) {
	s, a := testAccount(t, 2*ReservationBlock, 1<<30)
	n, err := a.take(context.Background(), 1024)
	if err != nil || n != 1024 {
		t.Fatal(n, err)
	}
	users, err := s.LoadUsers()
	if err != nil {
		t.Fatal(err)
	}
	resumed := newAccount(1, users[1], s)
	if err = resumed.configure(a.policy); err != nil {
		t.Fatal(err)
	}
	if resumed.credit != 0 || resumed.disk.Spent != ReservationBlock {
		t.Fatal("reservation replayed")
	}
	_, err = resumed.take(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.disk.Spent != 2*ReservationBlock {
		t.Fatal("restart did not debit next reservation")
	}
}
func TestDisabledAndExpiredAccountRejects(t *testing.T) {
	_, a := testAccount(t, 1<<20, 1<<20)
	for _, p := range []*pb.UserPolicy{{Id: 1, Enabled: false, Issued: 1 << 20, SpeedBps: 1 << 20}, {Id: 1, Enabled: true, ExpiresUnix: time.Now().Unix() - 1, Issued: 1 << 20, SpeedBps: 1 << 20}} {
		if err := a.configure(p); err != nil {
			t.Fatal(err)
		}
		if a.acquire() {
			t.Fatal("inactive account accepted")
		}
		if _, err := a.take(context.Background(), 10); err == nil {
			t.Fatal("inactive account forwarded")
		}
	}
}
func TestTCPHalfCloseAndBidirectionalAccounting(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("reply:"), data...))
	}()
	s, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e, err := NewEngine(s, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	config := &pb.ControlMessage{Revision: 1, Users: []*pb.UserPolicy{{Id: 1, Enabled: true, Issued: 1 << 20, SpeedBps: 1 << 30, MaxConnections: 100}}, Rules: []*pb.Rule{{Id: 1, UserId: 1, ListenHost: "127.0.0.1", ListenPort: 0, TargetHost: "127.0.0.1", TargetPort: int32(target.Addr().(*net.TCPAddr).Port), Enabled: true}}}
	if err = e.Apply(config); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTCP("tcp", nil, e.listeners[1].ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("hello"))
	_ = c.CloseWrite()
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "reply:hello" {
		t.Fatalf("reply: %q", reply)
	}
	<-done
	r, err := e.Report()
	if err != nil {
		t.Fatal(err)
	}
	if r.Usage[0].Traffic != 16 || r.RuleUsage[0].Traffic != 16 {
		t.Fatalf("double-count or missing data: %v", r)
	}
}
func TestSharedLimiter(t *testing.T) {
	_, a := testAccount(t, 1<<20, 128<<10)
	a.limiter.SetBurst(BufferSize)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if err := a.limiter.WaitN(context.Background(), BufferSize); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("combined rate incorrect: %v", elapsed)
	}
}
