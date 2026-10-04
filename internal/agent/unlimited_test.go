package agent

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"golang.org/x/time/rate"
)

func TestUnlimitedAccountingAndModeChanges(t *testing.T) {
	state, a := testAccount(t, 0, 1<<20)
	unlimited := &pb.UserPolicy{Id: 1, Enabled: true, QuotaUnlimited: true, SpeedBps: 0, MaxConnections: 0}
	if err := a.configure(unlimited); err != nil {
		t.Fatal(err)
	}
	if a.limiter.Limit() != rate.Inf {
		t.Fatal("zero speed did not remove limiter")
	}
	for i := 0; i < 100; i++ {
		if !a.acquire() {
			t.Fatal("unlimited connection rejected")
		}
	}
	a.active.Store(0)
	total := 2*ReservationBlock + 123
	for left := total; left > 0; {
		n, err := a.take(context.Background(), int(min(int64(BufferSize), left)))
		if err != nil {
			t.Fatal(err)
		}
		a.count(n)
		left -= int64(n)
	}
	if a.disk.Issued != 0 || a.disk.Spent != 0 || a.disk.Traffic != total || a.disk.UnlimitedSpent < total {
		t.Fatalf("unlimited fabricated finite grants: %+v", a.disk)
	}
	a.mu.Lock()
	report, wanted, err := a.report()
	if err == nil {
		err = a.persist()
	}
	a.mu.Unlock()
	if err != nil || wanted || !report.QuotaUnlimited || report.UnlimitedSpent < total {
		t.Fatal(report, wanted, err)
	}
	users, err := state.LoadUsers()
	if err != nil {
		t.Fatal(err)
	}
	resumed := newAccount(1, users[1], state)
	if err = resumed.configure(unlimited); err != nil {
		t.Fatal(err)
	}
	spent := resumed.disk.UnlimitedSpent
	if _, err = resumed.take(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	resumed.count(1)
	if resumed.disk.UnlimitedSpent != spent+ReservationBlock {
		t.Fatal("unlimited reservation replayed after restart")
	}
	finite := &pb.UserPolicy{Id: 1, Enabled: true, Issued: 4096, SpeedBps: 125000, MaxConnections: 1}
	if err = resumed.configure(finite); err != nil {
		t.Fatal(err)
	}
	if resumed.limiter.Limit() != 125000 || !resumed.acquire() || resumed.acquire() {
		t.Fatal("finite limits did not return")
	}
	n, err := resumed.take(context.Background(), 8192)
	if err != nil || n != 4096 {
		t.Fatal(n, err)
	}
	resumed.count(n)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = resumed.take(ctx, 1); err == nil {
		t.Fatal("unlimited credit leaked into finite mode")
	}
	finite.ExpiresUnix = time.Now().Unix() - 1
	finite.QuotaUnlimited = true
	resumed.configure(finite)
	if _, err = resumed.take(context.Background(), 1); err == nil {
		t.Fatal("unlimited mode bypassed expiry")
	}
}

func TestUnlimitedNodeConnectionCap(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := NewEngine(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	cfg := &pb.ControlMessage{Node: defaultNodeConfig(), Users: []*pb.UserPolicy{{Id: 1, Enabled: true, QuotaUnlimited: true}}, Rules: []*pb.Rule{{Id: 1, UserId: 1, Enabled: true, ListenHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: int32(target.Addr().(*net.TCPAddr).Port)}}}
	cfg.Node.MaxConnections = 2
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	addr := engine.listeners[1].ln.Addr().String()
	connect := func() net.Conn {
		t.Helper()
		c, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	exchange := func(c net.Conn) {
		t.Helper()
		if _, e := c.Write([]byte("x")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 1)
		if _, e := io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
	}
	a, b := connect(), connect()
	defer a.Close()
	defer b.Close()
	exchange(a)
	exchange(b)
	denied := connect()
	defer denied.Close()
	denied.Write([]byte("x"))
	if _, err = denied.Read(make([]byte, 1)); err == nil {
		t.Fatal("finite node cap not applied")
	}
	cfg.Node.MaxConnections = 0
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	c := connect()
	defer c.Close()
	exchange(c)
}
