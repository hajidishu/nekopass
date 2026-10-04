package agent

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestOneWayTrafficIsNotIdle(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 25; i++ {
			if _, e = c.Write([]byte("x")); e != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
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
	cfg := &pb.ControlMessage{Node: defaultNodeConfig(), Users: []*pb.UserPolicy{{Id: 1, Enabled: true, Issued: 1 << 20, SpeedBps: 1 << 30, MaxConnections: 10}}, Rules: []*pb.Rule{{Id: 1, UserId: 1, Enabled: true, ListenHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: int32(target.Addr().(*net.TCPAddr).Port)}}}
	cfg.Node.IdleTimeoutSeconds = 1
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", engine.listeners[1].ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(c)
	if err != nil || len(data) != 25 {
		t.Fatalf("one-way data stopped as idle: %d %v", len(data), err)
	}
	<-done
	cfg.Node.Enabled = false
	if err = engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if len(engine.listeners) != 0 {
		t.Fatal("disabled node still listening")
	}
	saved, err := state.Config()
	if err != nil || saved.Node.Enabled || saved.Node.IdleTimeoutSeconds != 1 {
		t.Fatal("central configuration not persisted")
	}
}
func TestUserIPBudgetShared(t *testing.T) {
	_, a := testAccount(t, 1<<20, 1<<20)
	a.policy.IpLimit = 1
	if !a.addIP("192.0.2.1") || !a.addIP("192.0.2.1") || a.addIP("192.0.2.2") {
		t.Fatal("user IP cap not shared")
	}
	a.removeIP("192.0.2.1")
	if a.addIP("192.0.2.2") {
		t.Fatal("released IP before last connection")
	}
	a.removeIP("192.0.2.1")
	if !a.addIP("192.0.2.2") {
		t.Fatal("IP slot not released")
	}
}
