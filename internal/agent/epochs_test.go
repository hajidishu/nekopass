package agent

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"path/filepath"
	"testing"
)

func TestQuotaResetSeparatesInflightUsageAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, e := OpenState(path)
	if e != nil {
		t.Fatal(e)
	}
	engine, e := NewEngine(state, 100)
	if e != nil {
		t.Fatal(e)
	}
	oldConfig := &pb.ControlMessage{Revision: 1, Users: []*pb.UserPolicy{{Id: 7, Enabled: true, Issued: 1000}}}
	if e = engine.Apply(oldConfig); e != nil {
		t.Fatal(e)
	}
	old := engine.users[7]
	old.active.Store(1)
	if n, e := old.tryTake(100); n != 100 || e != nil {
		t.Fatal(n, e)
	}
	old.count(80)
	report, e := engine.Report()
	if e != nil {
		t.Fatal(e)
	}
	config := &pb.ControlMessage{Revision: 2, Users: []*pb.UserPolicy{{Id: 7, Enabled: true, Issued: 500, QuotaEpoch: 1}}, AcknowledgedUsage: report.Usage}
	if e = engine.Apply(config); e != nil {
		t.Fatal(e)
	}
	// A write reserved before reset completes afterward. It belongs to epoch 0.
	old.count(20)
	old.active.Store(0)
	if old.valid() {
		t.Fatal("retired account may still allocate")
	}
	current := engine.users[7]
	if n, e := current.tryTake(500); n != 500 || e != nil {
		t.Fatal(n, e)
	}
	current.count(500)
	if n, e := current.tryTake(1); n != 0 || e != nil {
		t.Fatal("old credit leaked into new quota", n, e)
	}
	report, e = engine.Report()
	if e != nil {
		t.Fatal(e)
	}
	var oldUsage, newUsage *pb.Usage
	for _, u := range report.Usage {
		if u.QuotaEpoch == 0 {
			oldUsage = u
		} else {
			newUsage = u
		}
	}
	if oldUsage == nil || newUsage == nil || oldUsage.Traffic != 100 || newUsage.Traffic != 500 {
		t.Fatal(report.Usage)
	}
	// Acknowledging the earlier 80-byte report must not drop the 20 late bytes.
	if e = engine.Apply(config); e != nil {
		t.Fatal(e)
	}
	if len(engine.retired) != 1 {
		t.Fatal("unacknowledged late usage lost")
	}
	engine.Close()
	state.Close()
	state, e = OpenState(path)
	if e != nil {
		t.Fatal(e)
	}
	defer state.Close()
	engine, e = NewEngine(state, 100)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	cached, e := state.Config()
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.Apply(cached); e != nil {
		t.Fatal(e)
	}
	report, e = engine.Report()
	if e != nil {
		t.Fatal(e)
	}
	if len(engine.retired) != 1 || engine.users[7].disk.Epoch != 1 || engine.users[7].disk.Traffic != 500 {
		t.Fatal("period state lost on restart")
	}
	cached.AcknowledgedUsage = report.Usage
	if e = engine.Apply(cached); e != nil {
		t.Fatal(e)
	}
	pending, e := state.LoadRetired()
	if e != nil || len(pending) != 0 || len(engine.retired) != 0 {
		t.Fatal("acknowledged retired ledger retained", pending, e)
	}
}
