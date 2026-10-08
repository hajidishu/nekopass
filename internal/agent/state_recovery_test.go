package agent

import (
	"path/filepath"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestRestoredNodePersistsBaselinesAndNeverCachesRecoveryInstruction(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.db")
	state, err := OpenState(file)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	request, err := e.Report()
	if err != nil || !request.RestoreState || len(request.Usage) != 0 {
		t.Fatal("fresh Agent did not request restoration", err)
	}
	config := &pb.ControlMessage{Node: &pb.NodeConfig{Enabled: false}, Users: []*pb.UserPolicy{{Id: 7, Enabled: true, QuotaEpoch: 2, Issued: 700}}, StateRestore: &pb.StateRestore{InstanceId: state.Instance, Users: []*pb.UserStateBaseline{{UserId: 7, QuotaEpoch: 2, Issued: 700, Spent: 500, Released: 20, Traffic: 300}}, Rules: []*pb.RuleUsage{{RuleId: 8, Traffic: 300}}}}
	if err = e.Apply(config); err != nil {
		t.Fatal(err)
	}
	report, err := e.Report()
	if err != nil || report.RestoreState || len(report.Usage) != 1 || report.Usage[0].Spent != 500 || report.Usage[0].Traffic != 300 || report.RuleUsage[0].Traffic != 300 {
		t.Fatal("restored counters regressed", report, err)
	}
	e.Close()
	state.Close()
	state, err = OpenState(file)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cached, err := state.Config()
	if err != nil || cached.StateRestore != nil {
		t.Fatal("one-time recovery replayed on restart", err)
	}
	e, err = NewEngine(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Apply(cached); err != nil {
		t.Fatal(err)
	}
	report, err = e.Report()
	if err != nil || report.RestoreState || report.Usage[0].Traffic != 300 {
		t.Fatal("restart lost restored accounting", err)
	}
}

func TestRecoveryRejectsWrongInstanceAndInvalidBaseline(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	e, err := NewEngine(state, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	c := &pb.ControlMessage{StateRestore: &pb.StateRestore{InstanceId: "wrong-instance"}}
	if e.Apply(c) == nil {
		t.Fatal("foreign recovery accepted")
	}
	c.StateRestore.InstanceId = state.Instance
	c.StateRestore.Users = []*pb.UserStateBaseline{{UserId: 7, Issued: 10, Spent: 11}}
	if e.Apply(c) == nil {
		t.Fatal("invalid quota baseline accepted")
	}
}
