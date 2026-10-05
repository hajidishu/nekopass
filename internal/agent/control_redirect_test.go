package agent

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/grpc"
)

type redirectFixtureServer struct {
	pb.UnimplementedControlServer
	endpoint    atomic.Value
	connections atomic.Int32
}

func (s *redirectFixtureServer) Connect(stream pb.Control_ConnectServer) error {
	s.connections.Add(1)
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(&pb.ControlMessage{Revision: 1, ControlEndpoint: s.endpoint.Load().(string)}); err != nil {
			return err
		}
	}
}

func TestAgentAutomaticallyReconnectsToAuthenticatedControlRedirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &redirectFixtureServer{}
	fixture.endpoint.Store("")
	srv := grpc.NewServer()
	pb.RegisterControlServer(srv, fixture)
	go srv.Serve(ln)
	defer srv.Stop()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	e, err := NewEngine(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	origin := "http://" + ln.Addr().String()
	go func() { done <- Run(ctx, e, origin, "fixture-node-token") }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Agent did not stop")
		}
	}()
	wait := func(predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if predicate() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("expected reconnect did not occur")
	}
	wait(func() bool { return fixture.connections.Load() == 1 })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	destination := "http://localhost:" + port
	fixture.endpoint.Store(destination)
	wait(func() bool { return fixture.connections.Load() == 2 })
	if got, err := e.redirectedControlEndpoint(origin); err != nil || got != destination {
		t.Fatal("reconnected endpoint not persisted", got, err)
	}
}

func TestControlRedirectPersistsWithoutReplacingManualConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{state: state}
	origin, destination := "https://control.example.test:9443", "http://control.example.test:9443"
	if err := e.saveControlEndpoint(origin, destination); err != nil {
		t.Fatal(err)
	}
	state.Close()
	state, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	e.state = state
	if got, err := e.redirectedControlEndpoint(origin); err != nil || got != destination {
		t.Fatal("new endpoint lost on restart", got, err)
	}
	manual := "http://another-control.example.test:9443"
	if got, err := e.redirectedControlEndpoint(manual); err != nil || got != manual {
		t.Fatal("saved endpoint replaced explicit configuration", got, err)
	}
	if err := e.saveControlEndpoint(origin, "http://control.example.test:9443/path"); err == nil {
		t.Fatal("invalid redirect accepted")
	}
}
