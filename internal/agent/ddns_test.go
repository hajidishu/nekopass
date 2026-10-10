package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func waitDDNS(t *testing.T, e *Engine, generation int64, state string) *pb.DDNSStatus {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		r := e.ddnsStatus.Load()
		if r != nil && r.Generation == generation && r.State == state {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("DDNS did not reach generation %d state %s: %v", generation, state, e.ddnsStatus.Load())
	return nil
}

func TestNodeDDNSLifecycleAndOfflineRestore(t *testing.T) {
	var writes, lookups atomic.Int32
	var fail6 atomic.Bool
	var ip4 atomic.Value
	ip4.Store("203.0.113.7")
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ip4" || r.URL.Path == "/ip6" {
			lookups.Add(1)
			if r.Header.Get("Authorization") != "" {
				t.Error("token leaked to IP source")
			}
			if r.URL.Path == "/ip6" {
				if fail6.Load() {
					http.Error(w, "unavailable", 503)
				} else {
					fmt.Fprint(w, "2001:db8::7")
				}
			} else {
				fmt.Fprint(w, ip4.Load().(string))
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("API token missing")
		}
		if r.Method == "GET" {
			fmt.Fprint(w, `{"success":true,"result":[]}`)
			return
		}
		var record map[string]any
		if json.NewDecoder(r.Body).Decode(&record) != nil || record["proxied"] != false {
			t.Error("wrong DNS request")
		}
		writes.Add(1)
		fmt.Fprint(w, `{"success":true,"result":{}}`)
	}))
	defer s.Close()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	newEngine := func() *Engine {
		e, err := NewEngine(state, 0)
		if err != nil {
			t.Fatal(err)
		}
		e.ddnsClient = func() *ddns.Client {
			return &ddns.Client{APIBase: s.URL, API: s.Client(), IPv4: s.Client(), IPv6: s.Client()}
		}
		return e
	}
	e := newEngine()
	defer e.Close()
	cfg := &pb.ControlMessage{Node: defaultNodeConfig()}
	cfg.Node.Enabled = false // DNS also runs on a forwarding-disabled node.
	cfg.Node.Ddns = &pb.DDNSConfig{Enabled: true, Generation: 1, Provider: "cloudflare", RecordName: "node.example.com", Token: "fixture-token", ZoneId: strings.Repeat("a", 32), Ipv4: true, Ipv6: true, IntervalSeconds: 60, Ttl: 300, Ipv4Url: s.URL + "/ip4", Ipv6Url: s.URL + "/ip6"}
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	r := waitDDNS(t, e, 1, "ok")
	if r.Ipv4 != "203.0.113.7" || r.Ipv6 != "2001:db8::7" || r.UpdatedUnix == 0 || writes.Load() != 2 {
		t.Fatal("dual stack update failed")
	}
	for range 5 {
		if err = e.Apply(proto.Clone(cfg).(*pb.ControlMessage)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(40 * time.Millisecond)
	if lookups.Load() != 2 {
		t.Fatal("unchanged controller pushes restarted DNS polling")
	}
	fail6.Store(true)
	ip4.Store("203.0.113.8")
	cfg.Node.Ddns.Generation = 2
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	r = waitDDNS(t, e, 2, "partial")
	if r.Ipv4 != "203.0.113.8" || r.Ipv6 != "" || r.Error == "" || strings.Contains(r.Error, "fixture-token") {
		t.Fatal("partial failure report invalid")
	}
	// A stale canceled worker cannot overwrite the next generation.
	e.publishDDNS(context.Background(), &pb.DDNSStatus{Generation: 1, State: "error"})
	if e.ddnsStatus.Load().Generation != 2 {
		t.Fatal("stale generation accepted")
	}
	saved, err := state.Config()
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	fail6.Store(false)
	e2 := newEngine()
	defer e2.Close()
	if err = e2.Apply(saved); err != nil {
		t.Fatal(err)
	}
	waitDDNS(t, e2, 2, "ok") // No controller connection required after restoring cached config.
	saved.Node.Ddns.Enabled = false
	saved.Node.Ddns.Generation = 3
	if err = e2.Apply(saved); err != nil {
		t.Fatal(err)
	}
	waitDDNS(t, e2, 3, "disabled")
	before := lookups.Load()
	time.Sleep(40 * time.Millisecond)
	if lookups.Load() != before {
		t.Fatal("disabled DDNS continued fetching addresses")
	}
	report, err := e2.Report()
	if err != nil || report.ProtocolVersion != 18 {
		t.Fatal("DDNS protocol capability missing")
	}
}

func TestClosingNodeCancelsInFlightDDNS(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(canceled) }))
	defer s.Close()
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
	e.ddnsClient = func() *ddns.Client {
		return &ddns.Client{APIBase: s.URL, API: s.Client(), IPv4: s.Client(), IPv6: s.Client()}
	}
	cfg := &pb.ControlMessage{Node: defaultNodeConfig()}
	cfg.Node.Ddns = &pb.DDNSConfig{Enabled: true, Generation: 1, Provider: "cloudflare", RecordName: "node.example.com", Token: "fixture-token", Ipv4: true, IntervalSeconds: 60, Ttl: 300, Ipv4Url: s.URL, Ipv6Url: s.URL}
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request not started")
	}
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("node shutdown blocked on DNS")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("DNS request not canceled")
	}
}
