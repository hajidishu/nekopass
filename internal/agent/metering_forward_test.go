package agent

import (
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func TestMeteredGroupUsesTheSelectedExitRate(t *testing.T) {
	target, _ := inboundEcho(t, false)
	peers := []*pb.EgressPeer{}
	var rule *pb.Rule
	for i, mode := range []string{"plain_tcp", "plain_h2"} {
		exit, _, cfg, r := h2Fixture(t, target)
		randomFixture(t, cfg, r, "chacha20-poly1305")
		cfg.Node.NodeId = int64(3 + i)
		cfg.Node.TunnelProtocol = mode
		if err := exit.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		peers = append(peers, &pb.EgressPeer{NodeId: int64(3 + i), Host: r.TunnelHost, Port: r.TunnelPort, Token: r.TunnelToken, Protocol: mode, Tls: r.Tls, Weight: 1, TrafficRate: []int64{5000, 20000}[i]})
		rule = r
	}
	state, err := OpenState(filepath.Join(t.TempDir(), "entry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	entry, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()
	rule.EgressNodeId = 0
	rule.EgressGroupId = 9
	rule.EgressStrategy = "round_robin"
	rule.EgressPeers = peers
	rule.Enabled = true
	rule.Protocol = "tcp"
	rule.ListenHost = "127.0.0.1"
	rule.Targets = []string{target}
	rule.MeteringConfigured = true
	rule.TrafficRate = 10000 // Must use the selected peer instead of this parent rate.
	cfg := &pb.ControlMessage{Node: &pb.NodeConfig{Enabled: true, MaxConnections: 100, DialTimeoutSeconds: 8, SecurityConfigured: true}, Users: []*pb.UserPolicy{{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1000, MeteringConfigured: true}}, Rules: []*pb.Rule{rule}}
	if err = entry.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for range 2 {
		c, err := net.Dial("tcp", entry.listeners[rule.Id].ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 5)
		if _, err = io.ReadFull(c, b); err != nil || string(b) != "hello" {
			t.Fatal(err, string(b))
		}
	}
	until := time.Now().Add(time.Second)
	for entry.counters[rule.Id].Load() != 20 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	entry.users[5].mu.Lock()
	raw, charged := entry.users[5].disk.Traffic, entry.users[5].disk.Charged
	entry.users[5].mu.Unlock()
	if raw != 20 || charged != 25 {
		t.Fatal("group ignored actual exit rate", raw, charged)
	}
	updated := proto.Clone(cfg).(*pb.ControlMessage)
	updated.Rules[0].EgressPeers[0].TrafficRate = 30000
	if err = entry.Apply(updated); err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err = c.Read(b[:]); err == nil {
			t.Fatal("old-rate session survived rate change")
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("old-rate session was left open")
		}
	}
}

func TestMeteredTCPForwardingAcrossTransports(t *testing.T) {
	for _, mode := range []string{"random_tcp", "random_h2", "plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "tls_h3"} {
		t.Run(mode, func(t *testing.T) {
			target, _ := inboundEcho(t, false)
			exit, _, cfg, r := h2Fixture(t, target)
			randomFixture(t, cfg, r, "chacha20-poly1305")
			cfg.Node.TunnelProtocol = mode
			r.TunnelProtocol = mode
			if mode == "tls_tcp" {
				cfg.Node.Tls.PaddingEnabled = true
				r.Tls.PaddingEnabled = true
			}
			if err := exit.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			state, err := OpenState(filepath.Join(t.TempDir(), "entry.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			entry, err := NewEngine(state, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Close()
			r.Enabled = true
			r.Protocol = "tcp"
			r.ListenHost = "127.0.0.1"
			r.Targets = []string{target}
			r.MeteringConfigured = true
			r.TrafficRate = 25000
			if err = entry.Apply(&pb.ControlMessage{Node: &pb.NodeConfig{Enabled: true, MaxConnections: 100, DialTimeoutSeconds: 8, SecurityConfigured: true}, Users: []*pb.UserPolicy{{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1 << 20, MeteringConfigured: true}}, Rules: []*pb.Rule{r}}); err != nil {
				t.Fatal(err)
			}
			client, err := net.Dial("tcp", entry.listeners[r.Id].ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("ten-bytes!")
			if _, err = client.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(client, got); err != nil || string(got) != string(payload) {
				t.Fatal("payload changed", err)
			}
			until := time.Now().Add(time.Second)
			for entry.counters[r.Id].Load() != 20 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			entry.users[5].mu.Lock()
			raw, charged := entry.users[5].disk.Traffic, entry.users[5].disk.Charged
			entry.users[5].mu.Unlock()
			if raw != 20 || charged != 50 {
				t.Fatal("tunnel padding/framing charged or multiplier lost", raw, charged)
			}
		})
	}
}

func TestMeteredUDPFreeAndFractionalForwarding(t *testing.T) {
	for _, rate := range []int64{0, 5000, 20000} {
		t.Run(strconv.FormatInt(rate, 10), func(t *testing.T) {
			echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				b := make([]byte, maxDatagram)
				for {
					n, addr, err := echo.ReadFromUDP(b)
					if err != nil {
						return
					}
					echo.WriteToUDP(b[:n], addr)
				}
			}()
			state, err := OpenState(filepath.Join(t.TempDir(), "entry.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			entry, err := NewEngine(state, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Close()
			p := &pb.UserPolicy{Id: 1, Enabled: true, Issued: 1000, MeteringConfigured: true, QuotaBlocked: rate == 0}
			if rate == 0 {
				p.Issued = 0
			}
			r := &pb.Rule{Id: 1, UserId: 1, Enabled: true, Protocol: "udp", ListenHost: "127.0.0.1", Targets: []string{echo.LocalAddr().String()}, MeteringConfigured: true, TrafficRate: rate}
			if err = entry.Apply(&pb.ControlMessage{Node: &pb.NodeConfig{Enabled: true, MaxConnections: 100, DialTimeoutSeconds: 8, SecurityConfigured: true}, Users: []*pb.UserPolicy{p}, Rules: []*pb.Rule{r}}); err != nil {
				t.Fatal(err)
			}
			c, err := net.DialUDP("udp", nil, entry.udpListeners[1].conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for _, data := range [][]byte{{1, 2, 3}, {}, {4, 5}} {
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write(data)
				b := make([]byte, 100)
				n, err := c.Read(b)
				if err != nil || string(b[:n]) != string(data) {
					t.Fatal("datagram changed", err)
				}
			}
			until := time.Now().Add(time.Second)
			for entry.counters[1].Load() != 10 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			entry.users[1].mu.Lock()
			raw, charged := entry.users[1].disk.Traffic, entry.users[1].disk.Charged
			entry.users[1].mu.Unlock()
			if raw != 10 || charged != 10*rate/10000 {
				t.Fatal("UDP billing incorrect", raw, charged, rate)
			}
		})
	}
}
