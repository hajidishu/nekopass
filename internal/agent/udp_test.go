package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

func TestUDPDirectPreservesDatagramsAndMetersPayloadOnly(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], addr)
		}
	}()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	config := &pb.ControlMessage{Users: []*pb.UserPolicy{{Id: 1, Enabled: true, QuotaUnlimited: true}}, Rules: []*pb.Rule{{Id: 1, UserId: 1, Enabled: true, Protocol: "udp", ListenHost: "127.0.0.1", Targets: []string{echo.LocalAddr().String()}}}}
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	listener := engine.udpListeners[1]
	if listener == nil {
		t.Fatal("UDP listener missing")
	}
	client, err := net.DialUDP("udp", nil, listener.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payloads := [][]byte{[]byte("hello"), {}, bytes.Repeat([]byte("x"), 45000)}
	var used int64
	for _, p := range payloads {
		client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = client.Write(p); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 65535)
		n, err := client.Read(b)
		if err != nil || !bytes.Equal(b[:n], p) {
			t.Fatal("datagram boundary or empty packet lost", err)
		}
		used += int64(2 * len(p))
	}
	deadline := time.Now().Add(time.Second)
	for engine.counters[1].Load() != used && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if engine.counters[1].Load() != used {
		t.Fatal("UDP overhead charged or payload lost", engine.counters[1].Load(), used)
	}
	config.Rules[0].Enabled = false
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	if engine.udpListeners[1] != nil {
		t.Fatal("paused UDP listener still present")
	}
}

func TestNativeUDPAuthenticationReassemblyAndReplay(t *testing.T) {
	source, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var queued atomic.Int64
	id, _ := randomNativeID()
	key := "fixture-native-auth-key"
	sender := newNativePeer(context.Background(), source, target.LocalAddr().(*net.UDPAddr), key, id, &queued, true)
	defer sender.Close()
	receiver := newNativePeer(context.Background(), target, source.LocalAddr().(*net.UDPAddr), key, id, &queued, false)
	defer receiver.Close()
	payload := bytes.Repeat([]byte("payload"), 700)
	if err = sender.send(nativeData, payload); err != nil {
		t.Fatal(err)
	}
	var packets [][]byte
	for i := 0; i < (len(payload)+nativePartSize-1)/nativePartSize; i++ {
		target.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1500)
		n, _, err := target.ReadFromUDP(b)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, append([]byte{}, b[:n]...))
	}
	bad := append([]byte{}, packets[0]...)
	bad[len(bad)-1] ^= 1
	if _, _, _, _, _, _, _, _, ok := decodeNative(bad, key, true); ok {
		t.Fatal("forged packet accepted")
	}
	for i := len(packets) - 1; i >= 0; i-- {
		_, _, seq, kind, msg, index, total, body, ok := decodeNative(packets[i], key, true)
		if !ok {
			t.Fatal("valid MAC rejected")
		}
		receiver.receive(seq, kind, msg, index, total, body)
	}
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, err := receiver.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatal("out-of-order fragments corrupted", err)
	}
	for _, p := range packets {
		_, _, seq, kind, msg, index, total, body, _ := decodeNative(p, key, true)
		receiver.receive(seq, kind, msg, index, total, body)
	}
	if len(receiver.queue) != 0 || queued.Load() != 0 {
		t.Fatal("replayed data delivered or fragment memory retained")
	}
}

func TestNativeUDPUnknownProbeIsSilent(t *testing.T) {
	engine, _, config, _ := h2Fixture(t, "127.0.0.1:9")
	config.Node.TunnelProtocol = "plain_udp"
	config.EgressRules[0].Protocol = "udp"
	if err := engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	if engine.syncError != "" {
		t.Fatal(engine.syncError)
	}
	conn, err := net.DialUDP("udp", nil, engine.nativeUDP.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	noise := make([]byte, 400)
	rand.Read(noise)
	conn.Write(noise)
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err = conn.Read(make([]byte, 1500)); err == nil {
		t.Fatal("untrusted UDP probe received a response")
	}
}

func TestUDPStreamTunnelTransportCombinations(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "plain_udp", "dtls_udp"} {
		t.Run(mode, func(t *testing.T) {
			echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				b := make([]byte, 65535)
				for {
					n, addr, err := echo.ReadFromUDP(b)
					if err != nil {
						return
					}
					echo.WriteToUDP(b[:n], addr)
				}
			}()
			engine, transport, config, rule := h2Fixture(t, echo.LocalAddr().String())
			config.Node.TunnelProtocol = mode
			config.EgressRules[0].Protocol = "udp"
			rule.Protocol = "udp"
			rule.TunnelProtocol = mode
			rule.Tls.Fingerprint = "off"
			if err = engine.Apply(config); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := dialDatagramTunnel(ctx, ctx, rule, echo.LocalAddr().String(), transport, &engine.udpQueued)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if mode == "plain_udp" && c.(*nativePeer).queued != &engine.udpQueued {
				t.Fatal("native ingress created a per-session receive budget")
			}
			for _, p := range [][]byte{{}, []byte("udp packet"), bytes.Repeat([]byte("x"), 45000)} {
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = c.Write(p); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 65535)
				n, err := c.Read(b)
				if err != nil || !bytes.Equal(b[:n], p) {
					t.Fatal("UDP data corrupted", err, n, len(p))
				}
			}
		})
	}
}

func TestUDPAllowanceNeverSplitsDatagram(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	a := newAccount(1, DiskUser{Issued: 5}, state)
	if err = a.configure(&pb.UserPolicy{Id: 1, Enabled: true, Issued: 5}); err != nil {
		t.Fatal(err)
	}
	if err = a.takeDatagram(6); err == nil {
		t.Fatal("partial allowance accepted a larger packet")
	}
	if a.disk.Spent != 0 {
		t.Fatal("rejected datagram consumed allowance")
	}
	if err = a.takeDatagram(5); err != nil {
		t.Fatal(err)
	}
	if err = a.takeDatagram(0); err == nil {
		t.Fatal("exhausted user can continue zero-length packets")
	}
}
