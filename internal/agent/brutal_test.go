package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/quic-go/quic-go/brutal"
	"google.golang.org/protobuf/proto"
)

func enableBrutalFixture(t testing.TB, e *Engine, c *pb.ControlMessage, r *pb.Rule, send, receive uint64) {
	t.Helper()
	r.Congestion = &pb.TunnelCongestion{Brutal: true, SendBps: send, ReceiveBps: receive}
	c.TunnelLinks[0].Congestion = &pb.TunnelCongestion{Brutal: true, SendBps: receive, ReceiveBps: send}
	c.Node.BrutalEnabled = true
	c.Node.BandwidthUpBps = receive
	c.Node.BandwidthDownBps = send
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
}

func TestBrutalNativeUDPAllSecurityModes(t *testing.T) {
	for _, mode := range []string{"plain_udp", "dtls_udp", "random_udp"} {
		t.Run(mode, func(t *testing.T) {
			target := randomUDPEcho(t)
			e, h, c, r := h2Fixture(t, target)
			c.Node.TunnelProtocol = mode
			c.EgressRules[0].Protocol = "udp"
			r.TunnelProtocol = mode
			r.Protocol = "udp"
			if mode == "random_udp" {
				randomFixture(t, c, r, "chacha20-poly1305")
			}
			enableBrutalFixture(t, e, c, r, 1250000, 1250000)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var queued atomic.Int64
			conn, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for _, body := range [][]byte{{}, []byte("Brutal"), bytes.Repeat([]byte{0x52}, 45000), bytes.Repeat([]byte{0x39}, 65507)} {
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				if _, err = conn.Write(body); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, maxDatagram)
				n, err := conn.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:n], body) {
					t.Fatal("datagram boundary or payload changed", len(body), n, err)
				}
			}
			conn.Close()
			if queued.Load() != 0 {
				t.Fatal("receive memory was not released", queued.Load())
			}
		})
	}
}

func TestBrutalH3ConcurrentStreamsShareNodeBandwidth(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, h, c, r := h3Fixture(t, target)
	c.Node.Tls.MaxStreams = 1
	r.Tls.MaxStreams = 1
	r.Tls.PoolSize = 2
	enableBrutalFixture(t, e, c, r, 1000000, 1000000)
	h.h3.brutalBudget = brutal.NewBudget(125000)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var connections []net.Conn
	for i := 0; i < 2; i++ {
		conn, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		defer conn.Close()
	}
	h.h3.mu.Lock()
	pool := h.h3.pools[h2PoolKey(r)]
	h.h3.mu.Unlock()
	pool.mu.Lock()
	physical := len(pool.peers)
	pool.mu.Unlock()
	if physical != 2 {
		t.Fatal("test did not create separate QUIC connections", physical)
	}
	payload := bytes.Repeat([]byte("b"), 80000)
	start := time.Now()
	var wg sync.WaitGroup
	for _, conn := range connections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			go func() { _, err := conn.Write(payload); done <- err }()
			received := make([]byte, len(payload))
			_, err := io.ReadFull(conn, received)
			if err != nil || !bytes.Equal(received, payload) {
				t.Error("Brutal H3 payload failed", err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Fatal("connections bypassed shared node bandwidth", elapsed)
	}
}

func TestBrutalH3UDPAndInvalidConfiguration(t *testing.T) {
	target := randomUDPEcho(t)
	e, h, c, r := h3Fixture(t, target)
	c.EgressRules[0].Protocol = "udp"
	r.Protocol = "udp"
	enableBrutalFixture(t, e, c, r, 1250000, 1250000)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := h.h3.Dial(ctx, ctx, r, target, true, &queued)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, body := range [][]byte{[]byte("packet"), bytes.Repeat([]byte{7}, 45000)} {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write(body); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, maxDatagram)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], body) {
			t.Fatal("CONNECT-UDP failed", err)
		}
	}
	bad := proto.Clone(c).(*pb.ControlMessage)
	bad.Node.BandwidthUpBps = 0
	if e.Apply(bad) == nil {
		t.Fatal("invalid bandwidth applied")
	}
}

func TestBrutalFeedbackRejectsUnsentAndDecreasingCounters(t *testing.T) {
	b, err := newDatagramBrutal(&pb.TunnelCongestion{Brutal: true, SendBps: 100000, ReceiveBps: 100000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := b.frame([]byte("x"))
	plain, ack, ok := b.receive(body)
	if !ok || string(plain) != "x" || len(ack) != brutalFeedbackSize {
		t.Fatal("feedback framing")
	}
	b.feedback(ack)
	if b.lastHigh != 1 || b.lastReceived != 1 {
		t.Fatal("valid feedback ignored")
	}
	for _, change := range []func([]byte){func(v []byte) { binary.BigEndian.PutUint64(v, 999) }, func(v []byte) { binary.BigEndian.PutUint64(v[8:], 999) }, func(v []byte) { binary.BigEndian.PutUint64(v[8:], 0) }} {
		bad := append([]byte(nil), ack...)
		change(bad)
		b.feedback(bad)
		if b.lastHigh != 1 || b.lastReceived != 1 {
			t.Fatal("invalid feedback changed state")
		}
	}
	if _, _, ok := b.receive(body[:3]); ok {
		t.Fatal("truncated feedback header accepted")
	}
}

func TestBrutalUDPConfigurationMismatchFailsBeforeTargetData(t *testing.T) {
	for _, mode := range []string{"plain_udp", "random_udp"} {
		for _, serverEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/server=%t", mode, serverEnabled), func(t *testing.T) {
				target := randomUDPEcho(t)
				e, h, c, r := h2Fixture(t, target)
				c.Node.TunnelProtocol = mode
				c.EgressRules[0].Protocol = "udp"
				r.TunnelProtocol = mode
				r.Protocol = "udp"
				if mode == "random_udp" {
					randomFixture(t, c, r, "aes-256-gcm")
				}
				cfg := &pb.TunnelCongestion{Brutal: true, SendBps: 1250000, ReceiveBps: 1250000}
				if serverEnabled {
					c.Node.BrutalEnabled = true
					c.Node.BandwidthUpBps = 1250000
					c.Node.BandwidthDownBps = 1250000
					c.TunnelLinks[0].Congestion = cfg
				} else {
					r.Congestion = cfg
				}
				if err := e.Apply(c); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
				defer cancel()
				var queued atomic.Int64
				conn, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
				if err == nil {
					conn.Close()
					t.Fatal("mismatched framing configuration was accepted")
				}
			})
		}
	}
}
