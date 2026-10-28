package agent

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/networkpolicy"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
	"google.golang.org/protobuf/proto"
)

func randomUDPEcho(t testing.TB) string {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			n, from, err := socket.ReadFromUDP(buf)
			if err != nil {
				return
			}
			socket.WriteToUDP(buf[:n], from)
		}
	}()
	return socket.LocalAddr().String()
}
func randomUDPFixture(t testing.TB, name, target string) (*Engine, *h2Transport, *pb.ControlMessage, *pb.Rule) {
	e, h, c, r := h2Fixture(t, target)
	randomFixture(t, c, r, name)
	c.Node.TunnelProtocol = "random_udp"
	c.EgressRules[0].Protocol = "udp"
	r.TunnelProtocol = "random_udp"
	r.Protocol = "udp"
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	return e, h, c, r
}
func TestRandomUDPAlgorithmsMultiplexAndAuthorization(t *testing.T) {
	for _, name := range []string{tunnelcrypto.ChaCha20Poly1305, tunnelcrypto.AES256GCM} {
		t.Run(name, func(t *testing.T) {
			target := randomUDPEcho(t)
			exit, h, c, r := randomUDPFixture(t, name, target)
			secondTarget := randomUDPEcho(t)
			grant := proto.Clone(c.EgressRules[0]).(*pb.EgressRule)
			grant.RuleId++
			grant.UserId++
			grant.Targets = []string{secondTarget}
			c.EgressRules = append(c.EgressRules, grant)
			c.Revision++
			if err := exit.Apply(c); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var queued atomic.Int64
			first, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			r2 := proto.Clone(r).(*pb.Rule)
			r2.Id++
			r2.UserId++
			second, err := h.randomUDP.Dial(ctx, ctx, r2, secondTarget, &queued)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.(*randomUDPFlow).association != second.(*randomUDPFlow).association {
				t.Fatal("rules did not reuse node association")
			}
			var wg sync.WaitGroup
			for i, conn := range []net.Conn{first, second} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := range 10 {
						data := bytes.Repeat([]byte{byte(i + 1), byte(j)}, j*500)
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						if _, err := conn.Write(data); err != nil {
							t.Error(err)
							return
						}
						buf := make([]byte, maxDatagram)
						n, err := conn.Read(buf)
						if err != nil || !bytes.Equal(buf[:n], data) {
							t.Error("crossed flow / datagram corruption", err)
							return
						}
					}
				}()
			}
			wg.Wait()
			for _, bad := range []*pb.Rule{func() *pb.Rule { b := proto.Clone(r).(*pb.Rule); b.UserId++; return b }(), func() *pb.Rule { b := proto.Clone(r).(*pb.Rule); b.QuotaEpoch++; return b }(), func() *pb.Rule { b := proto.Clone(r).(*pb.Rule); b.Id += 100; return b }()} {
				if conn, err := h.randomUDP.Dial(ctx, ctx, bad, target, &queued); err == nil {
					conn.Close()
					t.Fatal("foreign grant accepted")
				}
			}
			if conn, err := h.randomUDP.Dial(ctx, ctx, r, secondTarget, &queued); err == nil {
				conn.Close()
				t.Fatal("foreign target accepted")
			}
			exit.randomUDP.mu.Lock()
			sessions := len(exit.randomUDP.associations)
			exit.randomUDP.mu.Unlock()
			if sessions != 1 {
				t.Fatal("duplicate handshake sessions", sessions)
			}
			first.Close()
			second.Close()
			if queued.Load() != 0 {
				t.Fatal("closed flows retained queued bytes", queued.Load())
			}
		})
	}
}

// Faults are applied to complete UDP packets. This exercises the actual wire
// parser, cookie retries, reply deduplication, fragment reassembly and replay.
type randomUDPProxy struct {
	front, back       *net.UDPConn
	mu                sync.Mutex
	client            *net.UDPAddr
	request, response func([]byte) [][]byte
	max               atomic.Int64
}

func newRandomUDPProxy(t testing.TB, remote *net.UDPAddr) *randomUDPProxy {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	p := &randomUDPProxy{front: front, back: back}
	t.Cleanup(func() { front.Close(); back.Close() })
	forward := func(input *net.UDPConn, out *net.UDPConn, request bool) {
		buf := make([]byte, 1500)
		for {
			n, from, err := input.ReadFromUDP(buf)
			if err != nil {
				return
			}
			for high := p.max.Load(); int64(n) > high; high = p.max.Load() {
				if p.max.CompareAndSwap(high, int64(n)) {
					break
				}
			}
			wire := bytes.Clone(buf[:n])
			p.mu.Lock()
			destination := p.client
			hook := p.response
			if request {
				p.client = from
				destination = remote
				hook = p.request
			}
			packets := [][]byte{wire}
			if hook != nil {
				packets = hook(wire)
			}
			p.mu.Unlock()
			if destination != nil {
				for _, data := range packets {
					out.WriteToUDP(data, destination)
				}
			}
		}
	}
	go forward(front, back, true)
	go forward(back, front, false)
	return p
}
func reverseBatch(count int) func([]byte) [][]byte {
	var saved [][]byte
	return func(wire []byte) [][]byte {
		if len(saved) == count {
			return [][]byte{wire}
		}
		saved = append(saved, wire)
		if len(saved) < count {
			return nil
		}
		if len(saved) > count {
			return [][]byte{wire}
		}
		out := make([][]byte, 0, count+1)
		for i := len(saved) - 1; i >= 0; i-- {
			out = append(out, saved[i])
		}
		out = append(out, saved[0])
		return out
	}
}
func TestRandomUDPLossReorderReplayAndMTU(t *testing.T) {
	target := randomUDPEcho(t)
	exit, h, _, r := randomUDPFixture(t, tunnelcrypto.AES256GCM, target)
	proxy := newRandomUDPProxy(t, exit.randomUDP.socket.LocalAddr().(*net.UDPAddr))
	droppedInitial, droppedReply := false, false
	proxy.mu.Lock()
	proxy.request = func(wire []byte) [][]byte {
		if len(wire) == tunnelcrypto.DatagramInitialSize && !droppedInitial {
			droppedInitial = true
			return nil
		}
		return [][]byte{wire}
	}
	proxy.response = func(wire []byte) [][]byte {
		if len(wire) == 129 && !droppedReply {
			droppedReply = true
			return nil
		}
		return [][]byte{wire}
	}
	proxy.mu.Unlock()
	r.TunnelHost = "127.0.0.1"
	r.TunnelPort = int32(proxy.front.LocalAddr().(*net.UDPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal("handshake retransmission", err)
	}
	defer conn.Close()
	data := bytes.Repeat([]byte("packet"), 7500)
	parts := (len(data) + nativePartSize - 1) / nativePartSize
	proxy.mu.Lock()
	if !droppedInitial || !droppedReply {
		proxy.mu.Unlock()
		t.Fatal("faults not applied")
	}
	proxy.request = reverseBatch(parts)
	proxy.response = reverseBatch(parts)
	proxy.mu.Unlock()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(data); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxDatagram)
	n, err := conn.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], data) {
		t.Fatal("out-of-order fragments", err, n)
	}
	proxy.mu.Lock()
	drop := true
	proxy.request = func(wire []byte) [][]byte {
		if drop {
			drop = false
			return nil
		}
		return [][]byte{wire}
	}
	proxy.response = nil
	proxy.mu.Unlock()
	if _, err = conn.Write(bytes.Repeat([]byte{1}, 3000)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("after-loss")); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf)
	if err != nil || string(buf[:n]) != "after-loss" {
		t.Fatal("loss blocked subsequent datagrams", err, n)
	}
	if proxy.max.Load() > tunnelcrypto.DatagramMTU {
		t.Fatal("MTU exceeded", proxy.max.Load())
	}
	exit.randomUDP.mu.Lock()
	var all []*randomUDPAssociation
	for _, a := range exit.randomUDP.associations {
		all = append(all, a)
	}
	exit.randomUDP.mu.Unlock()
	for _, a := range all {
		a.expire(time.Now().Add(4 * time.Second))
	}
	if exit.udpQueued.Load() != 0 {
		t.Fatal("incomplete fragments retained memory", exit.udpQueued.Load())
	}
	conn.Close()
	if queued.Load() != 0 {
		t.Fatal("receive memory leaked", queued.Load())
	}
}
func TestRandomUDPMeteringFreeAndFinite(t *testing.T) {
	for _, rate := range []int64{0, 15000} {
		t.Run(strconv.FormatInt(rate, 10), func(t *testing.T) {
			target := randomUDPEcho(t)
			_, _, _, r := randomUDPFixture(t, tunnelcrypto.ChaCha20Poly1305, target)
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
			r.Protocol = "udp"
			r.ListenHost = "127.0.0.1"
			r.Targets = []string{target}
			r.MeteringConfigured = true
			r.TrafficRate = rate
			user := &pb.UserPolicy{Id: 5, Enabled: true, QuotaEpoch: 3, Issued: 1000, MeteringConfigured: true, QuotaBlocked: rate == 0}
			if rate == 0 {
				user.Issued = 0
			}
			if err = entry.Apply(&pb.ControlMessage{Node: &pb.NodeConfig{Enabled: true, MaxConnections: 100, DialTimeoutSeconds: 8, SecurityConfigured: true}, Users: []*pb.UserPolicy{user}, Rules: []*pb.Rule{r}}); err != nil {
				t.Fatal(err)
			}
			client, err := net.DialUDP("udp", nil, entry.udpListeners[r.Id].conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("ten-bytes!")
			client.Write(payload)
			buf := make([]byte, 100)
			n, err := client.Read(buf)
			if err != nil || !bytes.Equal(buf[:n], payload) {
				t.Fatal("payload", err)
			}
			until := time.Now().Add(time.Second)
			for entry.counters[r.Id].Load() != 20 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			entry.users[5].mu.Lock()
			raw, charged := entry.users[5].disk.Traffic, entry.users[5].disk.Charged
			entry.users[5].mu.Unlock()
			if raw != 20 || charged != 20*rate/10000 {
				t.Fatal("overhead charged or multiplier lost", raw, charged, rate)
			}
		})
	}
}
func TestRandomUDPACLRevocationAndKeyRotation(t *testing.T) {
	target := randomUDPEcho(t)
	exit, h, c, r := randomUDPFixture(t, tunnelcrypto.ChaCha20Poly1305, target)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c.Node.SecurityConfigured = true
	c.Node.TargetDenyCidrs = networkpolicy.Defaults()
	c.Revision++
	if err = exit.Apply(c); err != nil {
		t.Fatal(err)
	}
	if denied, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued); err != errTunnelTarget {
		if denied != nil {
			denied.Close()
		}
		t.Fatal("target ACL bypassed or target error misclassified", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("live ACL stream survived")
	}
	c.Node.TargetDenyCidrs = nil
	old := proto.Clone(r).(*pb.Rule)
	key, _ := tunnelcrypto.GenerateKey()
	c.Node.Random.Key = key
	r.Random.Key = key
	c.Revision++
	if err = exit.Apply(c); err != nil {
		t.Fatal(err)
	}
	peer, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal("new key failed", err)
	}
	peer.Close()
	badctx, stop := context.WithTimeout(ctx, 800*time.Millisecond)
	defer stop()
	if peer, err = h.randomUDP.Dial(badctx, ctx, old, target, &queued); err == nil {
		peer.Close()
		t.Fatal("old key accepted")
	}
	probe, err := net.DialUDP("udp", nil, exit.randomUDP.socket.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	probe.SetDeadline(time.Now().Add(100 * time.Millisecond))
	probe.Write(bytes.Repeat([]byte("GET / HTTP/1.1"), 9))
	if n, err := probe.Read(make([]byte, 1500)); n != 0 || err == nil {
		t.Fatal("unauthenticated probe received data")
	}
}

func TestRandomUDPSourceBindingAndSessionRecovery(t *testing.T) {
	target := randomUDPEcho(t)
	exit, h, _, r := randomUDPFixture(t, tunnelcrypto.AES256GCM, target)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var queued atomic.Int64
	first, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	a := first.(*randomUDPFlow).association
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	frame := make([]byte, randomUDPFrameSize+8)
	frame[0] = randomUDPPing
	frame[14] = 1
	wire, err := a.crypto.Seal(frame)
	if err != nil {
		t.Fatal(err)
	}
	other.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	other.WriteToUDP(wire, exit.randomUDP.socket.LocalAddr().(*net.UDPAddr))
	if n, err := other.Read(make([]byte, 1500)); n != 0 || err == nil {
		t.Fatal("source address migrated without challenge")
	}
	a.socket.Close()
	select {
	case <-a.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("dead socket did not close association")
	}
	second, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal("automatic session recovery", err)
	}
	defer second.Close()
	if second.(*randomUDPFlow).association.crypto.ID() == a.crypto.ID() {
		t.Fatal("recovery reused old session keys")
	}
	second.SetDeadline(time.Now().Add(time.Second))
	second.Write([]byte("recovered"))
	buf := make([]byte, 100)
	n, err := second.Read(buf)
	if err != nil || string(buf[:n]) != "recovered" {
		t.Fatal("recovered payload", err)
	}
}

func TestRandomUDPRemoteCloseReleasesUnreadBuffers(t *testing.T) {
	target := randomUDPEcho(t)
	exit, h, _, r := randomUDPFixture(t, tunnelcrypto.ChaCha20Poly1305, target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f := conn.(*randomUDPFlow)
	exit.randomUDP.mu.Lock()
	remote := exit.randomUDP.associations[f.association.crypto.ID()]
	exit.randomUDP.mu.Unlock()
	remote.mu.Lock()
	serverFlow := remote.flows[f.id]
	remote.mu.Unlock()
	serverFlow.Write(bytes.Repeat([]byte{1}, 100))
	serverFlow.Close()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		f.association.mu.Lock()
		received := !f.remoteClosedAt.IsZero()
		f.association.mu.Unlock()
		if received {
			break
		}
		time.Sleep(time.Millisecond)
	}
	f.association.expire(time.Now().Add(2 * time.Second))
	f.association.mu.Lock()
	left := len(f.association.flows)
	f.association.mu.Unlock()
	if left != 0 || queued.Load() != 0 {
		t.Fatal("unread close leaked flow or buffers", left, queued.Load())
	}
	if peer, err := h.randomUDP.Dial(ctx, ctx, r, target, &queued); err != nil {
		t.Fatal("closing flow closed shared association", err)
	} else {
		peer.Close()
	}
}
