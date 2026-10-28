package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func h3PaddingFixture(t *testing.T, target string, serverPad bool) (*Engine, *h2Transport, *pb.ControlMessage, *pb.Rule) {
	t.Helper()
	e, h, c, r := h3Fixture(t, target)
	c.Node.Tls.QuicPadding = &pb.QUICPaddingConfig{Enabled: serverPad, MaxPadding: 1400, BurstBytes: 8192, BytesPerSecond: 8192}
	r.Tls.QuicPadding = proto.Clone(c.Node.Tls.QuicPadding).(*pb.QUICPaddingConfig)
	r.Tls.QuicPadding.Enabled = true
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	return e, h, c, r
}
func TestH3PaddingTCPAndPeerCompatibility(t *testing.T) {
	target, _ := inboundEcho(t, false)
	for _, profile := range []string{"adaptive"} {
		for _, both := range []bool{false, true} {
			t.Run(profile+map[bool]string{false: "/client-only", true: "/both"}[both], func(t *testing.T) {
				_, h, _, r := h3PaddingFixture(t, target, both)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				c, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				body := bytes.Repeat([]byte("native padding payload"), 6000)
				done := make(chan error, 1)
				go func() { _, err := c.Write(body); done <- err }()
				got := make([]byte, len(body))
				if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
					t.Fatal("TCP data", err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err = c.Read(make([]byte, 1)); err != io.EOF {
					t.Fatal("native FIN", err)
				}
				pool := h.h3.pools[h2PoolKey(r)]
				pool.mu.Lock()
				stats := pool.peers[0].conn.PacketPaddingStats()
				pool.mu.Unlock()
				if stats.Packets == 0 || stats.Bytes == 0 {
					t.Fatal("no native padding emitted", stats)
				}
				for _, bad := range []func(*pb.Rule){func(v *pb.Rule) { v.UserId++ }, func(v *pb.Rule) { v.Tls.ServerName = "wrong.example.test" }, func(v *pb.Rule) { v.Tls.RootCa = "" }} {
					v := proto.Clone(r).(*pb.Rule)
					bad(v)
					if c, err := h.h3.Dial(ctx, ctx, v, target, false, nil); err == nil {
						c.Close()
						t.Fatal("certificate or user verification bypassed")
					}
				}
			})
		}
	}
}
func TestH3PaddingUDPBoundaryAndRevocation(t *testing.T) {
	target := randomUDPEcho(t)
	exit, h, c, r := h3PaddingFixture(t, target, true)
	c.EgressRules[0].Protocol = "udp"
	r.Protocol = "udp"
	if err := exit.Apply(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := h.h3.Dial(ctx, ctx, r, target, true, &queued)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, body := range [][]byte{{}, []byte("native datagram"), bytes.Repeat([]byte{7}, 45000)} {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write(body); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, maxDatagram)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(body, got[:n]) {
			t.Fatal("UDP boundary or payload changed", len(body), n, err)
		}
	}
	c.EgressRules = nil
	if err := exit.Apply(c); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked UDP remained open")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("revoked flow not closed")
	}
	conn.Close()
	if queued.Load() != 0 {
		t.Fatal("queued bytes leaked", queued.Load())
	}
}
func TestH3PaddingMetering(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, _, _, r := h3PaddingFixture(t, target, true)
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
	c, err := net.Dial("tcp", entry.listeners[r.Id].ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	body := []byte("ten-bytes!")
	if _, err = c.Write(body); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(body))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for entry.counters[r.Id].Load() != 20 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	entry.users[5].mu.Lock()
	raw, charged := entry.users[5].disk.Traffic, entry.users[5].disk.Charged
	entry.users[5].mu.Unlock()
	if raw != 20 || charged != 50 {
		t.Fatal("QUIC padding charged as user payload", raw, charged)
	}
}
func TestH3PaddingPoolConcurrency(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, r := h3PaddingFixture(t, target, true)
	r.Tls.PoolSize = 1
	r.Tls.MaxStreams = 32
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for round := 0; round < 3; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
				if err != nil {
					errs <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(8 * time.Second))
				body := bytes.Repeat([]byte{byte(i + 1)}, 100+i*20)
				if _, err = c.Write(body); err != nil {
					errs <- err
					return
				}
				got := make([]byte, len(body))
				if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, body) {
					errs <- fmt.Errorf("concurrent data %d: %v", i, err)
					return
				}
				c.(interface{ CloseWrite() error }).CloseWrite()
				if _, err = io.Copy(io.Discard, c); err != nil {
					errs <- err
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	}
	pool := h.h3.pools[h2PoolKey(r)]
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.peers) != 1 || pool.peers[0].conn.PacketPaddingStats().Packets == 0 {
		t.Fatal("pool did not reuse a padded connection")
	}
}

func TestH3PaddingRealWebsiteAndFallback(t *testing.T) {
	var leaked atomic.Bool
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Stream") != "" {
			leaked.Store(true)
		}
		w.Header().Set("Alt-Svc", `h3=":1"`)
		io.WriteString(w, "ordinary fallback website")
	}))
	defer site.Close()
	e, _, c, r := h3PaddingFixture(t, "127.0.0.1:1", true)
	c.Node.Tls.FallbackUrl = site.URL
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(r.Tls.RootCa))
	tlsCfg := &tls.Config{ServerName: r.Tls.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS13}
	transport := &http3.Transport{TLSClientConfig: tlsCfg, QUICConfig: &quic.Config{EnableDatagrams: true}, EnableDatagrams: true}
	defer transport.Close()
	address := "https://127.0.0.1:" + strconv.Itoa(int(r.TunnelPort))
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(address + "/normal")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.ProtoMajor != 3 || string(body) != "ordinary fallback website" || !strings.Contains(response.Header.Get("Alt-Svc"), strconv.Itoa(int(r.TunnelPort))) {
		t.Fatal("not a working HTTP/3 website", response.Status, string(body))
	}
	tcpTransport := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true}
	defer tcpTransport.CloseIdleConnections()
	response, err = (&http.Client{Transport: tcpTransport, Timeout: 5 * time.Second}).Get(address + "/normal")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Header.Get("Alt-Svc") == "" {
		t.Fatal("HTTPS did not advertise HTTP/3")
	}
	request, _ := http.NewRequest("CONNECT", address, nil)
	request.Header.Set("Authorization", "Bearer invalid")
	request.Header.Set("X-Stream", "invalid")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "ordinary fallback website" || leaked.Load() {
		t.Fatal("fallback failed or credentials leaked")
	}
	c.Node.Tls.FallbackUrl = ""
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 404 || strings.Contains(strings.ToLower(string(body)), "nginx") {
		t.Fatal("expected ordinary 404")
	}
}

func TestH3PaddingReverseHalfClose(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	result := make(chan []byte, 1)
	go func() {
		raw, err := target.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn := raw.(*net.TCPConn)
		conn.Write(bytes.Repeat([]byte("download"), 10000))
		conn.CloseWrite()
		body, _ := io.ReadAll(conn)
		result <- body
	}()
	_, h, _, r := h3PaddingFixture(t, target.Addr().String(), true)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := h.h3.Dial(ctx, ctx, r, target.Addr().String(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(body, bytes.Repeat([]byte("download"), 10000)) {
		t.Fatal("response FIN truncated", len(body), err)
	}
	payload := bytes.Repeat([]byte("upload-after-fin"), 10000)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*h3StreamConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Closing the reader must not discard data queued before the write FIN.
	conn.Close()
	select {
	case got := <-result:
		if !bytes.Equal(got, payload) {
			t.Fatal("upload truncated after FIN", len(got))
		}
	case <-ctx.Done():
		t.Fatal("upload FIN not delivered")
	}
}

func TestH3PaddingServerOnlyTunnel(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, r := h3PaddingFixture(t, target, true)
	r.Tls.QuicPadding.Enabled = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("server-only"), 300)
	go c.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal(err)
	}
	c.(interface{ CloseWrite() error }).CloseWrite()
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatal(err)
	}
	pool := h.h3.pools[h2PoolKey(r)]
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if stats := pool.peers[0].conn.PacketPaddingStats(); stats.Packets != 0 || stats.Bytes != 0 {
		t.Fatal("disabled client padded packets", stats)
	}
}

func TestH3PaddingConfigurationReload(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, _, cfg, _ := h3PaddingFixture(t, target, true)
	original := e.h3Listener
	updated := proto.Clone(cfg).(*pb.ControlMessage)
	updated.Node.Tls.QuicPadding.MaxPadding = 512
	if err := e.Apply(updated); err != nil {
		t.Fatal(err)
	}
	if e.h3Listener == original || e.h3Listener.server.QUICConfig.PacketPadding.MaxPadding != 512 {
		t.Fatal("updated policy did not replace listener configuration")
	}
	current := e.h3Listener
	if err := e.Apply(updated); err != nil {
		t.Fatal(err)
	}
	if e.h3Listener != current {
		t.Fatal("unchanged policy restarted listener")
	}
}
