package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/protobuf/proto"
)

func h3Fixture(t testing.TB, target string) (*Engine, *h2Transport, *pb.ControlMessage, *pb.Rule) {
	e, h, c, r := h2Fixture(t, target)
	c.Node.TunnelProtocol = "tls_h3"
	r.TunnelProtocol = "tls_h3"
	r.Tls.MaxStreams = c.Node.Tls.MaxStreams
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	return e, h, c, r
}
func TestH3TCPHalfCloseAndAuthentication(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, r := h3Fixture(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("HTTP/3 TCP data"), 10000)
	done := make(chan error, 1)
	go func() { _, err := conn.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("payload", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("half close", err)
	}
	for _, change := range []func(*pb.Rule){func(v *pb.Rule) { v.UserId++ }, func(v *pb.Rule) { v.QuotaEpoch++ }, func(v *pb.Rule) { v.TunnelToken = strings.Repeat("b", 64) }} {
		bad := proto.Clone(r).(*pb.Rule)
		change(bad)
		if c, err := h.h3.Dial(ctx, ctx, bad, target, false, nil); err == nil {
			c.Close()
			t.Fatal("invalid credentials accepted")
		}
	}
}
func TestH3ConnectUDPDatagrams(t *testing.T) {
	target := randomUDPEcho(t)
	e, h, c, r := h3Fixture(t, target)
	c.EgressRules[0].Protocol = "udp"
	r.Protocol = "udp"
	if err := e.Apply(c); err != nil {
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
	for _, body := range [][]byte{{}, []byte("datagram"), bytes.Repeat([]byte{1}, 45000)} {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write(body); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, maxDatagram)
		n, err := conn.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], body) {
			t.Fatal("UDP data", n, err)
		}
	}
	conn.Close()
	if queued.Load() != 0 {
		t.Fatal("receive budget leaked", queued.Load())
	}
}
func TestH3RealWebsiteAndFallback(t *testing.T) {
	var leaked atomic.Bool
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Stream") != "" {
			leaked.Store(true)
		}
		w.Header().Set("Alt-Svc", `h3=":1"`)
		io.WriteString(w, "ordinary fallback website")
	}))
	defer site.Close()
	e, _, c, r := h3Fixture(t, "127.0.0.1:1")
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

var _ net.Conn = (*h3StreamConn)(nil)

func TestH3ReverseHalfClose(t *testing.T) {
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
	_, h, _, r := h3Fixture(t, target.Addr().String())
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

func TestH3PoolCapacityCancellationAndRecovery(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, h, cfg, r := h3Fixture(t, target)
	cfg.Node.Tls.MaxStreams = 1
	r.Tls.MaxStreams = 1
	r.Tls.PoolSize = 2
	if err := e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	life, end := context.WithCancel(ctx)
	first, err := h.h3.Dial(ctx, life, r, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if c, err := h.h3.Dial(ctx, ctx, r, target, false, nil); err == nil {
		c.Close()
		t.Fatal("pool exceeded configured capacity")
	}
	end() // A caller abandoning a stream must release its pool lease.
	pool := h.h3.pools[h2PoolKey(r)]
	deadline := time.Now().Add(2 * time.Second)
	for {
		pool.mu.Lock()
		active := 0
		for _, p := range pool.peers {
			active += p.active
		}
		pool.mu.Unlock()
		if active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled stream retained capacity", active)
		}
		time.Sleep(time.Millisecond)
	}
	third, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal("capacity did not recover", err)
	}
	third.Close()
	second.Close()
	pool.mu.Lock()
	for _, p := range pool.peers {
		p.conn.CloseWithError(0, "")
	}
	pool.mu.Unlock()
	fourth, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal("closed peers exhausted pool permanently", err)
	}
	defer fourth.Close()
	h.h3.Prune(nil) // Active connections survive an unrelated configuration prune.
	fourth.SetDeadline(time.Now().Add(time.Second))
	if _, err = fourth.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err = io.ReadFull(fourth, got); err != nil || string(got) != "alive" {
		t.Fatal("prune closed active stream", err)
	}
}

func TestH3ReplayAuthorityAndLiveRevocation(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, h, cfg, r := h3Fixture(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, err := dialH3Peer(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.conn.CloseWithError(0, "")
	other, err := dialH3Peer(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer other.conn.CloseWithError(0, "")
	metadata, _ := json.Marshal(h2Open{Network: "tcp", Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target, Nonce: strings.Repeat("c", 32), Seq: 1})
	req := &http.Request{Method: "CONNECT", Host: target, URL: &url.URL{Host: target}, Header: http.Header{}}
	req.Header.Set("X-Stream", base64.RawURLEncoding.EncodeToString(metadata))
	req.Header.Set("Authorization", "Bearer "+h3RequestProof(r.TunnelToken, peer.exporter, metadata, req))
	send := func(p *h3Peer, request *http.Request, expected int) {
		t.Helper()
		str, err := p.cc.OpenRequestStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer str.CancelRead(0)
		defer str.CancelWrite(0)
		str.SetDeadline(time.Now().Add(3 * time.Second))
		if err = str.SendRequestHeader(request); err != nil {
			t.Fatal(err)
		}
		response, err := str.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != expected {
			t.Fatal("unexpected authentication response", response.StatusCode, expected)
		}
	}
	changed := req.Clone(ctx)
	changed.Host = "127.0.0.1:1"
	changed.URL = &url.URL{Host: changed.Host}
	send(peer, changed, 404)
	send(peer, req, 200)
	send(peer, req, 404)  // Same connection, repeated sequence.
	send(other, req, 404) // Different TLS exporter.
	conn, err := h.h3.Dial(ctx, ctx, r, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cfg.EgressRules = nil
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked stream kept forwarding")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("revocation did not terminate active stream")
	}
	if c, err := h.h3.Dial(ctx, ctx, r, target, false, nil); err == nil {
		c.Close()
		t.Fatal("removed rule accepted")
	}
	// Restore permissions, then verify target ACL rejection is authenticated.
	cfg.EgressRules = []*pb.EgressRule{{RuleId: r.Id, IngressNodeId: r.IngressNodeId, UserId: r.UserId, QuotaEpoch: r.QuotaEpoch, Targets: []string{target}, ExpiresUnix: time.Now().Add(time.Hour).Unix()}}
	cfg.Node.SecurityConfigured = true
	cfg.Node.TargetDenyCidrs = []string{"127.0.0.0/8"}
	if err = e.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if c, err := h.h3.Dial(ctx, ctx, r, target, false, nil); !errors.Is(err, errTunnelTarget) {
		if c != nil {
			c.Close()
		}
		t.Fatal("ACL denied target was not refused", err)
	}
}

func TestH3UDPMeteringFreeAndFinite(t *testing.T) {
	for _, rate := range []int64{0, 15000} {
		t.Run(strconv.FormatInt(rate, 10), func(t *testing.T) {
			target := randomUDPEcho(t)
			exit, _, config, r := h3Fixture(t, target)
			config.EgressRules[0].Protocol = "udp"
			if err := exit.Apply(config); err != nil {
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
