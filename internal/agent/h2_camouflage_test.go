package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/control"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func probeHTTPClient(t *testing.T, cert string, port int, sni string, h2 bool) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cert)) {
		t.Fatal("invalid fixture CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni}, ForceAttemptHTTP2: h2, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmtPort(port)))
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}
func fmtPort(port int) string { return strconv.Itoa(port) }

func TestCamouflageUniform404AndNoUnauthenticatedTargetDial(t *testing.T) {
	var targetCalls atomic.Int32
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			targetCalls.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	_, transport, cfg, rule := h2Fixture(t, target.Addr().String())
	client := probeHTTPClient(t, cfg.Node.Tls.Certificate, int(cfg.Node.TunnelListenPort), cfg.Node.Tls.ServerName, true)
	for _, sample := range []struct{ method, path, host string }{{"GET", "/", "tunnel.example.test"}, {"GET", "/other", "tunnel.example.test"}, {"POST", "/api/stream", "tunnel.example.test"}, {"POST", "/api/stream", "wrong.example.test"}, {"POST", "/api/stream?probe=1", "tunnel.example.test"}} {
		r, _ := http.NewRequest(sample.method, "https://tunnel.example.test"+sample.path, strings.NewReader("probe"))
		r.Host = sample.host
		r.Header.Set("Authorization", "Bearer invalid")
		r.Header.Set("X-Stream", "invalid")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 404 || response.Header.Get("Server") != "" || string(body) != "404 page not found\n" || response.Header.Get("X-Stream-Reply") != "" {
			t.Fatal("probe received distinguishable response", sample)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bad := proto.Clone(rule).(*pb.Rule)
	bad.TunnelToken = strings.Repeat("b", 64)
	if c, e := transport.Dial(ctx, ctx, bad, target.Addr().String()); e == nil {
		c.Close()
		t.Fatal("bad authentication opened tunnel")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("probe connected to a business target")
	}
	legacy := probeHTTPClient(t, cfg.Node.Tls.Certificate, int(cfg.Node.TunnelListenPort), cfg.Node.Tls.ServerName, false)
	legacy.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
	response, err := legacy.Get("https://tunnel.example.test/")
	if err != nil {
		t.Fatal("ordinary TLS 1.2 website probe failed", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("ordinary TLS 1.2 probe disclosed a tunnel")
	}
}

func TestCamouflageProxyStripsProofAndCustomHostPathWorks(t *testing.T) {
	requests := make(chan http.Header, 10)
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Clone()
		w.Header().Set("X-Decoy", "fixture")
		io.WriteString(w, "fixture decoy")
	}))
	defer decoy.Close()
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	engine, transport, cfg, rule := h2Fixture(t, target.Addr().String())
	cfg.Node.Tls.Host = "cdn.example.test"
	cfg.Node.Tls.Path = "/images/upload"
	cfg.Node.Tls.FallbackUrl = decoy.URL
	if e = engine.Apply(cfg); e != nil {
		t.Fatal(e)
	}
	rule.Tls.Host = cfg.Node.Tls.Host
	rule.Tls.Path = cfg.Node.Tls.Path
	rule.Tls.Fingerprint = "off"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, e := transport.Dial(ctx, ctx, rule, target.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c.Write([]byte("test"))
	data := make([]byte, 4)
	if _, e = io.ReadFull(c, data); e != nil || string(data) != "test" {
		t.Fatal("custom Host/Path tunnel failed", e)
	}
	c.Close()
	client := probeHTTPClient(t, cfg.Node.Tls.Certificate, int(cfg.Node.TunnelListenPort), cfg.Node.Tls.ServerName, true)
	r, _ := http.NewRequest("POST", "https://cdn.example.test/images/upload", strings.NewReader("probe"))
	r.Header.Set("X-Stream", "private metadata")
	r.Header.Set("X-Stream-Ingress", "123")
	r.Header.Set("X-Stream-Nonce", "private nonce")
	r.Header.Set("X-Stream-Binding", "private binding")
	r.Header.Set("Authorization", "Bearer private proof")
	response, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	data, e = io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || response.StatusCode != 200 || string(data) != "fixture decoy" {
		t.Fatal("unauthenticated request did not receive decoy", e)
	}
	head := <-requests
	if head.Get("Authorization") != "" || head.Get("X-Stream") != "" || head.Get("X-Stream-Ingress") != "" || head.Get("X-Stream-Nonce") != "" || head.Get("X-Stream-Binding") != "" {
		t.Fatal("tunnel proof leaked to decoy")
	}
	bad := proto.Clone(rule).(*pb.Rule)
	bad.TunnelToken = strings.Repeat("b", 64)
	if c, e := transport.Dial(ctx, ctx, bad, target.Addr().String()); e == nil {
		c.Close()
		t.Fatal("decoy HTTP 200 mistaken for authenticated tunnel")
	}
}

func TestPreHandshakeSNIRejectionPassesThroughToHTTPSDecoy(t *testing.T) {
	cert, key, _, e := control.SelfSignedTunnelCertificate("decoy.example.test")
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "real HTTPS decoy") }))
	decoy.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	decoy.StartTLS()
	defer decoy.Close()
	engine, _, cfg, _ := h2Fixture(t, "127.0.0.1:1")
	cfg.Node.Tls.FallbackUrl = decoy.URL
	if e = engine.Apply(cfg); e != nil {
		t.Fatal(e)
	}
	client := probeHTTPClient(t, cert, int(cfg.Node.TunnelListenPort), "decoy.example.test", false)
	response, e := client.Get("https://decoy.example.test/")
	if e != nil {
		t.Fatal("pre-flight probe was not routed to decoy TLS", e)
	}
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || string(body) != "real HTTPS decoy" {
		t.Fatal("decoy TLS response invalid", e)
	}
}
