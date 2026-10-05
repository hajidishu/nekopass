package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func initialH2Settings(t *testing.T, address, certificate, sni string) []http2.Setting {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(certificate))
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: sni, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	f := http2.NewFramer(c, c)
	if err := f.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
			var result []http2.Setting
			settings.ForeachSetting(func(s http2.Setting) error { result = append(result, s); return nil })
			return result
		}
	}
}

func TestUnauthenticatedSettingsMatchOrdinaryH2Website(t *testing.T) {
	engine, _, cfg, _ := h2Fixture(t, "127.0.0.1:1")
	pair, err := tls.X509KeyPair([]byte(cfg.Node.Tls.Certificate), []byte(cfg.Node.Tls.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	website := httptest.NewUnstartedServer(http.HandlerFunc(http.NotFound))
	website.Config.MaxHeaderBytes = 8192
	website.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2", "http/1.1"}}
	if err := http2.ConfigureServer(website.Config, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	website.StartTLS()
	defer website.Close()
	want := initialH2Settings(t, website.Listener.Addr().String(), cfg.Node.Tls.Certificate, cfg.Node.Tls.ServerName)
	for _, window := range []int32{16, 64} {
		cfg.Node.Tls.StreamWindowMib, cfg.Node.Tls.ConnectionWindowMib, cfg.Node.Tls.MaxStreams = window, window*2, 17
		if err := engine.Apply(cfg); err != nil {
			t.Fatal(err)
		}
		got := initialH2Settings(t, net.JoinHostPort("127.0.0.1", fmtPort(int(cfg.Node.TunnelListenPort))), cfg.Node.Tls.Certificate, cfg.Node.Tls.ServerName)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("tunnel settings differ from ordinary website:\ngot: %v\nwant: %v", got, want)
		}
	}
}

func TestAuthenticatedH2StreamLimitDoesNotChangePublicSettings(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	engine, transport, cfg, rule := h2Fixture(t, target.Addr().String())
	cfg.Node.Tls.MaxStreams = 1
	if err := engine.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	rule.Tls.PoolSize = 1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := transport.Dial(ctx, ctx, rule, target.Addr().String()); err == nil {
		second.Close()
		t.Fatal("second authenticated stream bypassed business cap")
	}
	if _, err := first.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5)
	if _, err := io.ReadFull(first, data); err != nil || string(data) != "alive" {
		t.Fatal("rejection interrupted existing stream", err)
	}
}
