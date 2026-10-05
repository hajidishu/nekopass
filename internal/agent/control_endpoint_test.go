package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestControlEndpointModes(t *testing.T) {
	for _, tc := range []struct{ raw, target, protocol string }{{"panel.example.test:9443", "panel.example.test:9443", "tls"}, {"https://panel.example.test:443", "panel.example.test:443", "tls"}, {"http://127.0.0.1:9443", "127.0.0.1:9443", "insecure"}, {"http://[2001:db8::1]:9443/", "[2001:db8::1]:9443", "insecure"}} {
		target, creds, err := controlEndpoint(tc.raw)
		if err != nil || target != tc.target || creds.Info().SecurityProtocol != tc.protocol {
			t.Fatalf("wrong control endpoint mode: %s", tc.raw)
		}
	}
	for _, raw := range []string{"ftp://panel.example.test:443", "https://user:secret@panel.example.test:443", "http://panel.example.test:9443/path", "https://panel.example.test:9443?q=x", "https://panel.example.test:9443#fragment", "http://panel.example.test:0", "http://panel.example.test:70000", "http://panel.example.test", "https://:443", "http://panel.example.test:9443\n"} {
		if _, _, err := controlEndpoint(raw); err == nil {
			t.Fatalf("invalid endpoint accepted: %q", raw)
		}
	}
}

func TestControlTLSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	target, creds, err := controlEndpoint(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, _, err := creds.ClientHandshake(ctx, target, raw); err == nil {
		conn.Close()
		t.Fatal("untrusted control TLS certificate accepted")
	}
}
