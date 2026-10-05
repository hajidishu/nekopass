package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	hp "google.golang.org/grpc/health/grpc_health_v1"
)

func TestAgentListenerChangesTLSWithoutRestartAndRejectsWrongTransport(t *testing.T) {
	cert, key, _, err := SelfSignedTunnelCertificate("control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "control.crt"), filepath.Join(dir, "control.key")
	if err := os.WriteFile(certFile, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &agentListener{listener: ln, address: ln.Addr().String(), certFile: certFile, keyFile: keyFile}
	tlsPlan, err := l.prepare(SystemSettings{AgentTransport: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	l.plan = tlsPlan
	srv := grpc.NewServer(grpc.Creds(&agentCredentials{listener: l}))
	hp.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(l)
	t.Cleanup(func() { srv.Stop(); l.Close() })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(cert))
	tlsClient := credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "control.example.test", MinVersion: tls.VersionTLS12})
	check := func(transport credentials.TransportCredentials, success bool) {
		t.Helper()
		_, port, _ := net.SplitHostPort(l.Addr().String())
		client, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", port), grpc.WithTransportCredentials(transport))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = hp.NewHealthClient(client).Check(ctx, &hp.HealthCheckRequest{})
		if (err == nil) != success {
			t.Fatalf("transport success=%v: %v", success, err)
		}
	}
	check(tlsClient, true)
	check(insecure.NewCredentials(), false)
	plainPlan, err := l.prepare(SystemSettings{AgentTransport: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.apply(plainPlan); err != nil {
		t.Fatal(err)
	}
	if host, _, _ := net.SplitHostPort(l.Addr().String()); net.ParseIP(host).IsLoopback() {
		t.Fatal("direct HTTP still binds loopback")
	}
	check(insecure.NewCredentials(), true)
	check(tlsClient, false)
	if err := l.apply(tlsPlan); err != nil {
		t.Fatal(err)
	}
	check(tlsClient, true)
}

func TestAgentListenerPlainIgnoresLegacyCertificatesAndProxyKeepsH2C(t *testing.T) {
	l := &agentListener{address: "127.0.0.1:9443", certFile: "missing.crt", keyFile: "missing.key"}
	p, err := l.prepare(SystemSettings{AgentTransport: "plain"})
	if err != nil || p.address != "0.0.0.0:9443" || p.credentials.Info().SecurityProtocol != "insecure" {
		t.Fatal("HTTP still depends on TLS files", err)
	}
	if _, err := l.prepare(SystemSettings{AgentTransport: "tls"}); err == nil {
		t.Fatal("invalid direct TLS configuration accepted")
	}
	l.certFile, l.keyFile = "", ""
	p, err = l.prepare(SystemSettings{AgentTransport: "tls"})
	if err != nil || p.mode != "proxy" || p.address != "127.0.0.1:9443" || p.credentials.Info().SecurityProtocol != "insecure" {
		t.Fatal("TLS reverse proxy backend changed", err)
	}
}
