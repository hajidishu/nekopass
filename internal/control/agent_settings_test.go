package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestSavingHTTPSettingsUpdatesLiveListenerAndSurvivesRestart(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	var original []byte
	if err := f.p.QueryRow(ctx, "SELECT config FROM site_settings WHERE id=1").Scan(&original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", original) })
	v := defaultSettings()
	v.AgentHost, v.AgentPort = "127.0.0.1", 443
	initial, _ := json.Marshal(v)
	if _, err := f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", initial); err != nil {
		t.Fatal(err)
	}
	cert, key, _, err := SelfSignedTunnelCertificate("control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	ln, creds, err := f.s.StartAgentListener(ctx, "127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Info().SecurityProtocol != "tls" {
		t.Fatal("fixture did not start TLS")
	}
	securityStatus(t, f.request(f.user, "admin/settings", "PUT", v), 403)
	v.AgentTransport = "plain"
	response := f.request(f.admin, "admin/settings", "PUT", v)
	securityStatus(t, response, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if v.AgentPort != mustPort(t, port) || creds.Info().SecurityProtocol != "insecure" {
		t.Fatal("HTTP save did not switch listener and advertised port")
	}
	if host, _, _ := net.SplitHostPort(ln.Addr().String()); net.ParseIP(host).IsLoopback() {
		t.Fatal("direct listener remained loopback")
	}
	ln.Close()
	// Persisted HTTP ignores stale certificate environment paths at next startup.
	fresh := New(f.p)
	ln, creds, err = fresh.StartAgentListener(ctx, "127.0.0.1:0", "missing.crt", "missing.key")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if creds.Info().SecurityProtocol != "insecure" {
		t.Fatal("TLS returned after restart")
	}
}

func mustPort(t *testing.T, port string) int {
	t.Helper()
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestOnlineNodeReceivesEndpointAfterSettingsSave(t *testing.T) {
	f := newSecurityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var original []byte
	if err := f.p.QueryRow(ctx, "SELECT config FROM site_settings WHERE id=1").Scan(&original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.p.Exec(context.Background(), "UPDATE site_settings SET config=$1 WHERE id=1", original)
	})
	v := defaultSettings()
	v.AgentTransport = "plain"
	data, _ := json.Marshal(v)
	if _, err := f.p.Exec(ctx, "UPDATE site_settings SET config=$1 WHERE id=1", data); err != nil {
		t.Fatal(err)
	}
	ln, creds, err := f.s.StartAgentListener(ctx, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterControlServer(srv, &StreamServer{Server: f.s})
	go srv.Serve(ln)
	defer srv.Stop()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	token := Secret()
	var node int64
	if err := f.p.QueryRow(ctx, "INSERT INTO nodes(name,token_hash,token) VALUES($1,$2,$3) RETURNING id", Secret(), Hash(token), token).Scan(&node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.p.Exec(context.Background(), "DELETE FROM nodes WHERE id=$1", node) })
	client, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stream, err := pb.NewControlClient(client).Connect(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token))
	if err != nil {
		t.Fatal(err)
	}
	report := &pb.AgentMessage{InstanceId: Secret(), ProtocolVersion: 12, AgentVersion: "dev"}
	if err := stream.Send(report); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	v.AgentHost, v.AgentPort = "localhost", mustPort(t, port)
	securityStatus(t, f.request(f.admin, "admin/settings", "PUT", v), 200)
	if err := stream.Send(report); err != nil {
		t.Fatal(err)
	}
	result, err := stream.Recv()
	if err != nil || result.ControlEndpoint != "http://localhost:"+port {
		t.Fatal("new endpoint not sent to connected node", result, err)
	}
}
