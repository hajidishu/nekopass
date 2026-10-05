package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/control"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func h2Fixture(t testing.TB, target string) (*Engine, *h2Transport, *pb.ControlMessage, *pb.Rule) {
	t.Helper()
	cert, key, _, err := control.SelfSignedTunnelCertificate("tunnel.example.test")
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(state, 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close(); state.Close() })
	secret := strings.Repeat("a", 64)
	config := &pb.ControlMessage{Revision: 1, Node: &pb.NodeConfig{NodeId: 3, Enabled: true, TunnelExitEnabled: true, TunnelProtocol: "tls_h2", TunnelListenHost: "127.0.0.1", TunnelListenPort: int32(port), MaxConnections: 100,
		Tls: &pb.TLSServerConfig{ServerName: "tunnel.example.test", Certificate: cert, PrivateKey: key, Path: "/api/stream", SiteTitle: "Welcome", StreamWindowMib: 16, ConnectionWindowMib: 64, MaxStreams: 256}},
		TunnelLinks: []*pb.TunnelLink{{IngressNodeId: 2, Token: secret}}, EgressRules: []*pb.EgressRule{{RuleId: 11, IngressNodeId: 2, UserId: 5, QuotaEpoch: 3, ExpiresUnix: time.Now().Add(time.Hour).Unix(), Targets: []string{target}}}}
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	transport := newH2Transport()
	t.Cleanup(transport.Close)
	rule := &pb.Rule{Id: 11, UserId: 5, IngressNodeId: 2, EgressNodeId: 3, QuotaEpoch: 3, TunnelProtocol: "tls_h2", TunnelHost: "127.0.0.1", TunnelPort: int32(port), TunnelToken: secret,
		Tls: &pb.TLSClientConfig{ServerName: "tunnel.example.test", Fingerprint: "chrome", RootCa: cert, Path: "/api/stream", RequireResponseProof: true, PoolSize: 2, StreamWindowMib: 16, ConnectionWindowMib: 64}}
	return engine, transport, config, rule
}

func TestH2TLS13ForwardingAndPermissionIsolation(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	engine, transport, config, rule := h2Fixture(t, target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, fingerprint := range []string{"off", "chrome", "firefox"} {
		rule.Tls.Fingerprint = fingerprint
		conn, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		payload := strings.Repeat("payload", 10000)
		if _, err = io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		read := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, read); err != nil || string(read) != payload {
			t.Fatal("TLS payload corrupted", err)
		}
		conn.Close()
	}
	for _, change := range []func(*pb.Rule){
		func(r *pb.Rule) { r.TunnelToken = strings.Repeat("b", 64) }, func(r *pb.Rule) { r.UserId = 6 }, func(r *pb.Rule) { r.QuotaEpoch = 2 },
		func(r *pb.Rule) { r.IngressNodeId = 4 }, func(r *pb.Rule) { r.Tls.ServerName = "wrong.example.test" }, func(r *pb.Rule) { r.Tls.RootCa = "" },
	} {
		bad := proto.Clone(rule).(*pb.Rule)
		change(bad)
		if conn, err := transport.Dial(ctx, ctx, bad, target.Addr().String()); err == nil {
			conn.Close()
			t.Fatal("invalid TLS identity or authorization accepted")
		}
	}
	if conn, err := transport.Dial(ctx, ctx, rule, "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("unauthorized target accepted")
	}
	config.EgressRules = nil
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	if conn, err := transport.Dial(ctx, ctx, rule, target.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("removed rule accepted")
	}
}

func TestH2HalfCloseInBothDirections(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	result := make(chan string, 1)
	go func() {
		raw, err := target.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn := raw.(*net.TCPConn)
		conn.Write([]byte("download"))
		conn.CloseWrite()
		payload, _ := io.ReadAll(conn)
		result <- string(payload)
	}()
	_, transport, _, rule := h2Fixture(t, target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read, err := io.ReadAll(conn)
	if err != nil || string(read) != "download" {
		t.Fatal("response FIN not delivered independently", err)
	}
	if _, err = conn.Write([]byte("upload-after-fin")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*h2StreamConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got != "upload-after-fin" {
			t.Fatal("upload did not survive response FIN")
		}
	case <-ctx.Done():
		t.Fatal("upload FIN not delivered")
	}
}

func TestH2CertificateHotReloadAndHTTPChallengeScope(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	engine, transport, config, rule := h2Fixture(t, target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, ctx, rule, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cert, key, _, err := control.SelfSignedTunnelCertificate("tunnel.example.test")
	if err != nil {
		t.Fatal(err)
	}
	config.Node.Tls.Certificate = cert
	config.Node.Tls.PrivateKey = key
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	config.Node.Tls.ChallengePort = int32(port)
	config.Node.Tls.Challenges = []*pb.ACMEChallenge{{Domain: "tunnel.example.test", Token: "fixture-token", KeyAuthorization: "fixture-authorization", Revision: 2, ExpiresUnix: time.Now().Add(time.Minute).Unix()}}
	config.Revision = 2
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("survives")); err != nil {
		t.Fatal("certificate update killed existing stream", err)
	}
	read := make([]byte, 8)
	if _, err = io.ReadFull(conn, read); err != nil || string(read) != "survives" {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	url := "http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port)) + "/.well-known/acme-challenge/fixture-token"
	for _, host := range []string{"tunnel.example.test", "wrong.example.test"} {
		request, _ := http.NewRequest("GET", url, nil)
		request.Host = host
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if host == "tunnel.example.test" {
			if response.StatusCode != 200 || string(body) != "fixture-authorization" {
				t.Fatal("HTTP challenge response wrong")
			}
		} else if response.StatusCode != 404 {
			t.Fatal("HTTP challenge exposed on unauthorized hostname")
		}
	}
	report, err := engine.Report()
	if err != nil || report.AcmeAck != 2 {
		t.Fatal("HTTP challenge readiness not acknowledged")
	}
	config.Node.Tls.Challenges = nil
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
}
