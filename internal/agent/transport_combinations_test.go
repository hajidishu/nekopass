package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"google.golang.org/protobuf/proto"
)

func TestTunnelTransportSecurityCombinations(t *testing.T) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		t.Run(mode, func(t *testing.T) {
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
			config.Revision++
			config.Node.TunnelProtocol = mode
			rule.TunnelProtocol = mode
			if mode == "plain_h2" {
				config.Node.Tls.Certificate = ""
				config.Node.Tls.PrivateKey = ""
				config.Node.Tls.ServerName = ""
				rule.Tls.ServerName = ""
				rule.Tls.RootCa = ""
			}
			if err = engine.Apply(config); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			dial := func(r *pb.Rule) (net.Conn, error) {
				if tunnel.H2(mode) {
					return transport.Dial(ctx, ctx, r, target.Addr().String())
				}
				return dialTunnel(ctx, r, target.Addr().String())
			}
			fingerprints := []string{"off"}
			if tunnel.TLS(mode) {
				fingerprints = []string{"off", "chrome", "firefox"}
			}
			for _, fingerprint := range fingerprints {
				rule.Tls.Fingerprint = fingerprint
				conn, err := dial(rule)
				if err != nil {
					t.Fatal(fingerprint, err)
				}
				payload := strings.Repeat("bidirectional-payload", 10000)
				written := make(chan error, 1)
				go func() { _, err := io.WriteString(conn, payload); written <- err }()
				received := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, received); err != nil || string(received) != payload {
					conn.Close()
					t.Fatal("payload", err)
				}
				if err = <-written; err != nil {
					t.Fatal(err)
				}
				if half, ok := conn.(interface{ CloseWrite() error }); ok {
					if err = half.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
						conn.Close()
						t.Fatal("half close", n, err)
					}
				}
				conn.Close()
			}
			bad := proto.Clone(rule).(*pb.Rule)
			bad.TunnelToken = strings.Repeat("b", 64)
			// Plain-H2 pools are keyed by peer settings, so authenticate a fresh peer as well.
			transport.Prune(nil)
			if conn, err := dial(bad); err == nil {
				conn.Close()
				t.Fatal("wrong credential accepted")
			}
			if tunnel.TLS(mode) {
				bad = proto.Clone(rule).(*pb.Rule)
				bad.Tls.RootCa = ""
				if conn, err := dial(bad); err == nil {
					conn.Close()
					t.Fatal("untrusted certificate accepted")
				}
			}
		})
	}
}

func TestPlainH2RejectsCapturedProofAcrossConnections(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	engine, _, config, rule := h2Fixture(t, target.Addr().String())
	config.Revision++
	config.Node.TunnelProtocol = "plain_h2"
	config.Node.Tls.ServerName = ""
	rule.TunnelProtocol = "plain_h2"
	rule.Tls.ServerName = ""
	rule.Tls.RootCa = "invalid ignored TLS configuration"
	if err = engine.Apply(config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := dialH2Peer(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	defer first.cc.Close()
	defer first.conn.Close()
	second, err := dialH2Peer(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	defer second.cc.Close()
	defer second.conn.Close()
	if bytes.Equal(first.exporter, second.exporter) {
		t.Fatal("connections share authentication binding")
	}
	metadata, _ := json.Marshal(h2Open{Ingress: rule.IngressNodeId, Rule: rule.Id, User: rule.UserId, Epoch: rule.QuotaEpoch, Target: target.Addr().String(), Nonce: strings.Repeat("c", 32)})
	proof := h2Proof(rule.TunnelToken, first.exporter, metadata)
	request := func(peer *h2Peer, expect int) {
		r, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://%s:%d%s", rule.TunnelHost, rule.TunnelPort, rule.Tls.Path), nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Stream", base64.RawURLEncoding.EncodeToString(metadata))
		r.Header.Set("Authorization", "Bearer "+proof)
		response, err := peer.cc.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != expect {
			t.Fatal("unexpected replay response", response.StatusCode, expect)
		}
	}
	request(first, 200)
	request(first, 404)
	request(second, 404)
	if accepted.Load() != 1 {
		t.Fatal("replay reached target", accepted.Load())
	}
}

func TestPlainH2RejectsMissingSettingsWithoutPanic(t *testing.T) {
	engine, _, config, _ := h2Fixture(t, "127.0.0.1:1")
	config.Revision++
	config.Node.TunnelProtocol = "plain_h2"
	config.Node.Tls = nil
	if err := engine.configureTunnel(config); err == nil {
		t.Fatal("missing H2 settings accepted")
	}
}
