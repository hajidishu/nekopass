package agent

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
	"google.golang.org/protobuf/proto"
)

func randomFixture(t testing.TB, c *pb.ControlMessage, r *pb.Rule, name string) {
	t.Helper()
	key, err := tunnelcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c.Node.Random = &pb.RandomConfig{Cipher: name, Key: key}
	r.Random = proto.Clone(c.Node.Random).(*pb.RandomConfig)
	// Deliberately leave saved TLS settings present, to verify they do not
	// accidentally switch encryption, enable padding, or affect certificates.
}

func TestRandomAlgorithmsAcrossStreamTransports(t *testing.T) {
	for _, name := range []string{tunnelcrypto.ChaCha20Poly1305, tunnelcrypto.AES256GCM} {
		for _, mode := range []string{"random_tcp", "random_h2"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				target, _ := inboundEcho(t, false)
				exit, h2, c, r := h2Fixture(t, target)
				randomFixture(t, c, r, name)
				c.Node.TunnelProtocol = mode
				r.TunnelProtocol = mode
				c.Node.Tls.PaddingEnabled = true
				r.Tls.PaddingEnabled = true
				if err := exit.Apply(c); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				dial := func(rule *pb.Rule) (net.Conn, error) {
					if tunnel.H2(mode) {
						return h2.Dial(ctx, ctx, rule, target)
					}
					return dialTunnel(ctx, rule, target)
				}
				conn, err := dial(r)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				data := strings.Repeat("independent encrypted tunnel", 4000)
				done := make(chan error, 1)
				go func() { _, err := io.WriteString(conn, data); done <- err }()
				got := make([]byte, len(data))
				if _, err = io.ReadFull(conn, got); err != nil || string(got) != data {
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
				bad := proto.Clone(r).(*pb.Rule)
				bad.Random.Key, _ = tunnelcrypto.GenerateKey()
				if peer, err := dial(bad); err == nil {
					peer.Close()
					t.Fatal("wrong key accepted or old h2 pool reused")
				}
				bad = proto.Clone(r).(*pb.Rule)
				bad.Random.Cipher = tunnelcrypto.AES256GCM
				if name == tunnelcrypto.AES256GCM {
					bad.Random.Cipher = tunnelcrypto.ChaCha20Poly1305
				}
				if peer, err := dial(bad); err == nil {
					peer.Close()
					t.Fatal("wrong cipher accepted")
				}
				// Rotating keys must close old sessions and make new connections work.
				old := proto.Clone(r).(*pb.Rule)
				key, _ := tunnelcrypto.GenerateKey()
				c.Node.Random.Key = key
				r.Random.Key = key
				c.Revision++
				if err = exit.Apply(c); err != nil {
					t.Fatal(err)
				}
				if peer, err := dial(old); err == nil {
					peer.Close()
					t.Fatal("old key accepted after rotation")
				}
				peer, err := dial(r)
				if err != nil {
					t.Fatal("new key failed", err)
				}
				peer.Close()
				// Unauthenticated traffic never reaches HTTP/2 or HTTP fallback.
				probe, err := net.Dial("tcp", net.JoinHostPort(r.TunnelHost, strconv.Itoa(int(r.TunnelPort))))
				if err != nil {
					t.Fatal(err)
				}
				probe.SetDeadline(time.Now().Add(time.Second))
				probe.Write([]byte(strings.Repeat("GET / HTTP/1.1\r\n", 10)))
				if n, err := probe.Read(make([]byte, 4096)); n != 0 || err == nil {
					t.Fatal("unauthenticated probe received data", n, err)
				}
				probe.Close()
			})
		}
	}
}
