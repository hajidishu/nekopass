package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

type clientTCPApplyCall struct {
	conn        *net.TCPConn
	rate, group uint64
}
type testClientTCPKernel struct {
	mu         sync.Mutex
	applyErr   error
	calls      []clientTCPApplyCall
	restored   []clientTCPOriginal
	algorithms map[*net.TCPConn]string
}

func (k *testClientTCPKernel) Apply(conn *net.TCPConn, rate, group uint64) (clientTCPOriginal, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, clientTCPApplyCall{conn, rate, group})
	if k.algorithms == nil {
		k.algorithms = map[*net.TCPConn]string{}
	}
	original := k.algorithms[conn]
	if original == "" {
		original = "cubic"
	}
	if k.applyErr != nil {
		return clientTCPOriginal{}, k.applyErr
	}
	k.algorithms[conn] = "brutal"
	return clientTCPOriginal{algorithm: original}, nil
}
func (k *testClientTCPKernel) Restore(conn *net.TCPConn, original clientTCPOriginal) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.restored = append(k.restored, original)
	k.algorithms[conn] = original.algorithm
	return nil
}
func (k *testClientTCPKernel) snapshot() ([]clientTCPApplyCall, []clientTCPOriginal) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]clientTCPApplyCall(nil), k.calls...), append([]clientTCPOriginal(nil), k.restored...)
}
func clientTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}

func TestClientTCPBrutalSharedGroupLiveUpdateRestoreAndCleanup(t *testing.T) {
	m := newClientTCPBrutal()
	kernel := &testClientTCPKernel{}
	m.kernel = kernel
	first, _ := clientTCPPair(t)
	second, _ := clientTCPPair(t)
	unregister := m.register(first)
	defer unregister()
	unregisterSecond := m.register(&bufferedConn{Conn: second, reader: bufio.NewReader(second)})
	defer unregisterSecond()
	if calls, _ := kernel.snapshot(); len(calls) != 0 {
		t.Fatal("default setting changed socket algorithms")
	}
	node := &pb.NodeConfig{NodeId: 6, Enabled: true, ClientTcpBrutalEnabled: true, BandwidthUpBps: 1250000}
	m.update(node)
	calls, _ := kernel.snapshot()
	if len(calls) != 2 || calls[0].group == 0 || calls[0].group != calls[1].group || calls[0].rate != 1250000 || calls[1].rate != 1250000 {
		t.Fatal("connections did not share the node's upload group", calls)
	}
	node.BandwidthUpBps = 2500000
	m.update(node)
	calls, _ = kernel.snapshot()
	if len(calls) != 4 || calls[2].rate != 2500000 || calls[3].rate != 2500000 || calls[2].group != calls[0].group {
		t.Fatal("existing connections did not update")
	}
	node.ClientTcpBrutalEnabled = false
	m.update(node)
	_, restored := kernel.snapshot()
	if len(restored) != 2 || restored[0].algorithm != "cubic" || restored[1].algorithm != "cubic" {
		t.Fatal("original algorithms were overwritten during update", restored)
	}
	unregister()
	unregister()
	unregisterSecond()
	if len(m.entries) != 0 {
		t.Fatal("closed connections retained metadata")
	}
}

func TestClientTCPBrutalSocketFailureAndCancellationDoNotLeak(t *testing.T) {
	m := newClientTCPBrutal()
	kernel := &testClientTCPKernel{applyErr: errors.New("locked route")}
	m.kernel = kernel
	m.update(&pb.NodeConfig{Enabled: true, ClientTcpBrutalEnabled: true, BandwidthUpBps: 1250000})
	server, client := clientTCPPair(t)
	unregister := m.register(server)
	if len(m.entries) != 1 || m.entries[server].applied {
		t.Fatal("failed parameter write was retained as active")
	}
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal("socket setup failure broke default forwarding", err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := client.Read(b[:]); err != nil || b[0] != 'x' {
		t.Fatal(err)
	}
	unregister()
	if len(m.entries) != 0 {
		t.Fatal("failed socket retained error state")
	}
	kernel.mu.Lock()
	kernel.applyErr = errClientTCPRestore
	kernel.mu.Unlock()
	unregister = m.register(server)
	defer unregister()
	if _, err := server.Write([]byte("y")); err == nil {
		t.Fatal("a socket with failed rollback was left under an unintended algorithm")
	}
}

func TestClientTCPBrutalOnlyTouchesUserFacingTCP(t *testing.T) {
	target, _ := inboundEcho(t, false)
	e, h, c, tunnelRule := h2Fixture(t, target)
	kernel := &testClientTCPKernel{}
	e.clientTCPBrutal.kernel = kernel
	c.Node.ClientTcpBrutalEnabled = true
	c.Node.BandwidthUpBps = 1250000
	c.Node.DialTimeoutSeconds = 8
	c.Node.IdleTimeoutSeconds = 300
	c.Users = []*pb.UserPolicy{{Id: 7, Enabled: true, QuotaUnlimited: true, MaxConnections: 100}}
	c.Rules = []*pb.Rule{{Id: 101, UserId: 7, Enabled: true, Protocol: "tcp", ListenHost: "127.0.0.1", Targets: []string{target}}, {Id: 102, UserId: 7, Enabled: true, Protocol: "udp", ListenHost: "127.0.0.1", Targets: []string{randomUDPEcho(t)}}}
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	user, err := net.Dial("tcp", e.listeners[101].ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer user.Close()
	inboundExchange(t, user, "download")
	calls, _ := kernel.snapshot()
	if len(calls) != 1 || calls[0].conn.LocalAddr().String() != e.listeners[101].ln.Addr().String() || calls[0].conn.RemoteAddr().String() != user.LocalAddr().String() {
		t.Fatal("configured the wrong TCP endpoint", calls)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := h.Dial(ctx, ctx, tunnelRule, target)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	inboundExchange(t, tunnel, "tunnel is independent")
	udp, err := net.DialUDP("udp", nil, e.udpListeners[102].conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(time.Second))
	if _, err := udp.Write([]byte("udp")); err != nil {
		t.Fatal(err)
	}
	var received [8]byte
	if n, err := udp.Read(received[:]); err != nil || string(received[:n]) != "udp" {
		t.Fatal(err)
	}
	if calls, _ := kernel.snapshot(); len(calls) != 1 {
		t.Fatal("UDP or tunnel socket was configured")
	}
	report, err := e.Report()
	if err != nil || report.Error != "" {
		t.Fatal("parameter setup interrupted reporting", report, err)
	}
	if e.counters[101].Load() != 16 {
		t.Fatal("TCP configuration changed payload accounting", e.counters[101].Load())
	}
}

func TestClientTCPBrutalSharedSNIPreservesEndToEndTLS(t *testing.T) {
	target, root := inboundEcho(t, true)
	e, c, address, tlsConfig := inboundFixture(t, root, target)
	kernel := &testClientTCPKernel{}
	e.clientTCPBrutal.kernel = kernel
	c.Node.ClientTcpBrutalEnabled = true
	c.Node.BandwidthUpBps = 1250000
	if err := e.Apply(c); err != nil {
		t.Fatal(err)
	}
	client, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	inboundExchange(t, client, "end-to-end TLS")
	if state := client.ConnectionState(); len(state.PeerCertificates) == 0 || state.PeerCertificates[0].VerifyHostname("a.example.test") != nil {
		t.Fatal("target TLS certificate was replaced")
	}
	calls, _ := kernel.snapshot()
	if len(calls) != 1 || calls[0].conn.LocalAddr().String() != address {
		t.Fatal("shared listener wrapper hid the user socket", calls)
	}
}
