package agent

import (
	"errors"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"net"
	"sync"
)

var errClientTCPRestore = errors.New("TCP Brutal rollback failed")

type clientTCPOriginal struct {
	algorithm  string
	parameters []byte
}
type clientTCPKernel interface {
	Apply(*net.TCPConn, uint64, uint64) (clientTCPOriginal, error)
	Restore(*net.TCPConn, clientTCPOriginal) error
}
type clientTCPEntry struct {
	original clientTCPOriginal
	applied  bool
}

// Holds only live user-facing TCP sockets. No module discovery, installation,
// status reporting, or background retries are performed.
type clientTCPBrutal struct {
	mu          sync.Mutex
	kernel      clientTCPKernel
	entries     map[*net.TCPConn]*clientTCPEntry
	enabled     bool
	rate, group uint64
}

func newClientTCPBrutal() *clientTCPBrutal {
	return &clientTCPBrutal{kernel: systemClientTCPKernel{}, entries: map[*net.TCPConn]*clientTCPEntry{}}
}
func (m *clientTCPBrutal) update(node *pb.NodeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	enabled := node.GetEnabled() && node.GetClientTcpBrutalEnabled()
	rate := node.GetBandwidthUpBps()
	group := uint64(node.GetNodeId()) ^ uint64(0x4e656b6f50617373)
	if group == 0 {
		group = 1
	}
	if m.enabled == enabled && m.rate == rate && m.group == group {
		return
	}
	m.enabled, m.rate, m.group = enabled, rate, group
	for conn, entry := range m.entries {
		m.configureLocked(conn, entry)
	}
}
func (m *clientTCPBrutal) configureLocked(conn *net.TCPConn, entry *clientTCPEntry) {
	if !m.enabled {
		if entry.applied {
			if err := m.kernel.Restore(conn, entry.original); err != nil {
				conn.Close()
			}
			entry.applied = false
		}
		return
	}
	original, err := m.kernel.Apply(conn, m.rate, m.group)
	if err != nil {
		if errors.Is(err, errClientTCPRestore) {
			conn.Close()
		}
		return
	}
	if !entry.applied {
		entry.original = original
		entry.applied = true
	}
}
func clientTCPSocket(conn net.Conn) *net.TCPConn {
	for depth := 0; depth < 8 && conn != nil; depth++ {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c
		case *bufferedConn:
			conn = c.Conn
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
	}
	return nil
}
func (m *clientTCPBrutal) register(conn net.Conn) func() {
	tcp := clientTCPSocket(conn)
	if tcp == nil {
		return func() {}
	}
	m.mu.Lock()
	if m.entries[tcp] != nil {
		m.mu.Unlock()
		return func() {}
	}
	entry := &clientTCPEntry{}
	m.entries[tcp] = entry
	m.configureLocked(tcp, entry)
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.entries[tcp] == entry {
				delete(m.entries, tcp)
			}
		})
	}
}
