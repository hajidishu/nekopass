package agent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	dtls "github.com/pion/dtls/v3"
	"google.golang.org/protobuf/proto"
)

type nativeGateOpen struct {
	udpStreamOpen
	Cookie []byte `json:"cookie,omitempty"`
}
type nativeUDPListener struct {
	conn       *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
	node       *pb.NodeConfig
	secret     [32]byte
	mu         sync.Mutex
	peers      map[[16]byte]*nativePeer
	handshakes chan struct{}
}

func nativeOpenCipher(key string) (cipher.AEAD, error) {
	sum := sha256.Sum256([]byte("native-open/" + key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func sealNativeOpen(key string, id [16]byte, open nativeGateOpen) ([]byte, error) {
	a, err := nativeOpenCipher(key)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(open)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, data, id[:]), nil
}
func unsealNativeOpen(key string, id [16]byte, data []byte) (nativeGateOpen, error) {
	var open nativeGateOpen
	a, err := nativeOpenCipher(key)
	if err != nil || len(data) < a.NonceSize() {
		return open, errors.New("invalid gate")
	}
	plain, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], id[:])
	if err != nil {
		return open, err
	}
	err = json.Unmarshal(plain, &open)
	return open, err
}
func (l *nativeUDPListener) cookie(source *net.UDPAddr, route, id [16]byte, bucket int64) []byte {
	value := make([]byte, 40)
	binary.BigEndian.PutUint64(value[:8], uint64(bucket))
	m := hmac.New(sha256.New, l.secret[:])
	m.Write([]byte(source.String()))
	m.Write(route[:])
	m.Write(id[:])
	m.Write(value[:8])
	copy(value[8:], m.Sum(nil))
	return value
}
func (l *nativeUDPListener) validCookie(cookie []byte, source *net.UDPAddr, route, id [16]byte) bool {
	if len(cookie) != 40 {
		return false
	}
	bucket := int64(binary.BigEndian.Uint64(cookie[:8]))
	now := time.Now().Unix() / 60
	return (bucket == now || bucket == now-1) && hmac.Equal(cookie, l.cookie(source, route, id, bucket))
}

func (e *Engine) startNativeUDP(node *pb.NodeConfig) error {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(node.TunnelListenHost, strconv.Itoa(int(node.TunnelListenPort))))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &nativeUDPListener{conn: conn, ctx: ctx, cancel: cancel, node: proto.Clone(node).(*pb.NodeConfig), peers: map[[16]byte]*nativePeer{}, handshakes: make(chan struct{}, 32)}
	if _, err = rand.Read(l.secret[:]); err != nil {
		conn.Close()
		cancel()
		return err
	}
	e.nativeUDP = l
	e.wg.Add(1)
	go e.readNativeUDP(l)
	return nil
}
func (e *Engine) readNativeUDP(l *nativeUDPListener) {
	defer e.wg.Done()
	defer func() {
		l.mu.Lock()
		for _, p := range l.peers {
			p.Close()
		}
		l.mu.Unlock()
	}()
	buffer := make([]byte, 1500)
	for {
		n, source, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if n < nativeHeader+nativeMAC {
			continue
		}
		var route [16]byte
		copy(route[:], buffer[:16])
		policy := e.tunnelPolicy.Load()
		if policy == nil {
			continue
		}
		link, exists := policy.nativeRoutes[route]
		if !exists {
			continue
		}
		_, id, seq, kind, msg, index, total, body, valid := decodeNative(buffer[:n], link.key, true)
		if !valid {
			continue
		}
		l.mu.Lock()
		peer := l.peers[id]
		l.mu.Unlock()
		if peer != nil {
			if peer.key != link.key || peer.remote.String() != source.String() {
				continue
			}
			if kind == nativeOpen {
				peer.send(nativeAccepted, nil)
				continue
			}
			peer.receive(seq, kind, msg, index, total, body)
			continue
		}
		if kind != nativeOpen || total != 1 {
			continue
		}
		open, err := unsealNativeOpen(link.key, id, body)
		if err != nil || open.Network != "udp" || open.Ingress != link.ingress || open.Time < time.Now().Unix()-120 || open.Time > time.Now().Unix()+120 || !h2RuleAllowed(policy, open.h2Open) {
			continue
		}
		temporary := newNativePeer(l.ctx, l.conn, source, link.key, id, &e.udpQueued, false)
		if !l.validCookie(open.Cookie, source, route, id) {
			temporary.send(nativeChallenge, l.cookie(source, route, id, time.Now().Unix()/60))
			temporary.Close()
			continue
		}
		if !e.takeUDPNonce(link.key + hex.EncodeToString(id[:])) {
			temporary.Close()
			continue
		}
		active := e.connections.Add(1)
		if cap := e.maxConnections.Load(); cap > 0 && active > cap {
			e.connections.Add(-1)
			temporary.Close()
			continue
		}
		select {
		case l.handshakes <- struct{}{}:
		default:
			e.connections.Add(-1)
			temporary.Close()
			continue
		}
		l.mu.Lock()
		if len(l.peers) >= 65536 {
			l.mu.Unlock()
			<-l.handshakes
			e.connections.Add(-1)
			temporary.Close()
			continue
		}
		l.peers[id] = temporary
		l.mu.Unlock()
		temporary.replay.takeSequence(seq)
		temporary.send(nativeAccepted, nil)
		e.wg.Add(1)
		go e.runNativeUDP(l, temporary, open)
	}
}

type nativeLink struct {
	ingress int64
	key     string
}

func (e *Engine) runNativeUDP(l *nativeUDPListener, peer *nativePeer, open nativeGateOpen) {
	defer e.wg.Done()
	defer e.connections.Add(-1)
	defer func() { peer.Close(); l.mu.Lock(); delete(l.peers, peer.id); l.mu.Unlock() }()
	var conn net.Conn = peer
	if tunnel.TLS(l.node.TunnelProtocol) {
		cfg := e.node.Load()
		if cfg == nil || cfg.Tls == nil {
			<-l.handshakes
			return
		}
		pair, err := tls.X509KeyPair([]byte(cfg.Tls.Certificate), []byte(cfg.Tls.PrivateKey))
		if err != nil {
			<-l.handshakes
			return
		}
		encrypted, err := dtls.ServerWithOptions(&packetAdapter{Conn: peer}, peer.RemoteAddr(), dtls.WithCertificates(pair), dtls.WithMTU(1000), dtls.WithReplayProtectionWindow(4096))
		if err == nil {
			ctx, cancel := context.WithTimeout(peer.ctx, 8*time.Second)
			err = encrypted.HandshakeContext(ctx)
			cancel()
		}
		if err != nil {
			if encrypted != nil {
				encrypted.Close()
			}
			<-l.handshakes
			return
		}
		conn = newDTLSDatagram(encrypted, &e.udpQueued)
		defer conn.Close()
	}
	<-l.handshakes
	policy := e.tunnelPolicy.Load()
	if policy == nil {
		return
	}
	ctx, cancel := context.WithTimeout(peer.ctx, policy.dialTimeout)
	target, err := e.dialTarget(ctx, "udp", open.Target)
	cancel()
	if err != nil {
		return
	}
	defer target.Close()
	e.relayDatagrams(peer.ctx, conn, target, func() bool {
		node, policy := e.node.Load(), e.tunnelPolicy.Load()
		return node != nil && node.Enabled && node.TunnelExitEnabled && node.TunnelProtocol == l.node.TunnelProtocol && policy != nil && policy.links[open.Ingress] == peer.key && h2RuleAllowed(policy, open.h2Open)
	})
}

func dialNativeDatagram(ctx, lifetime context.Context, r *pb.Rule, target string, queued *atomic.Int64) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(r.TunnelHost, strconv.Itoa(int(r.TunnelPort))))
	if err != nil {
		return nil, err
	}
	network := "udp4"
	if addr.IP.To4() == nil {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	id, err := randomNativeID()
	if err != nil {
		socket.Close()
		return nil, err
	}
	peer := newNativePeer(lifetime, socket, addr, r.TunnelToken, id, queued, true)
	success := false
	defer func() {
		if !success {
			peer.Close()
			socket.Close()
		}
	}()
	stop := context.AfterFunc(peer.ctx, func() { socket.Close() })
	_ = stop
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := socket.ReadFromUDP(buf)
			if err != nil {
				peer.cancel()
				return
			}
			if from.String() != addr.String() {
				continue
			}
			_, pid, seq, kind, msg, index, total, body, ok := decodeNative(buf[:n], peer.key, false)
			if ok && pid == id {
				if kind == nativeChallenge || kind == nativeAccepted {
					peer.receiveControl(kind, body)
				} else {
					peer.receive(seq, kind, msg, index, total, body)
				}
			}
		}
	}()
	open := nativeGateOpen{udpStreamOpen: udpStreamOpen{h2Open: h2Open{Network: "udp", Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target}, Time: time.Now().Unix()}}
	accepted := false
	for !accepted {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		body, err := sealNativeOpen(peer.key, id, open)
		if err != nil {
			return nil, err
		}
		if len(body) > nativePartSize {
			return nil, errors.New("UDP gate metadata too large")
		}
		if err = peer.send(nativeOpen, body); err != nil {
			return nil, err
		}
		peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		reply, err := peer.next()
		if err != nil {
			if peer.ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if reply.kind == nativeChallenge {
			open.Cookie = reply.payload
		} else if reply.kind == nativeAccepted {
			accepted = true
		}
	}
	peer.SetDeadline(time.Time{})
	var conn net.Conn = peer
	if tunnel.TLS(r.TunnelProtocol) {
		if r.Tls == nil {
			return nil, errors.New("DTLS settings unavailable")
		}
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if r.Tls.RootCa != "" && !roots.AppendCertsFromPEM([]byte(r.Tls.RootCa)) {
			return nil, errors.New("invalid DTLS trust")
		}
		encrypted, err := dtls.ClientWithOptions(&packetAdapter{Conn: peer}, peer.RemoteAddr(), dtls.WithRootCAs(roots), dtls.WithServerName(r.Tls.ServerName), dtls.WithMTU(1000), dtls.WithReplayProtectionWindow(4096))
		if err == nil {
			err = encrypted.HandshakeContext(ctx)
		}
		if err != nil {
			if encrypted != nil {
				encrypted.Close()
			}
			return nil, err
		}
		conn = newDTLSDatagram(encrypted, queued)
	}
	success = true
	return conn, nil
}
