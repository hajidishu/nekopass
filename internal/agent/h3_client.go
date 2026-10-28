package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/quicpadding"
	"github.com/nekopass/nekopass/internal/tunnel"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type h3Peer struct {
	conn     *quic.Conn
	cc       *http3.ClientConn
	exporter []byte
	active   int
	sequence uint64
}
type h3Pool struct {
	mu      sync.Mutex
	peers   []*h3Peer
	retired bool
	onIdle  func()
	drain   *h3PoolDrain
}
type h3PoolDrain struct {
	ctx    context.Context
	cancel context.CancelFunc
}
type h3Transport struct {
	mu     sync.Mutex
	pools  map[string]*h3Pool
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	wg     sync.WaitGroup
}

func newH3Transport() *h3Transport {
	ctx, cancel := context.WithCancel(context.Background())
	return &h3Transport{pools: map[string]*h3Pool{}, ctx: ctx, cancel: cancel}
}
func (t *h3Transport) Close() {
	t.cancel()
	t.mu.Lock()
	t.closed = true
	for _, pool := range t.pools {
		pool.mu.Lock()
		pool.retired = true
		pool.closeLocked()
		pool.mu.Unlock()
	}
	t.pools = nil
	t.mu.Unlock()
	t.wg.Wait()
}
func (t *h3Transport) Prune(rules []*pb.Rule) {
	wanted := map[string]bool{}
	for _, r := range rules {
		if r.Enabled && tunnel.H3(r.TunnelProtocol) {
			wanted[h2PoolKey(r)] = true
		}
		for _, p := range r.EgressPeers {
			if r.Enabled && tunnel.H3(p.Protocol) {
				wanted[h2PoolKey(peerRule(r, p))] = true
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, pool := range t.pools {
		pool.mu.Lock()
		pool.retired = !wanted[key]
		if !pool.retired {
			pool.stopDrainLocked()
		} else {
			t.collectPoolLocked(key, pool)
		}
		pool.mu.Unlock()
	}
}

func (p *h3Pool) idleLocked() bool {
	for _, peer := range p.peers {
		if peer.active != 0 {
			return false
		}
	}
	return true
}
func (p *h3Pool) pendingLocked() bool {
	for _, peer := range p.peers {
		if peer.conn.Context().Err() == nil && peer.conn.OutgoingBidirectionalStreams() != 0 {
			return true
		}
	}
	return false
}
func (p *h3Pool) stopDrainLocked() {
	if p.drain != nil {
		p.drain.cancel()
		p.drain = nil
	}
}
func (p *h3Pool) closeLocked() {
	p.stopDrainLocked()
	for _, peer := range p.peers {
		peer.conn.CloseWithError(0, "")
	}
	p.peers = nil
}

// All paths taking both locks use transport.mu then pool.mu. A stream's lease
// release calls this only after dropping pool.mu.
func (t *h3Transport) collectPool(key string, pool *h3Pool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pools[key] != pool {
		return
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	t.collectPoolLocked(key, pool)
}
func (t *h3Transport) collectPoolLocked(key string, pool *h3Pool) {
	if !pool.retired || !pool.idleLocked() {
		return
	}
	if !pool.pendingLocked() {
		pool.closeLocked()
		delete(t.pools, key)
		return
	}
	if pool.drain != nil {
		return
	}
	// CloseWrite only queues a FIN. Preserve retransmission of reliable tails
	// until QUIC completes the streams, with the relay's 30-second grace bound.
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	drain := &h3PoolDrain{ctx: ctx, cancel: cancel}
	pool.drain = drain
	t.wg.Add(1)
	go t.drainPool(key, pool, drain)
}
func (t *h3Transport) drainPool(key string, pool *h3Pool, drain *h3PoolDrain) {
	defer t.wg.Done()
	defer drain.cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-drain.ctx.Done():
		case <-tick.C:
		}
		t.mu.Lock()
		pool.mu.Lock()
		if t.pools[key] != pool || pool.drain != drain || !pool.retired || !pool.idleLocked() {
			pool.mu.Unlock()
			t.mu.Unlock()
			return
		}
		done := !pool.pendingLocked() || drain.ctx.Err() != nil
		if done {
			pool.closeLocked()
			delete(t.pools, key)
		}
		pool.mu.Unlock()
		t.mu.Unlock()
		if done {
			return
		}
	}
}
func (p *h3Pool) reserve(ctx context.Context, r *pb.Rule) (*h3Peer, func(), uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return nil, nil, 0, net.ErrClosed
	}
	limit := int(r.Tls.PoolSize)
	if limit == 0 {
		limit = 2
	}
	if limit < 1 || limit > 8 {
		return nil, nil, 0, errors.New("invalid HTTP/3 pool size")
	}
	capacity := int(r.Tls.MaxStreams)
	if capacity == 0 {
		capacity = 256
	}
	var selected *h3Peer
	for i := 0; i < len(p.peers); {
		v := p.peers[i]
		if v.conn.Context().Err() != nil || v.sequence == math.MaxUint64 {
			v.conn.CloseWithError(0, "")
			p.peers = append(p.peers[:i], p.peers[i+1:]...)
			continue
		}
		if v.active < capacity && (selected == nil || v.active < selected.active) {
			selected = v
		}
		i++
	}
	if selected == nil && len(p.peers) < limit {
		v, err := dialH3Peer(ctx, r)
		if err != nil {
			return nil, nil, 0, err
		}
		p.peers = append(p.peers, v)
		selected = v
	}
	if selected == nil {
		return nil, nil, 0, errors.New("HTTP/3 stream capacity reached")
	}
	selected.active++
	selected.sequence++
	var once sync.Once
	release := func() {
		once.Do(func() {
			p.mu.Lock()
			selected.active--
			onIdle := p.onIdle
			collect := p.retired && p.idleLocked()
			p.mu.Unlock()
			if collect && onIdle != nil {
				onIdle()
			}
		})
	}
	return selected, release, selected.sequence, nil
}
func dialH3Peer(ctx context.Context, r *pb.Rule) (*h3Peer, error) {
	cfg := r.Tls
	if cfg == nil || cfg.ServerName == "" {
		return nil, errors.New("HTTP/3 TLS configuration missing")
	}
	packetPadding, err := quicpadding.ForConnection(cfg.QuicPadding)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if cfg.RootCa != "" && !roots.AppendCertsFromPEM([]byte(cfg.RootCa)) {
		return nil, errors.New("invalid HTTP/3 trust certificate")
	}
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(r.TunnelHost, strconv.Itoa(int(r.TunnelPort))), &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: cfg.ServerName, RootCAs: roots, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{PacketPadding: packetPadding, EnableDatagrams: true, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 20 * time.Second, MaxIncomingStreams: -1, MaxStreamReceiveWindow: uint64(cfg.StreamWindowMib) << 20, MaxConnectionReceiveWindow: uint64(cfg.ConnectionWindowMib) << 20})
	if err != nil {
		return nil, err
	}
	state := conn.ConnectionState().TLS
	exporter, err := state.ExportKeyingMaterial(h3ExporterLabel, nil, 32)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	cc := (&http3.Transport{EnableDatagrams: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}).NewClientConn(conn)
	return &h3Peer{conn: conn, cc: cc, exporter: exporter}, nil
}
func (t *h3Transport) Dial(dialCtx, lifetime context.Context, r *pb.Rule, target string, udp bool, queued *atomic.Int64) (net.Conn, error) {
	if !tunnel.H3(r.TunnelProtocol) || r.Tls == nil || len(r.TunnelToken) != 64 {
		return nil, errors.New("HTTP/3 configuration unavailable")
	}
	dialCtx, cancel := context.WithTimeout(dialCtx, 8*time.Second)
	defer cancel()
	stopTransport := context.AfterFunc(t.ctx, cancel)
	defer stopTransport()
	key := h2PoolKey(r)
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	pool := t.pools[key]
	if pool == nil {
		created := &h3Pool{}
		created.onIdle = func() { t.collectPool(key, created) }
		pool = created
		t.pools[key] = pool
	}
	t.mu.Unlock()
	peer, release, seq, err := pool.reserve(dialCtx, r)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	health := target == tunnelHealthTarget
	proxyDatagram := udp && !health
	request := &http.Request{Method: http.MethodConnect, Header: http.Header{}, URL: &url.URL{Host: target}, Host: target}
	if health {
		request.URL.Host = h3HealthAuthority
		request.Host = h3HealthAuthority
	}
	if proxyDatagram {
		select {
		case <-dialCtx.Done():
			return nil, dialCtx.Err()
		case <-peer.cc.Context().Done():
			return nil, net.ErrClosed
		case <-peer.cc.ReceivedSettings():
		}
		settings := peer.cc.Settings()
		if !settings.EnableDatagrams || !settings.EnableExtendedConnect {
			return nil, errors.New("HTTP/3 peer does not support CONNECT-UDP")
		}
		template, err := h3UDPTemplate(h3Authority(r.Tls, r), r.Tls.Path)
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		uri, err := template.Expand(uritemplate.Values{"target_host": uritemplate.String(host), "target_port": uritemplate.String(port)})
		if err != nil {
			return nil, err
		}
		request, err = http.NewRequestWithContext(lifetime, http.MethodConnect, uri, nil)
		if err != nil {
			return nil, err
		}
		request.Proto = "connect-udp"
		request.Host = request.URL.Host
		request.Header.Set(http3.CapsuleProtocolHeader, "?1")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	network := "tcp"
	if udp {
		network = "udp"
	}
	open := h2Open{Network: network, Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target, Nonce: hex.EncodeToString(nonce[:]), Seq: seq}
	metadata, _ := json.Marshal(open)
	request.Header.Set("X-Stream", base64.RawURLEncoding.EncodeToString(metadata))
	request.Header.Set("Authorization", "Bearer "+h3RequestProof(r.TunnelToken, peer.exporter, metadata, request))
	str, err := peer.cc.OpenRequestStream(dialCtx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	deadline, _ := dialCtx.Deadline()
	str.SetDeadline(deadline)
	stop := context.AfterFunc(dialCtx, func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})
	if err = str.SendRequestHeader(request); err != nil {
		stop()
		return nil, err
	}
	response, err := str.ReadResponse()
	stop()
	if err != nil {
		return nil, err
	}
	if err = dialCtx.Err(); err != nil {
		response.Body.Close()
		return nil, err
	}
	valid := hmac.Equal([]byte(response.Header.Get("X-Stream-Reply")), []byte(h2ResponseProof(r.TunnelToken, peer.exporter, metadata)))
	if response.StatusCode == 502 && valid {
		response.Body.Close()
		return nil, errTunnelTarget
	}
	if response.StatusCode != 200 || !valid {
		response.Body.Close()
		return nil, errors.New("HTTP/3 tunnel authentication refused")
	}
	str.SetDeadline(time.Time{})
	conn := newH3StreamConn(lifetime, str, peer.conn.LocalAddr(), peer.conn.RemoteAddr(), release)
	success = true
	if proxyDatagram {
		return newH3Datagram(conn, queued), nil
	}
	return conn, nil
}
