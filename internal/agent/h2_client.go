package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const exporterLabel = "nekopass/h2/open/v1"

type h2Open struct {
	Ingress int64  `json:"ingress"`
	Rule    int64  `json:"rule"`
	User    int64  `json:"user"`
	Epoch   int64  `json:"epoch"`
	Target  string `json:"target"`
	Nonce   string `json:"nonce"`
}

func h2Proof(key string, exporter, metadata []byte) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write(exporter)
	m.Write(metadata)
	return hex.EncodeToString(m.Sum(nil))
}

type h2Peer struct {
	cc       *http2.ClientConn
	conn     *utls.UConn
	exporter []byte
	opened   int
}
type h2Pool struct {
	mu    sync.Mutex
	peers []*h2Peer
	next  int
}
type h2Transport struct {
	mu     sync.Mutex
	pools  map[string]*h2Pool
	closed bool
}

func newH2Transport() *h2Transport { return &h2Transport{pools: map[string]*h2Pool{}} }
func h2PoolKey(rule *pb.Rule) string {
	encoded, _ := json.Marshal(rule.Tls)
	sum := sha256.Sum256(encoded)
	return net.JoinHostPort(rule.TunnelHost, strconv.Itoa(int(rule.TunnelPort))) + hex.EncodeToString(sum[:])
}
func (t *h2Transport) Prune(rules []*pb.Rule) {
	wanted := map[string]bool{}
	for _, rule := range rules {
		if rule.TunnelProtocol == "tls_h2" && rule.Tls != nil {
			wanted[h2PoolKey(rule)] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, pool := range t.pools {
		if !wanted[key] {
			pool.mu.Lock()
			for _, peer := range pool.peers {
				peer.cc.Close()
				peer.conn.Close()
			}
			pool.mu.Unlock()
			delete(t.pools, key)
		}
	}
}
func (t *h2Transport) Close() {
	t.mu.Lock()
	t.closed = true
	for _, pool := range t.pools {
		pool.mu.Lock()
		for _, peer := range pool.peers {
			peer.cc.Close()
			peer.conn.Close()
		}
		pool.mu.Unlock()
	}
	t.pools = nil
	t.mu.Unlock()
}

func (t *h2Transport) Dial(dialCtx, lifetime context.Context, rule *pb.Rule, target string) (net.Conn, error) {
	cfg := rule.Tls
	if cfg == nil || cfg.ServerName == "" || cfg.Path == "" || len(rule.TunnelToken) != 64 {
		return nil, errors.New("TLS tunnel configuration unavailable")
	}
	key := h2PoolKey(rule)
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	pool := t.pools[key]
	if pool == nil {
		pool = &h2Pool{}
		t.pools[key] = pool
	}
	t.mu.Unlock()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	metadata, _ := json.Marshal(h2Open{Ingress: rule.IngressNodeId, Rule: rule.Id, User: rule.UserId, Epoch: rule.QuotaEpoch, Target: target, Nonce: hex.EncodeToString(nonce[:])})
	ctx, cancel := context.WithCancel(lifetime)
	r, w := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, "POST", "https://"+net.JoinHostPort(cfg.ServerName, strconv.Itoa(int(rule.TunnelPort)))+cfg.Path, r)
	if err != nil {
		cancel()
		r.Close()
		w.Close()
		return nil, err
	}
	peer, err := pool.reserve(dialCtx, rule)
	if err != nil {
		cancel()
		r.Close()
		w.Close()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("X-Stream", base64.RawURLEncoding.EncodeToString(metadata))
	request.Header.Set("Authorization", "Bearer "+h2Proof(rule.TunnelToken, peer.exporter, metadata))
	response := make(chan struct {
		r   *http.Response
		err error
	}, 1)
	go func() {
		resp, err := peer.cc.RoundTrip(request)
		response <- struct {
			r   *http.Response
			err error
		}{resp, err}
	}()
	select {
	case result := <-response:
		if result.err != nil {
			cancel()
			r.Close()
			w.Close()
			return nil, result.err
		}
		if result.r.StatusCode != http.StatusOK {
			result.r.Body.Close()
			cancel()
			r.Close()
			w.Close()
			return nil, errors.New("TLS tunnel refused connection")
		}
		return &h2StreamConn{r: &h2PayloadReader{body: result.r.Body}, w: w, cancel: cancel, local: peer.conn.LocalAddr(), remote: peer.conn.RemoteAddr()}, nil
	case <-dialCtx.Done():
		cancel()
		r.Close()
		w.Close()
		go func() {
			result := <-response
			if result.r != nil {
				result.r.Body.Close()
			}
		}()
		return nil, dialCtx.Err()
	}
}

func (p *h2Pool) reserve(ctx context.Context, rule *pb.Rule) (*h2Peer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	limit := int(rule.Tls.PoolSize)
	if limit < 1 {
		limit = 2
	}
	if limit > 8 {
		return nil, errors.New("invalid TLS pool size")
	}
	// Add lazily under load; empty users/rules never create a TLS connection.
	for len(p.peers) < limit {
		if len(p.peers) > 0 && p.peers[0].cc.State().StreamsActive == 0 {
			break
		}
		peer, err := dialH2Peer(ctx, rule)
		if err != nil {
			if len(p.peers) == 0 {
				return nil, err
			}
			break
		}
		p.peers = append(p.peers, peer)
	}
	for offset := 0; offset < len(p.peers); offset++ {
		index := (p.next + offset) % len(p.peers)
		peer := p.peers[index]
		if peer.opened < 4096 && peer.cc.ReserveNewRequest() {
			peer.opened++
			p.next = index + 1
			return peer, nil
		}
	}
	// Replace a drained stale peer, never multiply connections past the configured cap.
	for index, peer := range p.peers {
		state := peer.cc.State()
		if state.StreamsActive == 0 && state.StreamsReserved == 0 {
			peer.cc.Close()
			peer.conn.Close()
			replacement, err := dialH2Peer(ctx, rule)
			if err != nil {
				return nil, err
			}
			p.peers[index] = replacement
			if replacement.cc.ReserveNewRequest() {
				replacement.opened++
				return replacement, nil
			}
		}
	}
	return nil, errors.New("HTTP/2 tunnel stream capacity reached; retry later")
}

func dialH2Peer(ctx context.Context, rule *pb.Rule) (*h2Peer, error) {
	cfg := rule.Tls
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if cfg.RootCa != "" && !roots.AppendCertsFromPEM([]byte(cfg.RootCa)) {
		return nil, errors.New("invalid TLS tunnel trust certificate")
	}
	profile := utls.HelloChrome_Auto
	if cfg.Fingerprint == "firefox" {
		profile = utls.HelloFirefox_Auto
	} else if cfg.Fingerprint != "chrome" {
		return nil, errors.New("unsupported uTLS fingerprint")
	}
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(rule.TunnelHost, strconv.Itoa(int(rule.TunnelPort))))
	if err != nil {
		return nil, err
	}
	conn := utls.UClient(raw, &utls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13}, profile)
	if err = conn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, err
	}
	// Browser presets include renegotiation_info on the wire. Keep that extension
	// unchanged, while disabling the legacy internal mode (TLS 1.3 can't renegotiate).
	for _, extension := range conn.Extensions {
		if info, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			info.Renegotiation = utls.RenegotiateNever
		}
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	state := conn.ConnectionState()
	if state.Version != utls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, errors.New("TLS 1.3 and h2 must be negotiated")
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		conn.Close()
		return nil, err
	}
	stream, connection := cfg.StreamWindowMib, cfg.ConnectionWindowMib
	if stream < 1 || stream > 64 || connection < stream || connection > 256 {
		conn.Close()
		return nil, errors.New("invalid HTTP/2 flow control configuration")
	}
	base := &http.Transport{HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: int(stream) << 20, MaxReceiveBufferPerConnection: int(connection) << 20, SendPingTimeout: 30 * time.Second, PingTimeout: 10 * time.Second}}
	transport, err := http2.ConfigureTransports(base)
	if err != nil {
		conn.Close()
		return nil, err
	}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("HTTP/2 setup: %w", err)
	}
	return &h2Peer{cc: cc, conn: conn, exporter: exporter}, nil
}
