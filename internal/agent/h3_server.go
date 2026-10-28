package agent

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/quicpadding"
	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"google.golang.org/protobuf/proto"
)

const h3ExporterLabel = "nekopass/h3/open/v1"
const h3HealthAuthority = "health.nekopass.invalid:443"

type h3SessionKey struct{}
type h3ServerSession struct {
	conn  *quic.Conn
	proof h2ServerSession
}
type h3Listener struct {
	config        *pb.NodeConfig
	udp           *net.UDPConn
	tcp           net.Listener
	server        *http3.Server
	website       *http.Server
	fallbackSlots chan struct{}
	physical      atomic.Int64
	once          sync.Once
}

func (l *h3Listener) Close() {
	l.once.Do(func() { l.server.Close(); l.website.Close(); l.udp.Close(); l.tcp.Close() })
}
func h3Authority(cfg *pb.TLSClientConfig, r *pb.Rule) string {
	if cfg.Host != "" {
		return cfg.Host
	}
	host := cfg.ServerName
	if host == "" {
		host = r.TunnelHost
	}
	return net.JoinHostPort(host, strconv.Itoa(int(r.TunnelPort)))
}
func h3UDPTemplate(host, path string) (*uritemplate.Template, error) {
	prefix := (&url.URL{Path: strings.TrimSuffix(path, "/")}).EscapedPath()
	return uritemplate.New("https://" + host + prefix + "/{target_host}/{target_port}/")
}
func h3RequestProof(key string, exporter, metadata []byte, r *http.Request) string {
	protocol := ""
	if r.Proto == "connect-udp" {
		protocol = r.Proto
	}
	binding := strings.Join([]string{r.Method, r.Host, r.URL.EscapedPath(), r.URL.RawQuery, protocol}, "\x00")
	return h2Proof(key, exporter, append(append([]byte(nil), metadata...), []byte("\x00"+binding)...))
}
func (e *Engine) startH3(node *pb.NodeConfig) error {
	if node.Tls == nil {
		return errors.New("HTTP/3 TLS configuration missing")
	}
	packetPadding, err := quicpadding.ForConnection(node.Tls.QuicPadding)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair([]byte(node.Tls.Certificate), []byte(node.Tls.PrivateKey))
	if err != nil {
		return errors.New("HTTP/3 certificate not ready")
	}
	address := net.JoinHostPort(node.TunnelListenHost, strconv.Itoa(int(node.TunnelListenPort)))
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		tcp.Close()
		return err
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		tcp.Close()
		return err
	}
	e.h2Certificate.Store(&pair)
	l := &h3Listener{config: proto.Clone(node).(*pb.NodeConfig), udp: udp, tcp: tcp, fallbackSlots: make(chan struct{}, 64)}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return e.h2Certificate.Load(), nil }}
	l.server = &http3.Server{Addr: address, TLSConfig: tlsCfg, EnableDatagrams: true, MaxHeaderBytes: 16 << 10, IdleTimeout: 60 * time.Second,
		QUICConfig: &quic.Config{PacketPadding: packetPadding, EnableDatagrams: true, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 60 * time.Second, MaxIncomingStreams: int64(node.Tls.MaxStreams), MaxStreamReceiveWindow: uint64(node.Tls.StreamWindowMib) << 20, MaxConnectionReceiveWindow: uint64(node.Tls.ConnectionWindowMib) << 20},
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			active := l.physical.Add(1)
			context.AfterFunc(c.Context(), func() { l.physical.Add(-1) })
			if active > 512 {
				c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
			}
			return context.WithValue(ctx, h3SessionKey{}, &h3ServerSession{conn: c})
		}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.handleH3(l, w, r) })}
	l.website = &http.Server{TLSConfig: tlsCfg.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.h3Fallback(l, w, r) })}
	e.h3Listener = l
	e.wg.Add(2)
	go func() { defer e.wg.Done(); l.server.Serve(udp) }()
	go func() { defer e.wg.Done(); l.website.ServeTLS(tcp, "", "") }()
	return nil
}
func (e *Engine) h3Fallback(l *h3Listener, w http.ResponseWriter, r *http.Request) {
	select {
	case l.fallbackSlots <- struct{}{}:
		defer func() { <-l.fallbackSlots }()
	default:
		http.Error(w, "Service unavailable", 503)
		return
	}
	n := e.node.Load()
	port := 0
	if n != nil {
		port = int(n.TunnelListenPort)
		if n.Tls.GetPublicPort() != 0 {
			port = int(n.Tls.PublicPort)
		}
	}
	alt := fmt.Sprintf(`h3=":%d"; ma=86400`, port)
	if r.Method == http.MethodConnect {
		r = r.Clone(r.Context())
		r.Method = http.MethodGet
		r.URL = &url.URL{Path: "/"}
		r.Body = http.NoBody
		r.ContentLength = 0
		r.Header.Del("Content-Length")
		r.Header.Del(http3.CapsuleProtocolHeader)
	}
	w.Header().Set("Alt-Svc", alt)
	e.camouflageWithAltSvc(w, r, alt)
}
func (e *Engine) h3Allowed(key string, open h2Open) bool {
	n, p := e.node.Load(), e.tunnelPolicy.Load()
	return n != nil && n.Enabled && n.TunnelExitEnabled && n.TunnelProtocol == "tls_h3" && p != nil && p.links[open.Ingress] == key && h2RuleAllowed(p, open)
}
func (e *Engine) handleH3(l *h3Listener, w http.ResponseWriter, r *http.Request) {
	fallback := func() { e.h3Fallback(l, w, r) }
	session, ok := r.Context().Value(h3SessionKey{}).(*h3ServerSession)
	if !ok || r.ProtoMajor != 3 || r.Method != http.MethodConnect || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h3" {
		fallback()
		return
	}
	encoded := r.Header.Get("X-Stream")
	if len(encoded) > 2048 {
		fallback()
		return
	}
	metadata, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		fallback()
		return
	}
	var open h2Open
	decoder := json.NewDecoder(strings.NewReader(string(metadata)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&open) != nil || decoder.Decode(new(any)) != io.EOF || len(open.Nonce) != 32 || open.Seq == 0 || open.Rule <= 0 || open.User <= 0 || open.Ingress <= 0 || open.Epoch < 0 || len(open.Target) > 512 || open.Network != "tcp" && open.Network != "udp" {
		fallback()
		return
	}
	if _, err = hex.DecodeString(open.Nonce); err != nil {
		fallback()
		return
	}
	node := e.node.Load()
	policy := e.tunnelPolicy.Load()
	if node == nil || node.Tls == nil || policy == nil {
		fallback()
		return
	}
	key := policy.links[open.Ingress]
	exporter, err := r.TLS.ExportKeyingMaterial(h3ExporterLabel, nil, 32)
	if err != nil || len(key) != 64 || !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h3RequestProof(key, exporter, metadata, r))) || !e.h3Allowed(key, open) {
		fallback()
		return
	}
	health := open.Target == tunnelHealthTarget
	if open.Network == "udp" && !health {
		template, err := h3UDPTemplate(r.Host, node.Tls.Path)
		expected := node.Tls.Host
		if expected == "" {
			expected = node.Tls.ServerName
		}
		if err != nil || !camouflageHostMatches(r.Host, expected) {
			fallback()
			return
		}
		parsed, err := masque.ParseProxyRequest(r, template)
		if err != nil || parsed.Target != open.Target {
			fallback()
			return
		}
	} else {
		target := open.Target
		if health {
			target = h3HealthAuthority
		}
		if r.Proto == "connect-udp" || r.Host != target || r.URL.Path != "" || r.URL.RawQuery != "" {
			fallback()
			return
		}
	}
	if !session.proof.takeSequence(open.Seq) {
		fallback()
		return
	}
	if !session.proof.reserve(int(node.Tls.MaxStreams)) {
		http.Error(w, "Service unavailable", 503)
		return
	}
	defer session.proof.release()
	active := e.connections.Add(1)
	defer e.connections.Add(-1)
	if cap := e.maxConnections.Load(); cap > 0 && active > cap {
		http.Error(w, "Service unavailable", 503)
		return
	}
	var target net.Conn
	if !health {
		ctx, cancel := context.WithTimeout(r.Context(), policy.dialTimeout)
		target, err = e.dialTarget(ctx, open.Network, open.Target)
		cancel()
		if err != nil {
			w.Header().Set("X-Stream-Reply", h2ResponseProof(key, exporter, metadata))
			http.Error(w, "Service unavailable", 502)
			return
		}
		defer target.Close()
	}
	if !e.h3Allowed(key, open) {
		fallback()
		return
	}
	w.Header().Set("X-Stream-Reply", h2ResponseProof(key, exporter, metadata))
	if open.Network == "udp" && !health {
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	}
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	// quic-go's request context follows the response send direction. Once the
	// stream is hijacked, a response FIN must not cancel an ongoing upload.
	ctx := session.conn.Context()
	peer := newH3StreamConn(ctx, stream, session.conn.LocalAddr(), session.conn.RemoteAddr(), nil)
	defer peer.Close()
	if health {
		peer.CloseWrite()
		return
	}
	allowed := func() bool { return e.h3Allowed(key, open) && e.targetAllowed(target) }
	if open.Network == "udp" {
		datagrams := newH3Datagram(peer, &e.udpQueued)
		defer datagrams.Close()
		e.relayDatagrams(ctx, datagrams, target, allowed)
		return
	}
	e.relayH3TCP(ctx, peer, target, allowed)
}
func (e *Engine) relayH3TCP(ctx context.Context, peer, target net.Conn, allowed func() bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { peer.Close(); target.Close() })
	defer stop()
	done := make(chan error, 2)
	for _, pair := range [][2]net.Conn{{target, peer}, {peer, target}} {
		go func() {
			_, err := io.Copy(pair[0], pair[1])
			if half, ok := pair[0].(interface{ CloseWrite() error }); ok {
				half.CloseWrite()
			}
			done <- err
		}()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var grace <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	finished := 0
	for finished < 2 {
		select {
		case err := <-done:
			finished++
			if err != nil {
				cancel()
			}
			if timer == nil {
				timer = time.NewTimer(30 * time.Second)
				grace = timer.C
			}
		case <-ctx.Done():
			peer.Close()
			target.Close()
			for finished < 2 {
				<-done
				finished++
			}
		case <-grace:
			cancel()
		case <-ticker.C:
			if !allowed() {
				cancel()
			}
		}
	}
}
