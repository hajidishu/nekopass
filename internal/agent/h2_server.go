package agent

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"golang.org/x/net/http2"
)

type h2SessionKey struct{}
type h2ServerSession struct {
	mu     sync.Mutex
	nonces map[string]bool
}

func (s *h2ServerSession) take(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nonces) >= 8192 || s.nonces[nonce] {
		return false
	}
	s.nonces[nonce] = true
	return true
}

func (e *Engine) startH2Server(ctx context.Context, ln net.Listener, cfg *pb.TLSServerConfig) error {
	pair, err := tls.X509KeyPair([]byte(cfg.Certificate), []byte(cfg.PrivateKey))
	if err != nil {
		return err
	}
	e.h2Certificate.Store(&pair)
	settings := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return e.h2Certificate.Load(), nil }}
	server := &http.Server{Handler: http.HandlerFunc(e.handleH2), TLSConfig: settings, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192,
		BaseContext: func(net.Listener) context.Context { return ctx }, ConnContext: func(parent context.Context, _ net.Conn) context.Context {
			return context.WithValue(parent, h2SessionKey{}, &h2ServerSession{nonces: map[string]bool{}})
		}}
	if err = http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: uint32(cfg.MaxStreams), MaxUploadBufferPerConnection: int32(cfg.ConnectionWindowMib) << 20, MaxUploadBufferPerStream: int32(cfg.StreamWindowMib) << 20, IdleTimeout: 60 * time.Second}); err != nil {
		return err
	}
	physical := int(e.maxConnections.Load())
	if physical == 0 {
		physical = 512
	}
	physical = max(16, min(physical, 512))
	ln = &limitedTLSListener{Listener: ln, slots: make(chan struct{}, physical)}
	e.wg.Add(1)
	go func() { defer e.wg.Done(); server.Serve(newCamouflageTLSListener(ctx, ln, settings, e)) }()
	e.wg.Add(1)
	go func() { defer e.wg.Done(); <-ctx.Done(); server.Close() }()
	return nil
}

func (e *Engine) handleH2(w http.ResponseWriter, r *http.Request) {
	node := e.node.Load()
	if node == nil || node.Tls == nil {
		e.camouflage(w, r)
		return
	}
	cfg := node.Tls
	expectedHost := cfg.Host
	if expectedHost == "" {
		expectedHost = cfg.ServerName
	}
	if r.URL.Path != cfg.Path || r.URL.RawQuery != "" || r.Method != "POST" || r.ProtoMajor != 2 || !camouflageHostMatches(r.Host, expectedHost) {
		e.camouflage(w, r)
		return
	}
	if !node.Enabled || !node.TunnelExitEnabled || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h2" {
		e.camouflage(w, r)
		return
	}
	encoded := r.Header.Get("X-Stream")
	if len(encoded) > 2048 {
		e.camouflage(w, r)
		return
	}
	metadata, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		e.camouflage(w, r)
		return
	}
	var open h2Open
	decoder := json.NewDecoder(strings.NewReader(string(metadata)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&open) != nil || decoder.Decode(new(any)) != io.EOF || len(open.Nonce) != 32 || len(open.Target) > 512 || open.Rule <= 0 || open.User <= 0 || open.Ingress <= 0 || open.Epoch < 0 {
		e.camouflage(w, r)
		return
	}
	if _, err = hex.DecodeString(open.Nonce); err != nil {
		e.camouflage(w, r)
		return
	}
	policy := e.tunnelPolicy.Load()
	if policy == nil {
		e.camouflage(w, r)
		return
	}
	key := policy.links[open.Ingress]
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		e.camouflage(w, r)
		return
	}
	proof := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	exporter, err := r.TLS.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil || len(key) != 64 || len(proof) != 64 || !hmac.Equal([]byte(proof), []byte(h2Proof(key, exporter, metadata))) || !h2RuleAllowed(policy, open) {
		e.camouflage(w, r)
		return
	}
	session, ok := r.Context().Value(h2SessionKey{}).(*h2ServerSession)
	if !ok || !session.take(open.Nonce) {
		e.camouflage(w, r)
		return
	}
	active := e.connections.Add(1)
	defer e.connections.Add(-1)
	if limit := e.maxConnections.Load(); limit > 0 && active > limit {
		http.Error(w, "Service unavailable", 503)
		return
	}
	dialCtx, cancelDial := context.WithTimeout(r.Context(), policy.dialTimeout)
	d := net.Dialer{KeepAlive: 30 * time.Second}
	target, err := d.DialContext(dialCtx, "tcp", open.Target)
	cancelDial()
	if err != nil {
		http.Error(w, "Service unavailable", 502)
		return
	}
	defer target.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Stream-Reply", h2ResponseProof(key, exporter, metadata))
	w.WriteHeader(200)
	controller := http.NewResponseController(w)
	if controller.Flush() != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer r.Body.Close()
	go func() {
		defer target.Close()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				target.Close()
				return
			case <-ticker.C:
				current := e.tunnelPolicy.Load()
				n := e.node.Load()
				if n == nil || !n.Enabled || !n.TunnelExitEnabled || current == nil || current.links[open.Ingress] != key || !h2RuleAllowed(current, open) {
					cancel()
					return
				}
			}
		}
	}()
	upload := make(chan error, 1)
	go func() {
		_, err := io.Copy(target, r.Body)
		if conn, ok := target.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
		if err != nil {
			cancel()
		}
		upload <- err
	}()
	buffer := buffers.Get().(*[]byte)
	defer buffers.Put(buffer)
	for {
		n, err := target.Read(*buffer)
		if n > 0 {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(n))
			if _, writeErr := w.Write(header[:]); writeErr != nil {
				break
			}
			if _, writeErr := w.Write((*buffer)[:n]); writeErr != nil {
				break
			}
			if controller.Flush() != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	var fin [4]byte
	w.Write(fin[:])
	controller.Flush()
	// The response END_STREAM is independent of upload FIN. The handler keeps
	// the request readable until upload ends (bounded after target half-close).
	select {
	case <-upload:
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
	}
}
func h2RuleAllowed(policy *tunnelPolicy, open h2Open) bool {
	return tunnelRuleAllowed(policy, open.Rule, open.Ingress, open.User, open.Epoch, open.Target)
}
