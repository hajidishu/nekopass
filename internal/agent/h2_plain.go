package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"golang.org/x/net/http2"
)

// Plain H2 authenticates each connection with its own public random binding.
// Captured open proofs cannot be replayed on a different connection. This is
// authentication only; headers and payload remain readable on the network.
func (e *Engine) startH2PlainServer(ctx context.Context, ln net.Listener, cfg *pb.TLSServerConfig) error {
	physical := int(e.maxConnections.Load())
	if physical == 0 {
		physical = 512
	}
	physical = max(16, min(physical, 512))
	ln = &limitedTLSListener{Listener: ln, slots: make(chan struct{}, physical)}
	server := &http2.Server{MaxConcurrentStreams: 250, MaxUploadBufferPerConnection: int32(cfg.ConnectionWindowMib) << 20, IdleTimeout: 60 * time.Second, ReadIdleTimeout: 30 * time.Second, PingTimeout: 10 * time.Second}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			binding := make([]byte, 32)
			if _, err = rand.Read(binding); err != nil {
				conn.Close()
				continue
			}
			session := &h2ServerSession{binding: binding, nonces: map[string]bool{}}
			e.wg.Add(1)
			go func() {
				defer e.wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				server.ServeConn(conn, &http2.ServeConnOpts{Context: context.WithValue(ctx, h2SessionKey{}, session), BaseConfig: &http.Server{ReadHeaderTimeout: 5 * time.Second}, Handler: http.HandlerFunc(e.handleH2)})
			}()
		}
	}()
	return nil
}

func bindingMetadata(ingress int64, nonce string) []byte {
	return []byte(fmt.Sprintf("nekopass/h2c/bind/v1:%d:%s", ingress, nonce))
}

func (e *Engine) handleH2Binding(w http.ResponseWriter, r *http.Request, node *pb.NodeConfig) bool {
	cfg := node.Tls
	host := cfg.Host
	if host == "" {
		host = cfg.ServerName
	}
	if !node.Enabled || !node.TunnelExitEnabled || r.ProtoMajor != 2 || r.TLS != nil || r.URL.Path != cfg.Path || r.URL.RawQuery != "" || host != "" && !camouflageHostMatches(r.Host, host) {
		return false
	}
	ingress, err := strconv.ParseInt(r.Header.Get("X-Stream-Ingress"), 10, 64)
	if err != nil || ingress <= 0 {
		return false
	}
	nonce := r.Header.Get("X-Stream-Nonce")
	if len(nonce) != 32 {
		return false
	}
	if _, err = hex.DecodeString(nonce); err != nil {
		return false
	}
	policy := e.tunnelPolicy.Load()
	if policy == nil {
		return false
	}
	key := policy.links[ingress]
	metadata := bindingMetadata(ingress, nonce)
	if len(key) != 64 || !hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h2Proof(key, nil, metadata))) {
		return false
	}
	session, ok := r.Context().Value(h2SessionKey{}).(*h2ServerSession)
	if !ok || len(session.binding) != 32 || !session.take(nonce) {
		return false
	}
	w.Header().Set("X-Stream-Binding", base64.RawURLEncoding.EncodeToString(session.binding))
	w.Header().Set("X-Stream-Reply", h2ResponseProof(key, session.binding, metadata))
	w.WriteHeader(http.StatusOK)
	return true
}

func requestH2Binding(ctx context.Context, cc *http2.ClientConn, rule *pb.Rule) ([]byte, error) {
	cfg := rule.Tls
	host := cfg.Host
	if host == "" {
		host = cfg.ServerName
	}
	if host == "" {
		host = net.JoinHostPort(rule.TunnelHost, strconv.Itoa(int(rule.TunnelPort)))
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	value := hex.EncodeToString(nonce[:])
	metadata := bindingMetadata(rule.IngressNodeId, value)
	request, err := http.NewRequestWithContext(ctx, "HEAD", "http://"+host+cfg.Path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Stream-Ingress", strconv.FormatInt(rule.IngressNodeId, 10))
	request.Header.Set("X-Stream-Nonce", value)
	request.Header.Set("Authorization", "Bearer "+h2Proof(rule.TunnelToken, nil, metadata))
	response, err := cc.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	binding, err := base64.RawURLEncoding.DecodeString(response.Header.Get("X-Stream-Binding"))
	if err != nil || len(binding) != 32 || response.StatusCode != http.StatusOK || !hmac.Equal([]byte(response.Header.Get("X-Stream-Reply")), []byte(h2ResponseProof(rule.TunnelToken, binding, metadata))) {
		return nil, errors.New("HTTP/2 connection authentication failed")
	}
	return binding, nil
}
