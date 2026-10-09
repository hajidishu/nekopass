package agent

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

type udpStreamOpen struct {
	h2Open
	Time int64 `json:"time"`
}

func dialRawDatagramTunnel(ctx context.Context, r *pb.Rule, target string) (net.Conn, error) {
	if !tunnel.Raw(r.TunnelProtocol) {
		return nil, errors.New("unsupported UDP tunnel")
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(r.TunnelHost, strconv.Itoa(int(r.TunnelPort))))
	if err != nil {
		return nil, err
	}
	c := raw
	var binding []byte
	if tunnel.TLS(r.TunnelProtocol) {
		if r.Tls == nil {
			raw.Close()
			return nil, errors.New("TLS settings missing")
		}
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if r.Tls.RootCa != "" && !roots.AppendCertsFromPEM([]byte(r.Tls.RootCa)) {
			raw.Close()
			return nil, errors.New("TLS trust invalid")
		}
		c, binding, err = dialTunnelTLSProtocol(ctx, raw, r.Tls, roots, false)
		if err != nil {
			return nil, err
		}
	}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	var nonce [16]byte
	rand.Read(nonce[:])
	open := udpStreamOpen{h2Open: h2Open{Network: "udp", Ingress: r.IngressNodeId, Rule: r.Id, User: r.UserId, Epoch: r.QuotaEpoch, Target: target, Nonce: hex.EncodeToString(nonce[:])}, Time: time.Now().Unix()}
	metadata, _ := json.Marshal(open)
	host := net.JoinHostPort(r.TunnelHost, strconv.Itoa(int(r.TunnelPort)))
	path := "/api/stream"
	if r.Tls != nil {
		if r.Tls.Host != "" {
			host = r.Tls.Host
		}
		if r.Tls.Path != "" {
			path = r.Tls.Path
		}
	}
	request, _ := http.NewRequest("POST", "http://"+host+path, nil)
	request.Header.Set("X-Stream", base64.RawURLEncoding.EncodeToString(metadata))
	request.Header.Set("Authorization", "Bearer "+h2Proof(r.TunnelToken, binding, metadata))
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	} else {
		c.SetDeadline(time.Now().Add(8 * time.Second))
	}
	if err = request.Write(c); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(c, 8192)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != 200 || !hmac.Equal([]byte(response.Header.Get("X-Stream-Reply")), []byte(h2ResponseProof(r.TunnelToken, binding, metadata))) {
		return nil, errors.New("UDP tunnel authentication refused")
	}
	c.SetDeadline(time.Time{})
	success = true
	return &framedDatagram{Conn: &bufferedConn{Conn: c, reader: reader}}, nil
}

func (e *Engine) handleUDPStream(ctx context.Context, c net.Conn, reader *bufio.Reader) {
	bounded := &boundedHeaderReader{Reader: reader, left: 8192}
	reader = bufio.NewReaderSize(bounded, 8192)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	bounded.left = -1
	defer request.Body.Close()
	node, policy := e.node.Load(), e.tunnelPolicy.Load()
	encoded := request.Header.Get("X-Stream")
	metadata, err := base64.RawURLEncoding.DecodeString(encoded)
	var open udpStreamOpen
	if err != nil || len(metadata) > 2048 || json.Unmarshal(metadata, &open) != nil || open.Network != "udp" || len(open.Nonce) != 32 || open.Time < time.Now().Unix()-120 || open.Time > time.Now().Unix()+120 || node == nil || policy == nil {
		e.serveRawCamouflage(ctx, c, reader, request)
		return
	}
	path := "/api/stream"
	host := ""
	if node.Tls != nil {
		path = node.Tls.Path
		host = node.Tls.Host
	}
	var binding []byte
	if tlsConn, ok := c.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		binding, err = state.ExportKeyingMaterial(exporterLabel, nil, 32)
		if err != nil {
			return
		}
	}
	key := policy.links[open.Ingress]
	if request.Method != "POST" || request.URL.Path != path || request.URL.RawQuery != "" || request.ContentLength != 0 || !camouflageHostMatches(request.Host, host) || len(key) != 64 || !hmac.Equal([]byte(request.Header.Get("Authorization")), []byte("Bearer "+h2Proof(key, binding, metadata))) || !h2RuleAllowed(policy, open.h2Open) || !e.takeUDPNonce(key+open.Nonce) {
		e.serveRawCamouflage(ctx, c, reader, request)
		return
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, policy.dialTimeout)
	target, err := e.dialTarget(dialCtx, "udp", open.Target)
	cancelDial()
	if err != nil {
		return
	}
	defer target.Close()
	allowed := func() bool {
		n, p := e.node.Load(), e.tunnelPolicy.Load()
		return n != nil && n.Enabled && n.TunnelExitEnabled && tunnel.Raw(n.TunnelProtocol) && p != nil && p.links[open.Ingress] == key && h2RuleAllowed(p, open.h2Open)
	}
	if !allowed() {
		return
	}
	if _, err = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Stream-Reply: " + h2ResponseProof(key, binding, metadata) + "\r\n\r\n")); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	e.relayDatagrams(ctx, &framedDatagram{Conn: &bufferedConn{Conn: c, reader: reader}}, target, allowed)
}

type boundedHeaderReader struct {
	Reader *bufio.Reader
	left   int
}

func (r *boundedHeaderReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, errors.New("HTTP header too large")
	}
	if r.left > 0 {
		p = p[:min(len(p), r.left)]
	}
	n, err := r.Reader.Read(p)
	if r.left > 0 {
		r.left -= n
	}
	return n, err
}

func (e *Engine) takeUDPNonce(nonce string) bool {
	e.udpNonceMu.Lock()
	defer e.udpNonceMu.Unlock()
	now := time.Now()
	for n, expires := range e.udpNonces {
		if expires.Before(now) {
			delete(e.udpNonces, n)
		}
	}
	if e.udpNonces[nonce].After(now) || len(e.udpNonces) >= 8192 {
		return false
	}
	e.udpNonces[nonce] = now.Add(4 * time.Minute)
	return true
}

// A single HTTP request receives the same decoy handler as the h2 listener.
func (e *Engine) serveRawCamouflage(ctx context.Context, c net.Conn, reader *bufio.Reader, request *http.Request) {
	if request == nil {
		return
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	response := &rawResponse{conn: c, header: http.Header{}}
	e.camouflage(response, request.WithContext(ctx))
	response.finish()
}

type rawResponse struct {
	conn    net.Conn
	header  http.Header
	started bool
}

func (w *rawResponse) Header() http.Header { return w.header }
func (w *rawResponse) WriteHeader(status int) {
	if w.started {
		return
	}
	w.started = true
	w.header.Set("Connection", "close")
	w.header.Del("Content-Length")
	w.header.Set("Transfer-Encoding", "chunked")
	w.conn.Write([]byte("HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n"))
	w.header.Write(w.conn)
	w.conn.Write([]byte("\r\n"))
}
func (w *rawResponse) Write(p []byte) (int, error) {
	if !w.started {
		w.WriteHeader(200)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := w.conn.Write([]byte(strconv.FormatInt(int64(len(p)), 16) + "\r\n")); err != nil {
		return 0, err
	}
	n, err := w.conn.Write(p)
	if err == nil {
		_, err = w.conn.Write([]byte("\r\n"))
	}
	return n, err
}
func (w *rawResponse) finish() {
	if !w.started {
		w.WriteHeader(404)
	}
	w.conn.Write([]byte("0\r\n\r\n"))
}
