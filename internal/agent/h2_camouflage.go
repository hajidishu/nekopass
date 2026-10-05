package agent

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const nginx404Body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

var camouflageTransport = &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 64, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 64, MaxResponseHeaderBytes: 64 << 10}

func nginx404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(nginx404Body)))
	w.WriteHeader(http.StatusNotFound)
	if r.Method != "HEAD" {
		io.WriteString(w, nginx404Body)
	}
}

func camouflageHostMatches(got, expected string) bool {
	// Host without a configured port accepts the advertised/public port. An
	// explicitly configured authority (host:port) must match exactly.
	if expected == "" {
		return true
	}
	if strings.ContainsAny(got, "/\\\r\n\x00") {
		return false
	}
	u, e := url.Parse("https://" + got)
	if e != nil || u.Host != got || u.User != nil {
		return false
	}
	v, e := url.Parse("https://" + expected)
	if e != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(v.Hostname(), ".")) && (v.Port() == "" || u.Port() == v.Port())
}

func (e *Engine) camouflage(w http.ResponseWriter, r *http.Request) {
	node := e.node.Load()
	if node == nil || node.Tls == nil || node.Tls.FallbackUrl == "" {
		nginx404(w, r)
		return
	}
	target, err := url.Parse(node.Tls.FallbackUrl)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		nginx404(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.Clone(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	proxy := &httputil.ReverseProxy{Transport: camouflageTransport, ErrorLog: log.New(io.Discard, "", 0), Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(target)
		p.Out.Host = target.Host
		// Tunnel metadata and exporter-bound proofs must never reach the decoy.
		p.Out.Header.Del("Authorization")
		p.Out.Header.Del("Proxy-Authorization")
		p.Out.Header.Del("X-Stream")
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) { nginx404(w, r) }}
	proxy.ServeHTTP(w, r)
}
