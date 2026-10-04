package control

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Only explicitly trusted reverse proxies may supply protocol/client headers.
func (s *Server) SetTrustedProxies(raw string) error {
	var ranges []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, network, err := net.ParseCIDR(part)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q", part)
		}
		ranges = append(ranges, network)
	}
	s.trustedProxies = ranges
	return nil
}
func (s *Server) trustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func remoteIP(r *http.Request) net.IP {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}
func (s *Server) requestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.trustedProxy(remoteIP(r)) && r.Header.Get("X-Forwarded-Proto") == "https"
}

// Browsers refuse to overwrite a Secure cookie from an HTTP origin, even when
// the old and new services use different ports. Keep the two sessions separate.
func (s *Server) sessionCookieName(r *http.Request) string {
	if s.requestHTTPS(r) {
		return "nekopass_session"
	}
	return "nekopass_session_http"
}
func (s *Server) clientIP(r *http.Request) string {
	ip := remoteIP(r)
	if s.trustedProxy(ip) {
		chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(chain) - 1; i >= 0; i-- {
			if !s.trustedProxy(ip) {
				break
			}
			next := net.ParseIP(strings.TrimSpace(chain[i]))
			if next == nil {
				break
			}
			ip = next
		}
	}
	return ip.String()
}
