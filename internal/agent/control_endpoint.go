package agent

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// HTTP means explicit h2c for test installations. HTTPS verifies against system roots.
// A legacy host:port endpoint retains verified TLS; there is no automatic downgrade.
func controlEndpoint(raw string) (string, credentials.TransportCredentials, error) {
	target := raw
	plain := false
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
			return "", nil, errors.New("control endpoint must be http://host:port or https://host:port")
		}
		target = u.Host
		plain = u.Scheme == "http"
	}
	host, port, err := net.SplitHostPort(target)
	number, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || number < 1 || number > 65535 || strings.ContainsAny(raw, "\r\n\x00") {
		return "", nil, errors.New("invalid control host or port")
	}
	if plain {
		return target, insecure.NewCredentials(), nil
	}
	return target, credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), nil
}
