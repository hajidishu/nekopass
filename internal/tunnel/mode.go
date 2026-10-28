// Package tunnel keeps transport and security choices independent. Mode is the
// stable wire/database encoding retained for compatibility with older agents.
package tunnel

import "errors"

func Split(mode string) (transport, security string) {
	switch mode {
	case "plain_tcp":
		return "raw_tcp", "none"
	case "tls_tcp":
		return "raw_tcp", "tls"
	case "random_tcp":
		return "raw_tcp", "random"
	case "plain_h2":
		return "h2", "none"
	case "tls_h2":
		return "h2", "tls"
	case "tls_h3":
		return "h3", "tls"
	case "random_h2":
		return "h2", "random"
	case "random_udp":
		return "raw_udp", "random"
	case "plain_udp":
		return "raw_udp", "none"
	case "dtls_udp":
		return "raw_udp", "tls"
	}
	return "", ""
}

func Compose(transport, security string) (string, error) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2", "plain_udp", "dtls_udp", "random_tcp", "random_h2", "random_udp", "tls_h3"} {
		t, s := Split(mode)
		if t == transport && s == security {
			return mode, nil
		}
	}
	return "", errors.New("unsupported tunnel transport or security")
}

func Valid(mode string) bool  { t, _ := Split(mode); return t != "" }
func TLS(mode string) bool    { _, s := Split(mode); return s == "tls" }
func Random(mode string) bool { _, s := Split(mode); return s == "random" }
func H2(mode string) bool     { t, _ := Split(mode); return t == "h2" }
func H3(mode string) bool     { return mode == "tls_h3" }
func Networks(mode string) []string {
	if H3(mode) {
		return []string{"tcp", "udp"}
	}
	if UDP(mode) {
		return []string{"udp"}
	}
	return []string{"tcp"}
}
func Raw(mode string) bool { t, _ := Split(mode); return t == "raw_tcp" }
func UDP(mode string) bool { t, _ := Split(mode); return t == "raw_udp" }
func MinimumVersion(mode string) int {
	switch mode {
	case "tls_h3":
		return 28
	case "random_udp":
		return 27
	case "random_tcp", "random_h2":
		return 26
	case "plain_tcp":
		return 6
	case "tls_h2":
		return 11
	case "tls_tcp", "plain_h2":
		return 13
	case "plain_udp", "dtls_udp":
		return 17
	}
	return 1 << 30
}
