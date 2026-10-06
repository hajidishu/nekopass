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
	case "plain_h2":
		return "h2", "none"
	case "tls_h2":
		return "h2", "tls"
	}
	return "", ""
}

func Compose(transport, security string) (string, error) {
	for _, mode := range []string{"plain_tcp", "tls_tcp", "plain_h2", "tls_h2"} {
		t, s := Split(mode)
		if t == transport && s == security {
			return mode, nil
		}
	}
	return "", errors.New("unsupported tunnel transport or security")
}

func Valid(mode string) bool { t, _ := Split(mode); return t != "" }
func TLS(mode string) bool   { _, s := Split(mode); return s == "tls" }
func H2(mode string) bool    { t, _ := Split(mode); return t == "h2" }
func Raw(mode string) bool   { t, _ := Split(mode); return t == "raw_tcp" }
func MinimumVersion(mode string) int {
	switch mode {
	case "plain_tcp":
		return 6
	case "tls_h2":
		return 11
	case "tls_tcp", "plain_h2":
		return 13
	}
	return 1 << 30
}
