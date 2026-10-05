package control

import "testing"

func TestTLSH2OptionalFingerprintAndProbeConfigValidation(t *testing.T) {
	for _, mode := range []string{"", "off", "chrome", "firefox"} {
		cfg := DefaultTunnelTLS()
		cfg.Fingerprint = mode
		cfg.Host = "assets.example.test:8443"
		cfg.FallbackURL = "https://www.example.test/site"
		if e := cfg.normalize(); e != nil {
			t.Fatal(e)
		}
	}
	if DefaultTunnelTLS().Fingerprint != "off" {
		t.Fatal("uTLS must be optional by default")
	}
	for _, host := range []string{"evil.test/path", "evil.test@victim.test", "example.test:70000", "example.test:", "example.test\r\nX-Header: injected"} {
		cfg := DefaultTunnelTLS()
		cfg.Host = host
		if cfg.normalize() == nil {
			t.Fatal("invalid Host accepted", host)
		}
	}
	for _, website := range []string{"file:///etc/passwd", "https://user:password@example.test", "https://example.test/#fragment", "https://example.test/?token=secret", "https://example.test:70000", "https://example.test:", "https://example.test\r\n"} {
		cfg := DefaultTunnelTLS()
		cfg.FallbackURL = website
		if website == "https://example.test\r\n" {
			website = "https://example.test/\r\nheader"
			cfg.FallbackURL = website
		}
		if cfg.normalize() == nil {
			t.Fatal("invalid camouflage URL accepted", website)
		}
	}
}
