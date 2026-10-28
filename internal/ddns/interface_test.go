package ddns

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
)

func TestInterfaceAddressSelection(t *testing.T) {
	for _, tc := range []struct {
		name, want        string
		addresses         []string
		v6, ignorePrivate bool
	}{
		{"public preferred", "203.0.113.7", []string{"127.0.0.1", "10.0.0.1", "203.0.113.8", "203.0.113.7"}, false, false},
		{"private filtered", "", []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1", "127.0.0.1"}, false, true},
		{"private allowed", "10.0.0.1", []string{"127.0.0.1", "192.168.1.1", "10.0.0.1"}, false, false},
		{"loopback allowed", "127.0.0.1", []string{"127.0.0.1"}, false, false},
		{"ipv6 public preferred", "2001:db8::7", []string{"::1", "fd00::1", "2001:db8::8", "2001:db8::7"}, true, false},
		{"ipv6 filtered", "", []string{"fd00::1", "::1"}, true, true},
		{"ipv6 private allowed", "fd00::1", []string{"::1", "fd00::1"}, true, false},
		{"ipv6 loopback allowed", "::1", []string{"::1"}, true, false},
		{"invalid IPv4 targets", "", []string{"0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255", "2001:db8::1"}, false, false},
		{"invalid IPv6 targets", "", []string{"::", "fe80::1", "fe80::1%eth0", "ff02::1", "203.0.113.7"}, true, false},
		{"mapped private filtered", "", []string{"::ffff:192.168.1.1"}, false, true},
		{"mapped public", "203.0.113.7", []string{"::ffff:203.0.113.7"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.IPSource, cfg.IgnorePrivateIPs = IPSourceInterface, tc.ignorePrivate
			addresses := make([]netip.Addr, len(tc.addresses))
			for i, value := range tc.addresses {
				addresses[i] = netip.MustParseAddr(value)
			}
			for range 2 {
				got, err := selectInterfaceAddress(addresses, cfg, tc.v6)
				if got != tc.want || (err != nil) != (tc.want == "") {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
				for i, j := 0, len(addresses)-1; i < j; i, j = i+1, j-1 {
					addresses[i], addresses[j] = addresses[j], addresses[i]
				}
			}
		})
	}
}

func TestInterfaceDiscoveryRetriesWithoutPublicAPI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPSource = IPSourceInterface
	attempts := 0
	client := &Client{InterfaceIPs: func() ([]netip.Addr, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("temporary")
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}}
	got, err := client.LookupAddress(context.Background(), cfg, false)
	if err != nil || got != "203.0.113.7" || attempts != 3 {
		t.Fatalf("discovery failed: %q, %v, attempts %d", got, err, attempts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.LookupAddress(ctx, cfg, false); err == nil || attempts != 3 {
		t.Fatal("canceled lookup still enumerated interfaces")
	}
}

func TestLegacyDDNSConfigAndSourceValidation(t *testing.T) {
	cfg := DefaultConfig()
	if err := json.Unmarshal([]byte(`{"provider":"cloudflare","ipv4":true}`), &cfg); err != nil || cfg.IPSource != IPSourceAPI || !cfg.IgnorePrivateIPs {
		t.Fatal("legacy DDNS defaults changed", err)
	}
	cfg.IPSource = "unknown"
	if cfg.Normalize() == nil {
		t.Fatal("invalid IP source accepted")
	}
	cfg.IPSource = IPSourceInterface
	cfg.IPv4URL = "not-used-in-interface-mode"
	if err := cfg.Normalize(); err != nil {
		t.Fatal("interface source still requires API URLs", err)
	}
	cfg.IPSource = IPSourceAPI
	if cfg.Normalize() == nil {
		t.Fatal("API source failed to validate its URL")
	}
}
