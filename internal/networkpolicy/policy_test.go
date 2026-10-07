package networkpolicy

import (
	"net/netip"
	"testing"
)

func TestDefaultSpecialTargetsAndMappedIPv4(t *testing.T) {
	p, err := Compile(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"127.0.0.1", "::1", "10.0.0.1", "172.31.4.66", "192.168.1.1", "fd00::1", "169.254.169.254", "100.100.100.200", "fe80::1%eth0", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "198.18.0.1", "192.0.2.1", "2001:db8::1", "64:ff9b::a00:1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"} {
		if !p.Denied(netip.MustParseAddr(value)) {
			t.Errorf("special target allowed: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if p.Denied(netip.MustParseAddr(value)) {
			t.Errorf("public target denied: %s", value)
		}
	}
}

func TestAdministratorOverridesAndCanonicalCIDRs(t *testing.T) {
	values, err := Normalize([]string{" ::ffff:192.168.1.33/120 ", "192.168.1.7/24"}, 256)
	if err != nil || len(values) != 1 || values[0] != "192.168.1.0/24" {
		t.Fatal(values, err)
	}
	for _, value := range []string{"not-cidr", "127.0.0.1", "::ffff:0.0.0.0/80"} {
		if _, err := Compile([]string{value}); err == nil {
			t.Fatal("invalid prefix accepted", value)
		}
	}
	p, _ := Compile([]string{})
	if p.Denied(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("explicit empty administrator list ignored")
	}
}
