// Package networkpolicy applies administrator-defined CIDRs to final targets.
package networkpolicy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Defaults block local, private, metadata, translation and special-use targets.
// Explicit administrator edits, including an empty list, replace these defaults.
func Defaults() []string {
	return []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	}
}

type Policy struct{ prefixes []netip.Prefix }

func Normalize(values []string, limit int) ([]string, error) {
	if len(values) > limit {
		return nil, fmt.Errorf("CIDR 网段最多 %d 个", limit)
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("无效 CIDR 网段：%s", value)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("IPv4 映射网段前缀不能小于 96：%s", value)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		canonical := p.Masked().String()
		if !seen[canonical] {
			result = append(result, canonical)
			seen[canonical] = true
		}
	}
	return result, nil
}

func Compile(values []string) (*Policy, error) {
	values, err := Normalize(values, 256)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	for _, value := range values {
		prefix, _ := netip.ParsePrefix(value)
		p.prefixes = append(p.prefixes, prefix)
	}
	return p, nil
}

func (p *Policy) Denied(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap().WithZone("")
	if p == nil {
		return false
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// CheckResolved is used from net.Dialer's ControlContext: address is the
// numeric endpoint selected by the resolver, immediately before connect.
func (p *Policy) CheckResolved(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid resolved target")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || p.Denied(ip) {
		return fmt.Errorf("target rejected by administrator network policy")
	}
	return nil
}
