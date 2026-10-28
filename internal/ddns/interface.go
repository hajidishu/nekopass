package ddns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// LookupAddress preserves the bounded retries for both discovery sources.
func (c *Client) LookupAddress(ctx context.Context, cfg Config, v6 bool) (string, error) {
	if cfg.IPSource != IPSourceInterface {
		source := cfg.IPv4URL
		if v6 {
			source = cfg.IPv6URL
		}
		return c.AddressWithRetry(ctx, source, v6)
	}
	return addressWithRetry(ctx, func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		lookup := c.InterfaceIPs
		if lookup == nil {
			lookup = interfaceAddresses
		}
		addresses, err := lookup()
		if err != nil {
			return "", errors.New("无法读取网卡 IP 地址")
		}
		return selectInterfaceAddress(addresses, cfg, v6)
	})
}

func interfaceAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch address := address.(type) {
			case *net.IPNet:
				ip = address.IP
			case *net.IPAddr:
				ip = address.IP
			}
			if value, ok := netip.AddrFromSlice(ip); ok {
				result = append(result, value.Unmap())
			}
		}
	}
	return result, nil
}

func selectInterfaceAddress(addresses []netip.Addr, cfg Config, v6 bool) (string, error) {
	var best netip.Addr
	bestRank := 3
	for _, address := range addresses {
		address = address.Unmap()
		if !cfg.AllowsAddress(address, v6) {
			continue
		}
		rank := 0
		if isLocalAddress(address) {
			rank = 1
		}
		if address.IsLoopback() {
			rank = 2
		}
		// Stable ordering prevents record changes caused by interface enumeration.
		if !best.IsValid() || rank < bestRank || rank == bestRank && address.Compare(best) < 0 {
			best, bestRank = address, rank
		}
	}
	if best.IsValid() {
		return best.String(), nil
	}
	family := "IPv4"
	if v6 {
		family = "IPv6"
	}
	return "", fmt.Errorf("网卡中未找到符合条件的 %s 地址", family)
}
