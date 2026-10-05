package agent

import (
	"io"
	"net"
	"net/netip"
	"testing"
)

func TestAutoProxyReceivesBothVersionsAndPreservesPayload(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, host := range []string{"192.0.2.3", "2001:db8::3"} {
			t.Run(version+host, func(t *testing.T) {
				source := netip.MustParseAddr(host)
				want := proxyAddresses{netip.AddrPortFrom(source, 1234), netip.AddrPortFrom(source, 443)}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				done := make(chan error, 1)
				go func() {
					err := writeProxy(a, version, want)
					if err == nil {
						_, err = a.Write([]byte("payload"))
					}
					a.Close()
					done <- err
				}()
				conn, got, err := readProxy(addressedConn{b}, "auto", []string{"127.0.0.1/32"})
				if err != nil || got != want {
					t.Fatalf("got %+v, error %v", got, err)
				}
				payload, err := io.ReadAll(conn)
				if err != nil || string(payload) != "payload" {
					t.Fatalf("payload %q, error %v", payload, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAutoProxyRequiresTrustedSourceAndValidHeader(t *testing.T) {
	for _, header := range []string{"", "GET / HTTP/1.1\r\n", "PROXY TCP4 spoofed 192.0.2.1 20 30\r\n", "\r\ninvalid-v2-header"} {
		a, b := net.Pipe()
		go func() { defer a.Close(); _, _ = a.Write([]byte(header)) }()
		if _, _, err := readProxy(addressedConn{b}, "auto", []string{"127.0.0.1/32"}); err == nil {
			t.Fatal("accepted missing or malformed header")
		}
		b.Close()
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := readProxy(addressedConn{b}, "auto", []string{"192.0.2.0/24"}); err == nil {
		t.Fatal("accepted untrusted source")
	}
}
