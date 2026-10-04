package agent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

type proxyAddresses struct{ src, dst netip.AddrPort }

func directAddresses(c net.Conn) (proxyAddresses, error) {
	src, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil {
		return proxyAddresses{}, e
	}
	dst, e := netip.ParseAddrPort(c.LocalAddr().String())
	return proxyAddresses{src, dst}, e
}
func readProxy(c net.Conn, mode string, trusted []string) (net.Conn, proxyAddresses, error) {
	a, e := directAddresses(c)
	if e != nil {
		return c, a, e
	}
	if mode == "" || mode == "off" {
		return c, a, nil
	}
	allowed := false
	for _, s := range trusted {
		p, err := netip.ParsePrefix(s)
		if err == nil && p.Contains(a.src.Addr().Unmap()) {
			allowed = true
			break
		}
	}
	if !allowed {
		return c, a, errors.New("untrusted proxy source")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	b := bufio.NewReader(c)
	wrapped := &bufferedConn{Conn: c, reader: b}
	switch mode {
	case "v1":
		line := []byte{}
		for len(line) < 108 {
			v, err := b.ReadByte()
			if err != nil {
				return c, a, err
			}
			line = append(line, v)
			if v == '\n' {
				break
			}
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return c, a, errors.New("invalid proxy v1 header")
		}
		parts := strings.Split(string(line[:len(line)-2]), " ")
		if len(parts) < 2 || parts[0] != "PROXY" {
			return c, a, errors.New("proxy v1 required")
		}
		if parts[1] == "UNKNOWN" {
			return wrapped, a, nil
		}
		if len(parts) != 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
			return c, a, errors.New("invalid proxy address family")
		}
		src, se := netip.ParseAddr(parts[2])
		dst, de := netip.ParseAddr(parts[3])
		sp, spe := strconv.ParseUint(parts[4], 10, 16)
		dp, dpe := strconv.ParseUint(parts[5], 10, 16)
		if se != nil || de != nil || spe != nil || dpe != nil || src.Is4() != dst.Is4() || src.Is4() != (parts[1] == "TCP4") {
			return c, a, errors.New("invalid proxy addresses")
		}
		a = proxyAddresses{netip.AddrPortFrom(src, uint16(sp)), netip.AddrPortFrom(dst, uint16(dp))}
	case "v2":
		h := make([]byte, 16)
		if _, e = io.ReadFull(b, h); e != nil {
			return c, a, e
		}
		if !bytes.Equal(h[:12], proxySignature) || h[12]>>4 != 2 || h[12]&15 > 1 {
			return c, a, errors.New("invalid proxy v2 header")
		}
		n := int(binary.BigEndian.Uint16(h[14:]))
		if n > 4096 {
			return c, a, errors.New("proxy v2 header exceeds 4096 bytes")
		}
		payload := make([]byte, n)
		if _, e = io.ReadFull(b, payload); e != nil {
			return c, a, e
		}
		if h[12]&15 == 0 {
			return wrapped, a, nil
		}
		switch h[13] {
		case 0x11:
			if n < 12 {
				return c, a, io.ErrUnexpectedEOF
			}
			a = proxyAddresses{netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[:4])), binary.BigEndian.Uint16(payload[8:10])), netip.AddrPortFrom(netip.AddrFrom4([4]byte(payload[4:8])), binary.BigEndian.Uint16(payload[10:12]))}
		case 0x21:
			if n < 36 {
				return c, a, io.ErrUnexpectedEOF
			}
			a = proxyAddresses{netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[:16])), binary.BigEndian.Uint16(payload[32:34])), netip.AddrPortFrom(netip.AddrFrom16([16]byte(payload[16:32])), binary.BigEndian.Uint16(payload[34:36]))}
		case 0x00:
			return wrapped, a, nil
		default:
			return c, a, errors.New("unsupported proxy v2 transport")
		}
	default:
		return c, a, errors.New("invalid proxy mode")
	}
	return wrapped, a, nil
}
func writeProxy(c net.Conn, mode string, a proxyAddresses) error {
	if mode == "" || mode == "off" {
		return nil
	}
	src, dst := a.src.Addr().Unmap(), a.dst.Addr().Unmap()
	if src.Is4() != dst.Is4() {
		return errors.New("mixed proxy address families")
	}
	var data []byte
	if mode == "v1" {
		family := "TCP6"
		if src.Is4() {
			family = "TCP4"
		}
		data = []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, src, dst, a.src.Port(), a.dst.Port()))
	} else if mode == "v2" {
		data = append([]byte{}, proxySignature...)
		family := byte(0x21)
		length := 36
		if src.Is4() {
			family = 0x11
			length = 12
		}
		data = append(data, 0x21, family, 0, byte(length))
		data = append(data, src.AsSlice()...)
		data = append(data, dst.AsSlice()...)
		data = binary.BigEndian.AppendUint16(data, a.src.Port())
		data = binary.BigEndian.AppendUint16(data, a.dst.Port())
	} else {
		return errors.New("invalid proxy mode")
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	n, e := c.Write(data)
	_ = c.SetWriteDeadline(time.Time{})
	if e == nil && n != len(data) {
		e = io.ErrShortWrite
	}
	return e
}
