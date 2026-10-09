package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"google.golang.org/protobuf/proto"
)

type framedDatagram struct {
	net.Conn
	readMu, writeMu sync.Mutex
}

func (c *framedDatagram) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var h [4]byte
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n > maxDatagram || n > len(p) {
		return 0, errors.New("invalid datagram length")
	}
	return io.ReadFull(c.Conn, p[:n])
}
func (c *framedDatagram) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) > maxDatagram {
		return 0, errors.New("datagram too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := io.Copy(c.Conn, bytes.NewReader(h[:])); err != nil {
		return 0, err
	}
	n, err := io.Copy(c.Conn, bytes.NewReader(p))
	return int(n), err
}
func dialDatagramTunnel(dialCtx, lifetime context.Context, r *pb.Rule, target string, h2 *h2Transport) (net.Conn, error) {
	r = proto.Clone(r).(*pb.Rule)
	r.Protocol = "udp"
	if tunnel.UDP(r.TunnelProtocol) {
		return dialNativeDatagram(dialCtx, lifetime, r, target)
	}
	if tunnel.H2(r.TunnelProtocol) {
		if h2 == nil {
			return nil, errors.New("HTTP/2 transport unavailable")
		}
		c, err := h2.Dial(dialCtx, lifetime, r, target)
		if err != nil {
			return nil, err
		}
		return &framedDatagram{Conn: c}, nil
	}
	return dialRawDatagramTunnel(dialCtx, r, target)
}
