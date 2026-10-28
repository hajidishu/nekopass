package agent

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Context 0 carries unmodified UDP payloads in both QUIC DATAGRAM frames and
// standard DATAGRAM capsules (RFC 9297 / RFC 9298). Large packets use capsules
// instead of a proprietary fragmentation protocol.
type h3Datagram struct {
	*nativePeer
	conn *h3StreamConn
	wg   sync.WaitGroup
	once sync.Once
}

func newH3Datagram(conn *h3StreamConn, queued *atomic.Int64) *h3Datagram {
	p := newNativePeer(conn.ctx, nil, nil, "", [16]byte{}, queued, true)
	d := &h3Datagram{nativePeer: p, conn: conn}
	d.wg.Add(2)
	go func() {
		defer d.wg.Done()
		defer d.fail()
		for {
			wire, err := conn.ReceiveDatagram(p.ctx)
			if err != nil {
				return
			}
			id, n, err := quicvarint.Parse(wire)
			if err == nil && id == 0 && len(wire[n:]) <= maxDatagram {
				p.receiveControl(nativeData, wire[n:])
			}
		}
	}()
	go func() {
		defer d.wg.Done()
		defer d.fail()
		parser := http3.NewCapsuleParser(conn)
		unknownBytes, unknownCount := int64(64<<10), 0
		for {
			kind, body, err := parser.Next()
			if err != nil {
				return
			}
			size := body.Remaining()
			if kind != 0 {
				unknownCount++
				unknownBytes -= size
				if unknownCount > 256 || unknownBytes < 0 {
					return
				}
				if err = body.Discard(); err != nil {
					return
				}
				continue
			}
			if size < 1 || size > maxDatagram+8 {
				return
			}
			wire, err := io.ReadAll(body)
			if err != nil {
				return
			}
			id, n, err := quicvarint.Parse(wire)
			if err != nil {
				return
			}
			if id == 0 {
				if len(wire[n:]) > maxDatagram {
					return
				}
				p.receiveControl(nativeData, wire[n:])
			} else {
				unknownCount++
				unknownBytes -= size
				if unknownCount > 256 || unknownBytes < 0 {
					return
				}
			}
		}
	}()
	return d
}
func (d *h3Datagram) fail()                { d.once.Do(func() { d.nativePeer.Close(); d.conn.Close() }) }
func (d *h3Datagram) Close() error         { d.fail(); d.wg.Wait(); return nil }
func (d *h3Datagram) LocalAddr() net.Addr  { return d.conn.LocalAddr() }
func (d *h3Datagram) RemoteAddr() net.Addr { return d.conn.RemoteAddr() }
func (d *h3Datagram) SetWriteDeadline(t time.Time) error {
	d.nativePeer.SetWriteDeadline(t)
	return d.conn.SetWriteDeadline(t)
}
func (d *h3Datagram) SetDeadline(t time.Time) error {
	d.nativePeer.SetReadDeadline(t)
	return d.SetWriteDeadline(t)
}
func (d *h3Datagram) Write(body []byte) (int, error) {
	if len(body) > maxDatagram {
		return 0, errors.New("HTTP/3 datagram too large")
	}
	d.nativePeer.mu.Lock()
	deadline := d.writeDeadline
	d.nativePeer.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if d.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	if len(body) <= 900 {
		err := d.conn.SendDatagram(append([]byte{0}, body...))
		if err == nil {
			return len(body), nil
		}
		var large *quic.DatagramTooLargeError
		if !errors.As(err, &large) {
			return 0, err
		}
	}
	// A DATAGRAM capsule is one atomic stream write. It preserves the original
	// packet boundary and works even when the packet exceeds the QUIC path MTU.
	wire := quicvarint.Append(nil, 0)
	wire = quicvarint.Append(wire, uint64(len(body)+1))
	wire = append(wire, 0)
	wire = append(wire, body...)
	_, err := d.conn.Write(wire)
	if err != nil {
		return 0, err
	}
	return len(body), nil
}
