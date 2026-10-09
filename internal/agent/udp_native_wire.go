package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const nativeHeader = 47
const nativeMAC = 32
const nativePartSize = 1100
const nativeOpen = 1
const nativeChallenge = 2
const nativeAccepted = 3
const nativeData = 4
const nativeClose = 5

type nativeMessage struct {
	kind    byte
	payload []byte
}
type nativePeer struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	conn                        *net.UDPConn
	remote                      *net.UDPAddr
	route                       [16]byte
	id                          [16]byte
	key                         string
	sequence                    atomic.Uint64
	message                     atomic.Uint32
	replay                      h2ServerSession
	queue                       chan nativeMessage
	parts                       map[uint32]*udpParts
	queued                      *atomic.Int64
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	deadlineChanged             chan struct{}
}
type udpParts struct {
	fragments [][]byte
	seen      int
	bytes     int
	expires   time.Time
}

func nativeRouteTag(key string) [16]byte {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("native-udp-route"))
	var result [16]byte
	copy(result[:], m.Sum(nil))
	return result
}

func newNativePeer(ctx context.Context, conn *net.UDPConn, remote *net.UDPAddr, key string, id [16]byte, queued *atomic.Int64) *nativePeer {
	ctx, cancel := context.WithCancel(ctx)
	return &nativePeer{ctx: ctx, cancel: cancel, conn: conn, remote: remote, key: key, id: id, route: nativeRouteTag(key), queue: make(chan nativeMessage, 64), parts: map[uint32]*udpParts{}, queued: queued, deadlineChanged: make(chan struct{}, 1)}
}
func (p *nativePeer) send(kind byte, body []byte) error {
	if len(body) > maxDatagram {
		return errors.New("native datagram too large")
	}
	p.mu.Lock()
	deadline := p.writeDeadline
	p.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return context.DeadlineExceeded
	}
	total := max(1, (len(body)+nativePartSize-1)/nativePartSize)
	msg := p.message.Add(1)
	for part := 0; part < total; part++ {
		if p.ctx.Err() != nil {
			return net.ErrClosed
		}
		chunk := body[min(len(body), part*nativePartSize):min(len(body), (part+1)*nativePartSize)]
		wire := make([]byte, nativeHeader+len(chunk)+nativeMAC)
		copy(wire[:16], p.route[:])
		copy(wire[16:32], p.id[:])
		binary.BigEndian.PutUint64(wire[32:40], p.sequence.Add(1))
		wire[40] = kind
		binary.BigEndian.PutUint32(wire[41:45], msg)
		wire[45] = byte(part)
		wire[46] = byte(total)
		copy(wire[nativeHeader:], chunk)
		mac := hmac.New(sha256.New, []byte(p.key))
		mac.Write(wire[:len(wire)-nativeMAC])
		copy(wire[len(wire)-nativeMAC:], mac.Sum(nil))
		if _, err := p.conn.WriteToUDP(wire, p.remote); err != nil {
			return err
		}
	}
	return nil
}
func decodeNative(wire []byte, key string) (route, id [16]byte, seq uint64, kind byte, msg uint32, index, total int, body []byte, ok bool) {
	if len(wire) < nativeHeader+nativeMAC || len(wire) > nativeHeader+nativePartSize+nativeMAC {
		return
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(wire[:len(wire)-nativeMAC])
	if !hmac.Equal(mac.Sum(nil), wire[len(wire)-nativeMAC:]) {
		return
	}
	copy(route[:], wire[:16])
	copy(id[:], wire[16:32])
	if route != nativeRouteTag(key) {
		return
	}
	seq = binary.BigEndian.Uint64(wire[32:40])
	kind = wire[40]
	msg = binary.BigEndian.Uint32(wire[41:45])
	index, total = int(wire[45]), int(wire[46])
	body = wire[nativeHeader : len(wire)-nativeMAC]
	ok = seq != 0 && total > 0 && total <= 60 && index < total && kind >= nativeOpen && kind <= nativeClose
	return
}
func (p *nativePeer) receive(seq uint64, kind byte, msg uint32, index, total int, body []byte) {
	if p.ctx.Err() != nil || !p.replay.takeSequence(seq) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		return
	}
	now := time.Now()
	for id, parts := range p.parts {
		if parts.expires.Before(now) {
			p.queued.Add(-int64(parts.bytes))
			delete(p.parts, id)
		}
	}
	if kind != nativeData {
		if total != 1 {
			return
		}
		select {
		case p.queue <- nativeMessage{kind: kind, payload: append([]byte{}, body...)}:
		default:
		}
		return
	}
	parts := p.parts[msg]
	if parts == nil {
		if len(p.parts) >= 8 {
			return
		}
		parts = &udpParts{fragments: make([][]byte, total), expires: now.Add(3 * time.Second)}
		p.parts[msg] = parts
	}
	if len(parts.fragments) != total || parts.fragments[index] != nil || parts.bytes+len(body) > maxDatagram {
		return
	}
	if p.queued.Add(int64(len(body))) > maxQueuedUDPBytes {
		p.queued.Add(-int64(len(body)))
		return
	}
	parts.fragments[index] = append([]byte{}, body...)
	parts.bytes += len(body)
	parts.seen++
	if parts.seen == total {
		payload := make([]byte, 0, parts.bytes)
		for _, part := range parts.fragments {
			payload = append(payload, part...)
		}
		delete(p.parts, msg)
		select {
		case p.queue <- nativeMessage{kind: nativeData, payload: payload}:
		default:
			p.queued.Add(-int64(parts.bytes))
		}
	}
}
func (p *nativePeer) next() (nativeMessage, error) {
	for {
		p.mu.Lock()
		deadline := p.readDeadline
		p.mu.Unlock()
		var timer *time.Timer
		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerCh = timer.C
		}
		select {
		case <-p.ctx.Done():
			if timer!=nil{timer.Stop()}
			return nativeMessage{}, net.ErrClosed
		case <-timerCh:
			return nativeMessage{}, context.DeadlineExceeded
		case <-p.deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case m := <-p.queue:
			if timer!=nil{timer.Stop()}
			if m.kind == nativeData {
				p.queued.Add(-int64(len(m.payload)))
			}
			return m, nil
		}
	}
}
func (p *nativePeer) Read(b []byte) (int, error) {
	for {
		m, err := p.next()
		if err != nil {
			return 0, err
		}
		if m.kind == nativeClose {
			return 0, net.ErrClosed
		}
		if m.kind != nativeData {
			continue
		}
		if len(m.payload) > len(b) {
			return 0, errors.New("datagram buffer too small")
		}
		return copy(b, m.payload), nil
	}
}
func (p *nativePeer) Write(b []byte) (int, error) {
	if err := p.send(nativeData, b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *nativePeer) Close() error {
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, parts := range p.parts {
		p.queued.Add(-int64(parts.bytes))
	}
	p.parts = map[uint32]*udpParts{}
	for {
		select {
		case m := <-p.queue:
			if m.kind == nativeData {
				p.queued.Add(-int64(len(m.payload)))
			}
		default:
			return nil
		}
	}
}
func (p *nativePeer) LocalAddr() net.Addr  { return p.conn.LocalAddr() }
func (p *nativePeer) RemoteAddr() net.Addr { return p.remote }
func (p *nativePeer) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.writeDeadline = t
	p.mu.Unlock()
	select {
	case p.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}
func (p *nativePeer) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	select {
	case p.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}
func (p *nativePeer) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	return nil
}

type packetAdapter struct{ net.Conn }

func (c *packetAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}
func (c *packetAdapter) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func randomNativeID() (id [16]byte, err error) { _, err = rand.Read(id[:]); return }
