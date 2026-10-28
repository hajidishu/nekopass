package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

const randomUDPFrameSize = 15
const randomUDPOpen = 1
const randomUDPAck = 2
const randomUDPData = 3
const randomUDPClose = 4
const randomUDPPing = 5
const randomUDPPong = 6
const randomUDPReady = 1
const randomUDPTargetFailed = 2
const randomUDPDenied = 3
const randomUDPBusy = 4
const randomUDPClosed = 5
const maxRandomUDPFlows = 65536

type randomUDPAssociation struct {
	ctx           context.Context
	cancel        context.CancelFunc
	socket        *net.UDPConn
	remote        *net.UDPAddr
	crypto        *tunnelcrypto.DatagramSession
	linkKey       string
	queued        *atomic.Int64
	server        *randomUDPListener
	mu            sync.Mutex
	flows         map[uint64]*randomUDPFlow
	flowSequence  uint64
	opened        h2ServerSession
	onClose       func()
	onConfirmed   func()
	confirmed     atomic.Bool
	confirmedOnce sync.Once
	once          sync.Once
	lastReceive   atomic.Int64
	lastActivity  atomic.Int64
	pingMu        sync.Mutex
	ping          [8]byte
}
type randomUDPFlow struct {
	*nativePeer
	association    *randomUDPAssociation
	id             uint64
	message        atomic.Uint32
	remoteClosed   atomic.Bool
	remoteClosedAt time.Time
	ready          chan byte
	state          byte // guarded by association.mu
	closedAt       time.Time
	stopLifetime   func() bool
	once           sync.Once
}

func newRandomUDPAssociation(ctx context.Context, socket *net.UDPConn, remote *net.UDPAddr, c *tunnelcrypto.DatagramSession, link string, queued *atomic.Int64) *randomUDPAssociation {
	ctx, cancel := context.WithCancel(ctx)
	a := &randomUDPAssociation{ctx: ctx, cancel: cancel, socket: socket, remote: remote, crypto: c, linkKey: link, queued: queued, flows: map[uint64]*randomUDPFlow{}}
	a.lastReceive.Store(time.Now().UnixNano())
	a.lastActivity.Store(time.Now().UnixNano())
	return a
}
func (a *randomUDPAssociation) newFlowLocked(id uint64, lifetime context.Context) *randomUDPFlow {
	var nativeID [16]byte
	binary.BigEndian.PutUint64(nativeID[:8], id)
	p := newNativePeer(a.ctx, a.socket, a.remote, "", nativeID, a.queued, true)
	f := &randomUDPFlow{nativePeer: p, association: a, id: id, ready: make(chan byte, 1)}
	if lifetime != nil {
		f.stopLifetime = context.AfterFunc(lifetime, p.cancel)
	}
	a.flows[id] = f
	a.lastActivity.Store(time.Now().UnixNano())
	return f
}
func (a *randomUDPAssociation) send(kind byte, id uint64, message uint32, index, total byte, body []byte) error {
	if a.ctx.Err() != nil {
		return net.ErrClosed
	}
	frame := make([]byte, randomUDPFrameSize+len(body))
	frame[0] = kind
	binary.BigEndian.PutUint64(frame[1:9], id)
	binary.BigEndian.PutUint32(frame[9:13], message)
	frame[13] = index
	frame[14] = total
	copy(frame[15:], body)
	wire, err := a.crypto.Seal(frame)
	if err != nil {
		return err
	}
	_, err = a.socket.WriteToUDP(wire, a.remote)
	return err
}
func (a *randomUDPAssociation) control(kind byte, id uint64, body []byte) error {
	return a.send(kind, id, 0, 0, 1, body)
}
func (a *randomUDPAssociation) receive(packet tunnelcrypto.DatagramPacket) {
	if a.ctx.Err() != nil {
		return
	}
	plain, err := a.crypto.Open(packet)
	if err != nil || len(plain) < randomUDPFrameSize {
		return
	}
	kind, id, message, index, total := plain[0], binary.BigEndian.Uint64(plain[1:9]), binary.BigEndian.Uint32(plain[9:13]), int(plain[13]), int(plain[14])
	body := plain[15:]
	if kind < randomUDPOpen || kind > randomUDPPong || total == 0 || total > 60 || index >= total || len(body) > nativePartSize {
		return
	}
	if kind != randomUDPData && (message != 0 || index != 0 || total != 1) {
		return
	}
	a.lastReceive.Store(time.Now().UnixNano())
	if a.server != nil {
		a.confirmed.Store(true)
		a.confirmedOnce.Do(func() {
			if a.onConfirmed != nil {
				a.onConfirmed()
			}
		})
	}
	if kind == randomUDPPing || kind == randomUDPPong {
		if id != 0 || len(body) != 8 {
			return
		}
		if kind == randomUDPPing {
			_ = a.control(randomUDPPong, 0, body)
		} else {
			a.pingMu.Lock()
			if string(body) == string(a.ping[:]) {
				a.ping = [8]byte{}
			}
			a.pingMu.Unlock()
		}
		return
	}
	if id == 0 {
		return
	}
	if kind == randomUDPOpen {
		if a.server != nil {
			a.server.openFlow(a, id, body)
		}
		return
	}
	a.mu.Lock()
	f := a.flows[id]
	state := byte(0)
	if f != nil {
		state = f.state
	}
	a.mu.Unlock()
	if f == nil {
		return
	}
	switch kind {
	case randomUDPAck:
		if a.server == nil && len(body) == 1 && body[0] >= randomUDPReady && body[0] <= randomUDPClosed {
			a.mu.Lock()
			if f.state == 0 {
				f.state = body[0]
			}
			a.mu.Unlock()
			select {
			case f.ready <- body[0]:
			default:
			}
		}
	case randomUDPData:
		if message == 0 || state > randomUDPReady || a.server != nil && state != randomUDPReady {
			return
		}
		a.lastActivity.Store(time.Now().UnixNano())
		f.nativePeer.receive(packet.Sequence(), nativeData, message, index, total, body)
	case randomUDPClose:
		if len(body) == 0 {
			if state == 0 {
				f.Close()
			} else if !f.remoteClosed.Swap(true) {
				a.mu.Lock()
				f.remoteClosedAt = time.Now()
				a.mu.Unlock()
				f.nativePeer.receiveControl(nativeClose, nil)
			}
		}
	}
}
func (a *randomUDPAssociation) Close() {
	a.once.Do(func() {
		a.cancel()
		if a.server == nil {
			a.socket.Close()
		}
		a.confirmedOnce.Do(func() {
			if a.onConfirmed != nil {
				a.onConfirmed()
			}
		})
		a.mu.Lock()
		flows := make([]*randomUDPFlow, 0, len(a.flows))
		for _, f := range a.flows {
			flows = append(flows, f)
		}
		a.mu.Unlock()
		for _, f := range flows {
			f.Close()
		}
		if a.onClose != nil {
			a.onClose()
		}
	})
}
func (f *randomUDPFlow) Write(body []byte) (int, error) {
	if len(body) > maxDatagram {
		return 0, errors.New("encrypted UDP datagram too large")
	}
	f.nativePeer.mu.Lock()
	deadline := f.writeDeadline
	f.nativePeer.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, context.DeadlineExceeded
	}
	if f.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	message := f.message.Add(1)
	if message == 0 {
		message = f.message.Add(1)
	}
	total := max(1, (len(body)+nativePartSize-1)/nativePartSize)
	for i := 0; i < total; i++ {
		if f.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		part := body[min(len(body), i*nativePartSize):min(len(body), (i+1)*nativePartSize)]
		if err := f.association.send(randomUDPData, f.id, message, byte(i), byte(total), part); err != nil {
			return 0, err
		}
	}
	return len(body), nil
}
func (f *randomUDPFlow) Close() error {
	f.once.Do(func() {
		f.nativePeer.Close()
		if f.stopLifetime != nil {
			f.stopLifetime()
		}
		a := f.association
		a.mu.Lock()
		notify := f.state <= randomUDPReady
		if notify {
			f.state = randomUDPClosed
		}
		f.closedAt = time.Now()
		if a.server == nil {
			delete(a.flows, f.id)
		}
		a.mu.Unlock()
		if notify && a.ctx.Err() == nil {
			_ = a.control(randomUDPClose, f.id, nil)
		}
	})
	return nil
}
