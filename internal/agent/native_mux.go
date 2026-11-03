package agent

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"github.com/quic-go/quic-go/brutal"
)

func (a *randomUDPAssociation) maxFragmentCount() int {
	if a.datagrams != nil {
		return 80
	}
	return 61
}
func (a *randomUDPAssociation) flowLimit() int {
	if a.muxConfig.GetEnabled() {
		return tunnel.MuxSettings(a.muxConfig).MaxStreams
	}
	return maxRandomUDPFlows
}

// Caller holds association.mu. Closed tombstones retain replay protection,
// but must not occupy a logical connection slot.
func (a *randomUDPAssociation) activeFlowsLocked() int {
	n := 0
	for _, f := range a.flows {
		if f.closedAt.IsZero() {
			n++
		}
	}
	return n
}

func dialNativeMuxAssociation(ctx, lifetime context.Context, r *pb.Rule, targetQueued *atomic.Int64, budget *brutal.Budget) (*randomUDPAssociation, error) {
	c, err := dialNativeDatagram(ctx, lifetime, r, tunnelHealthTarget, targetQueued, budget)
	if err != nil {
		return nil, err
	}
	a := newRandomUDPAssociation(lifetime, nil, nil, nil, r.TunnelToken, targetQueued)
	a.datagrams = c
	a.nativeIngress = r.IngressNodeId
	a.brutal, err = newDatagramBrutal(r.Congestion, budget)
	if err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}
func (a *randomUDPAssociation) readDatagrams() {
	defer a.Close()
	stop := context.AfterFunc(a.ctx, func() { a.datagrams.Close() })
	defer stop()
	buf := make([]byte, maxDatagram)
	var sequence uint64
	for {
		n, err := a.datagrams.Read(buf)
		if err != nil {
			return
		}
		sequence++
		a.receiveFrame(buf[:n], sequence)
	}
}

// Best-effort bounded notification frees the remote carrier slot promptly.
// Timeout-based reclamation remains necessary because UDP may lose all copies.
func (a *randomUDPAssociation) notifyMuxClose() {
	if !a.muxConfig.GetEnabled() || a.ctx.Err() != nil {
		return
	}
	frame := make([]byte, randomUDPFrameSize)
	frame[0] = randomUDPClose
	frame[14] = 1
	if a.datagrams != nil {
		if !a.sendMu.TryLock() {
			return
		}
		defer a.sendMu.Unlock()
		a.datagrams.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		for range 3 {
			if _, err := a.datagrams.Write(frame); err != nil {
				return
			}
		}
	} else if a.crypto != nil && a.socket != nil && a.server == nil {
		a.socket.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		for range 3 {
			wire, err := a.crypto.Seal(frame)
			if err != nil {
				return
			}
			if _, err = a.socket.WriteToUDP(wire, a.remote); err != nil {
				return
			}
		}
	}
}
func (e *Engine) runNativeMux(l *nativeUDPListener, peer *nativePeer, open nativeGateOpen, c net.Conn) {
	a := newRandomUDPAssociation(peer.ctx, nil, nil, nil, peer.key, &e.udpQueued)
	a.datagrams = c
	a.nativeIngress = open.Ingress
	a.muxConfig = l.node.Mux
	policy := e.tunnelPolicy.Load()
	if policy == nil {
		a.Close()
		return
	}
	var err error
	a.brutal, err = newDatagramBrutal(policy.congestion[open.Ingress], e.brutalBudget)
	if err != nil {
		a.Close()
		return
	}
	a.server = &randomUDPListener{e: e, node: l.node, ctx: l.ctx, dials: l.muxDials}
	defer a.Close()
	done := make(chan struct{})
	go func() { defer close(done); a.maintainClient() }()
	a.readDatagrams()
	<-done
}

func (f *randomUDPFlow) LocalAddr() net.Addr {
	if f.association.datagrams != nil {
		return f.association.datagrams.LocalAddr()
	}
	return f.nativePeer.LocalAddr()
}
func (f *randomUDPFlow) RemoteAddr() net.Addr {
	if f.association.datagrams != nil {
		return f.association.datagrams.RemoteAddr()
	}
	return f.nativePeer.RemoteAddr()
}
