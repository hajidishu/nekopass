package agent

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Models a DTLS Close that returns while another closer is still shutting down
// the packet transport. The wrapper must release its owned peer independently.
type pendingPacketClose struct{ net.Conn }

func (*pendingPacketClose) Close() error { return nil }

func TestDTLSDatagramCloseDrainsOwnedPacketTransport(t *testing.T) {
	var queued atomic.Int64
	peer := newNativePeer(context.Background(), nil, nil, "fixture-dtls-close", [16]byte{1}, &queued, true)
	defer peer.Close()
	peer.receiveControl(nativeAccepted, []byte("accepted"))
	peer.receive(1, nativeData, 1, 0, 2, []byte("partial record"))
	if queued.Load() == 0 {
		t.Fatal("fixture did not reserve receive memory")
	}
	conn := newDTLSDatagram(&pendingPacketClose{Conn: peer}, &queued, peer)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if peer.ctx.Err() == nil || queued.Load() != 0 {
		t.Fatal("DTLS close retained its packet transport or queued memory", queued.Load())
	}
	peer.receiveControl(nativeAccepted, []byte("late packet"))
	peer.receive(2, nativeData, 2, 0, 1, []byte("late payload"))
	if queued.Load() != 0 {
		t.Fatal("closed DTLS peer accepted more receive reservations")
	}
	if err := conn.Close(); err != nil || queued.Load() != 0 {
		t.Fatal("repeated DTLS close changed receive accounting", err, queued.Load())
	}
}

func TestNativePeerCloseSettlesConcurrentReceiveReservations(t *testing.T) {
	for round := 0; round < 30; round++ {
		var queued atomic.Int64
		peer := newNativePeer(context.Background(), nil, nil, "fixture-receive-close", [16]byte{1}, &queued, true)
		var receivers sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			receivers.Add(1)
			go func() { defer receivers.Done(); <-start; _, _ = peer.next() }()
		}
		for range 64 {
			peer.receiveControl(nativeAccepted, make([]byte, 64))
		}
		close(start)
		done := make(chan struct{})
		go func() { _ = peer.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("closing a peer blocked on its receivers")
		}
		if used := queued.Load(); used != 0 {
			t.Fatal("close returned with unfinished receive reservations", used)
		}
		receivers.Wait()
		if queued.Load() != 0 {
			t.Fatal("late receiver changed closed-peer accounting", queued.Load())
		}
	}
}
