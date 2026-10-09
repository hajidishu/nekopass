package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeUDPRejectsReflectedAndLegacyPackets(t *testing.T) {
	for _, outgoing := range []bool{true, false} {
		t.Run(map[bool]string{true: "ingress", false: "exit"}[outgoing], func(t *testing.T) {
			sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			var queued atomic.Int64
			id, err := randomNativeID()
			if err != nil {
				t.Fatal(err)
			}
			key := "fixture-native-direction"
			peer := newNativePeer(context.Background(), socket, sink.LocalAddr().(*net.UDPAddr), key, id, &queued, outgoing)
			defer peer.Close()
			if _, err = peer.Write([]byte("direction-bound payload")); err != nil {
				t.Fatal(err)
			}
			wire := make([]byte, 1500)
			sink.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := sink.ReadFromUDP(wire)
			if err != nil {
				t.Fatal(err)
			}
			wire = wire[:n]
			if _, _, _, _, _, _, _, _, ok := decodeNative(wire, key, outgoing); !ok {
				t.Fatal("legitimate peer rejected packet")
			}
			if _, _, _, _, _, _, _, _, ok := decodeNative(wire, key, !outgoing); ok {
				t.Fatal("sender accepted reflected packet")
			}
			legacy := append([]byte{}, wire...)
			mac := hmac.New(sha256.New, []byte(key))
			mac.Write(legacy[:len(legacy)-nativeMAC])
			copy(legacy[len(legacy)-nativeMAC:], mac.Sum(nil))
			if _, _, _, _, _, _, _, _, ok := decodeNative(legacy, key, outgoing); ok {
				t.Fatal("legacy directionless authentication accepted")
			}
		})
	}
}

func TestNativeUDPSessionsShareReceiveBudget(t *testing.T) {
	var queued atomic.Int64
	var peers []*nativePeer
	body := make([]byte, nativePartSize)
	for i := 0; i < 9; i++ {
		peer := newNativePeer(context.Background(), nil, nil, "fixture-budget", [16]byte{byte(i + 1)}, &queued, true)
		peers = append(peers, peer)
		t.Cleanup(func() { peer.Close() })
		seq := uint64(0)
		for msg := 1; msg <= 64; msg++ {
			total := (maxDatagram + nativePartSize - 1) / nativePartSize
			for part := 0; part < total; part++ {
				seq++
				size := min(nativePartSize, maxDatagram-part*nativePartSize)
				peer.receive(seq, nativeData, uint32(msg), part, total, body[:size])
				if used := queued.Load(); used < 0 || used > maxQueuedUDPBytes {
					t.Fatalf("shared budget exceeded: %d", used)
				}
			}
		}
	}
	if queued.Load() == 0 {
		t.Fatal("test did not enqueue packets")
	}
	var delivered int
	for _, peer := range peers {
		delivered += len(peer.queue)
		peer.Close()
		peer.Close()
	}
	if delivered >= 9*64 || queued.Load() != 0 {
		t.Fatal("budget did not bound packets or close leaked reservations", delivered, queued.Load())
	}
}

func TestNativeUDPControlQueueReleasesSharedBudget(t *testing.T) {
	var queued atomic.Int64
	peer := newNativePeer(context.Background(), nil, nil, "fixture-control", [16]byte{1}, &queued, true)
	defer peer.Close()
	peer.receiveControl(nativeChallenge, make([]byte, 40))
	if queued.Load() != 40 {
		t.Fatal("control packet not charged")
	}
	if _, err := peer.next(); err != nil || queued.Load() != 0 {
		t.Fatal("control dequeue leaked reservation", err)
	}
	peer.receiveControl(nativeChallenge, make([]byte, 40))
	peer.Close()
	peer.receiveControl(nativeChallenge, make([]byte, 40))
	if queued.Load() != 0 {
		t.Fatal("close leaked reservation or accepted new packet")
	}
}
