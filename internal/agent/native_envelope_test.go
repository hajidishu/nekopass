package agent

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

func TestNativeEnvelopeHidesMetadataAndRejectsTamperingReflectionAndLegacy(t *testing.T) {
	key, err := tunnelcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cover, err := newNativeEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	left, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	var queued atomic.Int64
	p := newNativePeer(context.Background(), left, right.LocalAddr().(*net.UDPAddr), "fixture-envelope-link", [16]byte{7}, &queued, true)
	defer p.Close()
	p.envelope = cover
	var captured [][]byte
	for i := 0; i < 64; i++ {
		if err = p.send(nativeData, []byte("test")); err != nil {
			t.Fatal(err)
		}
		right.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1500)
		n, _, err := right.ReadFromUDP(b)
		if err != nil {
			t.Fatal(err)
		}
		captured = append(captured, bytes.Clone(b[:n]))
	}
	for _, wire := range captured {
		if len(wire) > 1200 || bytes.Equal(wire[:16], p.route[:]) || bytes.Contains(wire, p.id[:]) {
			t.Fatal("metadata remained clear or MTU exceeded")
		}
		plain, err := cover.open(wire, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, _, _, body, ok := decodeNative(plain, p.key, true); !ok || string(body) != "test" {
			t.Fatal("inner authentication changed")
		}
		if _, err = cover.open(wire, false); err == nil {
			t.Fatal("reflected envelope accepted")
		}
		if _, err = cover.open(plain, true); err == nil {
			t.Fatal("legacy plaintext envelope accepted")
		}
	}
	for i := range captured[0] {
		bad := bytes.Clone(captured[0])
		bad[i] ^= 1
		if _, err = cover.open(bad, true); err == nil {
			t.Fatal("tampered envelope accepted", i)
		}
	}
	for i := 1; i < len(captured); i++ {
		if bytes.Equal(captured[i][:24], captured[0][:24]) {
			t.Fatal("per-packet nonce repeated")
		}
	}
}

func TestNativeDTLSCapturedInitialSilentAfterCompletionAndListenerRestart(t *testing.T) {
	target := randomUDPEcho(t)
	e, h, c, r := muxFixture(t, "dtls_udp", target)
	proxy := newRandomUDPProxy(t, e.nativeUDP.conn.LocalAddr().(*net.UDPAddr))
	var captured []byte
	proxy.mu.Lock()
	proxy.request = func(wire []byte) [][]byte {
		if captured == nil {
			captured = bytes.Clone(wire)
		}
		return [][]byte{wire}
	}
	proxy.mu.Unlock()
	r.TunnelPort = int32(proxy.front.LocalAddr().(*net.UDPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var queued atomic.Int64
	conn, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
	if err != nil {
		t.Fatal(err)
	}
	muxExchange(t, conn, []byte("valid DTLS"), true)
	defer conn.Close()
	proxy.mu.Lock()
	wire := bytes.Clone(captured)
	proxy.mu.Unlock()
	if len(wire) == 0 {
		t.Fatal("no first flight captured")
	}
	assertSilent := func() {
		t.Helper()
		for i := 0; i < 3; i++ {
			probe, err := net.DialUDP("udp", nil, e.nativeUDP.conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			probe.SetDeadline(time.Now().Add(60 * time.Millisecond))
			probe.Write(wire)
			n, err := probe.Read(make([]byte, 1500))
			probe.Close()
			if err == nil || n != 0 {
				t.Fatal("captured DTLS first flight got a response", n, err)
			}
		}
	}
	assertSilent()
	c.Node.TunnelExitEnabled = false
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	c.Node.TunnelExitEnabled = true
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	assertSilent()
	old := e.nativeUDP
	next, _ := tunnelcrypto.GenerateKey()
	c.Node.Random.Key = next
	if err = e.Apply(c); err != nil {
		t.Fatal(err)
	}
	if e.nativeUDP == old {
		t.Fatal("header-key rotation reused old listener")
	}
	assertSilent()
	r.Random.Key = next
	r.TunnelPort = c.Node.TunnelListenPort
	h.Prune(nil)
	fresh, err := dialDatagramTunnel(ctx, ctx, r, target, h, &queued)
	if err != nil {
		t.Fatal("rotated key did not reconnect", err)
	}
	defer fresh.Close()
	muxExchange(t, fresh, []byte("rotated DTLS"), true)
}
