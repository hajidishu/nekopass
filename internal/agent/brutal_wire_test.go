package agent

import (
	"context"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
)

type brutalWireTestConn struct {
	muxWriteCapture
	wire       uint64
	controller *datagramBrutal
	before     time.Time
}

func (c *brutalWireTestConn) wireBytesSent() uint64 { return c.wire }
func (c *brutalWireTestConn) Write(p []byte) (int, error) {
	// One 891-byte DTLS Mux frame: 8-byte fragmentation header, 37-byte
	// AES-GCM DTLS overhead, and 119-byte authenticated native envelope.
	c.wire += uint64(len(p) + 8 + 37 + nativeHeader + nativeMAC + nativeEnvelopeOverhead)
	if p[0] == randomUDPData {
		c.controller.controller.Sent(time.Now().Add(time.Second), 0)
		c.before = c.controller.controller.Next(time.Now())
	}
	return c.muxWriteCapture.Write(p)
}

func TestNativeMuxBrutalReconcilesActualWireOverheadWithoutBillingIt(t *testing.T) {
	const rate = 1250000
	b, err := newDatagramBrutal(&pb.TunnelCongestion{Brutal: true, SendBps: rate, ReceiveBps: rate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := &brutalWireTestConn{controller: b}
	a := newRandomUDPAssociation(context.Background(), nil, nil, nil, "", nil)
	defer a.Close()
	a.datagrams = wire
	a.brutal = b
	if err := a.send(randomUDPData, 1, 1, 0, 1, make([]byte, 860)); err != nil {
		t.Fatal(err)
	}
	if wire.wire != 1055 {
		t.Fatal("test did not include complete DTLS/native envelope", wire.wire)
	}
	delta := b.controller.Next(time.Now()).Sub(wire.before)
	if delta != time.Duration(float64(68)*float64(time.Second)/rate) {
		t.Fatal("unreserved transport bytes not reconciled", delta)
	}
	if b.sent.Load() != 1 {
		t.Fatal("transport overhead changed application packet feedback")
	}
	before := b.controller.Next(time.Now())
	if err := a.control(randomUDPPing, 0, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if !b.controller.Next(time.Now()).Equal(before) {
		t.Fatal("control packet consumed a data pacing reservation")
	}
}
