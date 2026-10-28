package quic

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/wire"
)

func TestPacketPaddingBudgetsAndStreamOffsets(t *testing.T) {
	cfg := &PacketPaddingConfig{MaxPadding: 1400, BurstBytes: 2048, BytesPerSecond: 128}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	s := newPacketPadding(cfg)
	now := monotime.Now()
	var seed uint64 = 192813
	rng := func(n uint64) uint64 { seed = seed*6364136223846793005 + 1; return seed % n }
	pl := payload{streamFrames: []ackhandler.StreamFrame{{Frame: &wire.StreamFrame{StreamID: 0, Offset: 1 << 30, Data: []byte("payload")}}}, length: 20}
	for i := 0; i < 2000; i++ {
		n := s.additional(pl, 100, 1200, now, rng)
		if n < 0 || n > 1400 {
			t.Fatal(n)
		}
	}
	before := s.bytes.Load()
	if before == 0 || before > 2048 {
		t.Fatal("initial budget or long offset", before)
	}
	for i := 0; i < 2000; i++ {
		s.additional(pl, 100, 1200, now.Add(16*time.Second), rng)
	}
	if s.bytes.Load() <= before || s.bytes.Load() > 4096 {
		t.Fatal("refill", before, s.bytes.Load())
	}
	if n := s.additional(pl, 1200, 1200, now, rng); n != 0 {
		t.Fatal("MTU changed")
	}
}

func TestPacketPaddingLeavesControlAndPathPacketsUnchanged(t *testing.T) {
	cfg := &PacketPaddingConfig{MaxPadding: 256, BurstBytes: 1024, BytesPerSecond: 128}
	for _, frame := range []wire.Frame{&wire.PingFrame{}, &wire.PathChallengeFrame{}, &wire.PathResponseFrame{}, &wire.ConnectionCloseFrame{}} {
		s := newPacketPadding(cfg)
		pl := payload{frames: []ackhandler.Frame{{Frame: frame}}, length: 20}
		if _, ok := frame.(*wire.PingFrame); !ok {
			pl.streamFrames = []ackhandler.StreamFrame{{Frame: &wire.StreamFrame{StreamID: 0, Data: []byte("data")}}}
		}
		if n := s.additional(pl, 100, 1200, monotime.Now(), func(uint64) uint64 { return 0 }); n != 0 {
			t.Fatal("control/path packet padded", frame)
		}
	}
	s := newPacketPadding(cfg)
	if n := s.additional(payload{ack: &wire.AckFrame{}, length: 10}, 100, 1200, monotime.Now(), func(uint64) uint64 { return 0 }); n != 0 {
		t.Fatal("ACK-only packet padded")
	}
}

func TestPacketPaddingConfigValidationAndClone(t *testing.T) {
	valid := PacketPaddingConfig{MaxPadding: 256, BurstBytes: 8192, BytesPerSecond: 8192}
	for _, change := range []func(*PacketPaddingConfig){func(c *PacketPaddingConfig) { c.MaxPadding = 0 }, func(c *PacketPaddingConfig) { c.MaxPadding = 1401 }, func(c *PacketPaddingConfig) { c.BurstBytes = 65537 }, func(c *PacketPaddingConfig) { c.BurstBytes = 10 }, func(c *PacketPaddingConfig) { c.BytesPerSecond = -1 }} {
		v := valid
		change(&v)
		if err := validateConfig(&Config{PacketPadding: &v}); err == nil {
			t.Fatal("invalid policy accepted", v)
		}
	}
	c := &Config{PacketPadding: &valid}
	copy := c.Clone()
	copy.PacketPadding.MaxPadding = 100
	if c.PacketPadding.MaxPadding != 256 {
		t.Fatal("cloned configuration aliases the original")
	}
	populated := populateConfig(c)
	populated.PacketPadding.MaxPadding = 80
	if c.PacketPadding.MaxPadding != 256 {
		t.Fatal("populated configuration aliases the original")
	}
}
