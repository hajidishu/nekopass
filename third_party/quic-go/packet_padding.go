package quic

import (
	"errors"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// PacketPaddingConfig controls standard QUIC PADDING on application packets.
// Nil disables it. It does not add packets, delay data or change application bytes.
type PacketPaddingConfig struct {
	MaxPadding     int
	BurstBytes     int
	BytesPerSecond int
}

func (c PacketPaddingConfig) validate() error {
	if c.MaxPadding < 1 || c.MaxPadding > 1400 || c.BurstBytes < c.MaxPadding || c.BurstBytes > 65536 || c.BytesPerSecond < 1 || c.BytesPerSecond > 65536 {
		return errors.New("QUIC padding limits out of bounds")
	}
	return nil
}
func clonePacketPadding(c *PacketPaddingConfig) *PacketPaddingConfig {
	if c == nil {
		return nil
	}
	copy := *c
	return &copy
}

type PacketPaddingStats struct{ Packets, Bytes, BudgetSkips uint64 }
type packetPaddingState struct {
	cfg                         PacketPaddingConfig
	tokens                      float64
	last                        monotime.Time
	adaptiveBias                int
	packets, bytes, budgetSkips atomic.Uint64
}

func newPacketPadding(c *PacketPaddingConfig) *packetPaddingState {
	if c == nil {
		return nil
	}
	return &packetPaddingState{cfg: *c, tokens: float64(c.BurstBytes)}
}
func (c *Conn) PacketPaddingStats() PacketPaddingStats {
	p, ok := c.packer.(*packetPacker)
	if !ok || p.packetPadding == nil {
		return PacketPaddingStats{}
	}
	s := p.packetPadding
	return PacketPaddingStats{Packets: s.packets.Load(), Bytes: s.bytes.Load(), BudgetSkips: s.budgetSkips.Load()}
}
func (s *packetPaddingState) additional(pl payload, current, maximum protocol.ByteCount, now monotime.Time, random func(uint64) uint64) protocol.ByteCount {
	// Leave path validation, close and MTU semantics untouched.
	for _, f := range pl.frames {
		switch f.Frame.(type) {
		case *wire.PathChallengeFrame, *wire.PathResponseFrame, *wire.ConnectionCloseFrame:
			return 0
		}
	}
	eligible := false
	for _, f := range pl.streamFrames {
		if f.Frame.StreamID%4 == 0 {
			eligible = true
			break
		}
	}
	if !eligible {
		for _, f := range pl.frames {
			if _, ok := f.Frame.(*wire.DatagramFrame); ok {
				eligible = true
				break
			}
		}
	}
	if !eligible || current >= maximum {
		return 0
	}
	if s.adaptiveBias == 0 {
		s.adaptiveBias = 1 + int(max(random(1000), random(1000)))
	}
	if !s.last.IsZero() && now > s.last {
		s.tokens = min(float64(s.cfg.BurstBytes), s.tokens+now.Sub(s.last).Seconds()*float64(s.cfg.BytesPerSecond))
	}
	if now > s.last {
		s.last = now
	}
	// A per-connection target distribution avoids a globally fixed packet-size floor.
	// Under load the budget reduces padding smoothly; no stream byte boundary is used.
	probability := min(1.0, s.tokens/float64(2*s.cfg.MaxPadding))
	if float64(random(1000)) >= 1000*probability {
		return 0
	}
	floor := int(maximum) * s.adaptiveBias / 1000
	target := floor + int(random(uint64(int(maximum)-floor+1)))
	extra := target - int(current)
	if extra <= 0 {
		return 0
	}
	if extra > s.cfg.MaxPadding || float64(extra) > s.tokens {
		s.budgetSkips.Add(1)
		return 0
	}
	s.tokens -= float64(extra)
	s.packets.Add(1)
	s.bytes.Add(uint64(extra))
	return protocol.ByteCount(extra)
}
