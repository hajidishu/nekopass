package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/quic-go/quic-go/brutal"
	"google.golang.org/protobuf/proto"
)

const brutalDataHeader = 16
const brutalFeedbackSize = 24

func validBrutal(c *pb.TunnelCongestion) bool {
	return c.GetBrutal() && c.GetSendBps() > 0 && c.GetSendBps() <= 125000000000 && c.GetReceiveBps() > 0 && c.GetReceiveBps() <= 125000000000
}
func newDatagramBrutal(c *pb.TunnelCongestion, budget *brutal.Budget) (*datagramBrutal, error) {
	if !c.GetBrutal() {
		return nil, nil
	}
	if !validBrutal(c) {
		return nil, errors.New("Brutal bandwidth configuration missing")
	}
	return &datagramBrutal{controller: brutal.New(c.SendBps, budget), config: proto.Clone(c).(*pb.TunnelCongestion)}, nil
}

func (e *Engine) sameBrutal(old *pb.NodeConfig, c *pb.ControlMessage) bool {
	if old.GetBrutalEnabled() != c.Node.GetBrutalEnabled() || old.GetBandwidthUpBps() != c.Node.GetBandwidthUpBps() || old.GetBandwidthDownBps() != c.Node.GetBandwidthDownBps() {
		return false
	}
	previous := e.tunnelPolicy.Load()
	if previous == nil {
		return true
	}
	for _, link := range c.TunnelLinks {
		if previous.links[link.IngressNodeId] != "" && !proto.Equal(previous.congestion[link.IngressNodeId], link.Congestion) {
			return false
		}
	}
	return true
}

func validateBrutalControl(c *pb.ControlMessage) error {
	if c.Node.GetClientTcpBrutalEnabled() && (c.Node.BandwidthUpBps == 0 || c.Node.BandwidthUpBps > 125000000000) {
		return errors.New("入口tcp Brutal 上行带宽无效")
	}
	check := func(v *pb.TunnelCongestion, mode string) bool {
		return !v.GetBrutal() || validBrutal(v) && (mode == "tls_h3" || mode == "plain_udp" || mode == "dtls_udp" || mode == "random_udp")
	}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		if !check(r.Congestion, r.TunnelProtocol) {
			return errors.New("invalid Brutal tunnel configuration")
		}
		for _, p := range r.EgressPeers {
			if !check(p.Congestion, p.Protocol) {
				return errors.New("invalid Brutal exit configuration")
			}
		}
	}
	if c.Node.GetBrutalEnabled() {
		if c.Node.BandwidthUpBps == 0 || c.Node.BandwidthDownBps == 0 || c.Node.BandwidthUpBps > 125000000000 || c.Node.BandwidthDownBps > 125000000000 {
			return errors.New("Brutal node bandwidth configuration missing")
		}
		for _, l := range c.TunnelLinks {
			if !validBrutal(l.Congestion) {
				return errors.New("Brutal link bandwidth configuration missing")
			}
		}
	}
	return nil
}

// Feedback carries cumulative receive counters, not lists of sent packets.
// Memory remains constant under loss, idle peers, and long-running sessions.
type datagramBrutal struct {
	config                     *pb.TunnelCongestion
	controller                 *brutal.Controller
	sent                       atomic.Uint64
	mu                         sync.Mutex
	highest, received          uint64
	feedbackAt                 time.Time
	sampleAt                   time.Time
	sampleHigh, sampleReceived uint64
	lastHigh, lastReceived     uint64
}

func (b *datagramBrutal) frame(body []byte) []byte {
	frame := make([]byte, brutalDataHeader+len(body))
	binary.BigEndian.PutUint64(frame, b.sent.Add(1))
	binary.BigEndian.PutUint64(frame[8:], uint64(time.Now().UnixNano()))
	copy(frame[16:], body)
	return frame
}

// Called only after packet authentication and replay rejection.
func (b *datagramBrutal) receive(frame []byte) (body, feedback []byte, ok bool) {
	if len(frame) < brutalDataHeader {
		return nil, nil, false
	}
	seq := binary.BigEndian.Uint64(frame)
	if seq == 0 {
		return nil, nil, false
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.highest = max(b.highest, seq)
	b.received++
	if b.received == 1 || b.received%16 == 0 || now.Sub(b.feedbackAt) >= 20*time.Millisecond {
		feedback = make([]byte, brutalFeedbackSize)
		binary.BigEndian.PutUint64(feedback, b.highest)
		binary.BigEndian.PutUint64(feedback[8:], b.received)
		copy(feedback[16:], frame[8:16])
		b.feedbackAt = now
	}
	return frame[16:], feedback, true
}

// Authenticated peers still cannot acknowledge unsent or decreasing counters.
func (b *datagramBrutal) feedback(body []byte) {
	if len(body) != brutalFeedbackSize {
		return
	}
	high, received := binary.BigEndian.Uint64(body), binary.BigEndian.Uint64(body[8:])
	if high == 0 || high > b.sent.Load() || received > high {
		return
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if high < b.lastHigh || received < b.lastReceived || high == b.lastHigh && received == b.lastReceived {
		return
	}
	b.lastHigh = high
	b.lastReceived = received
	if b.sampleAt.IsZero() {
		b.sampleAt = now
	}
	if now.Sub(b.sampleAt) < 200*time.Millisecond {
		return
	}
	sent := high - b.sampleHigh
	acked := min(sent, received-b.sampleReceived)
	b.controller.Outcome(now, acked, sent-acked)
	b.sampleHigh = high
	b.sampleReceived = received
	b.sampleAt = now
}
func (b *datagramBrutal) wait(ctx context.Context, deadline time.Time, n int) error {
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	return b.controller.Wait(ctx, n)
}
