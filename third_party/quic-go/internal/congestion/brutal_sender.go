package congestion

import (
	"github.com/quic-go/quic-go/brutal"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

type BrutalSender struct {
	controller *brutal.Controller
	rtt        *utils.RTTStats
	packetSize protocol.ByteCount
}

func NewBrutalSender(rate uint64, budget *brutal.Budget, rtt *utils.RTTStats, size protocol.ByteCount) *BrutalSender {
	return &BrutalSender{brutal.New(rate, budget), rtt, size}
}
func (b *BrutalSender) TimeUntilSend(protocol.ByteCount) monotime.Time {
	return monotime.FromTime(b.controller.Next(monotime.Now().ToTime()))
}
func (b *BrutalSender) HasPacingBudget(now monotime.Time) bool {
	return !b.controller.Next(now.ToTime()).After(now.ToTime())
}
func (b *BrutalSender) CanSend(inFlight protocol.ByteCount) bool {
	return inFlight < b.GetCongestionWindow()
}
func (b *BrutalSender) GetCongestionWindow() protocol.ByteCount {
	return protocol.ByteCount(b.controller.Window(monotime.Now().ToTime(), b.rtt.SmoothedRTT()))
}
func (b *BrutalSender) OnPacketSent(now monotime.Time, _ protocol.ByteCount, _ protocol.PacketNumber, n protocol.ByteCount, _ bool) {
	b.controller.Sent(now.ToTime(), int(n))
}
func (b *BrutalSender) OnPacketAcked(_ protocol.PacketNumber, _ protocol.ByteCount, _ protocol.ByteCount, now monotime.Time) {
	b.controller.Outcome(now.ToTime(), 1, 0)
}
func (b *BrutalSender) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
	b.controller.Outcome(monotime.Now().ToTime(), 0, 1)
}
func (*BrutalSender) OnSpuriousLoss(protocol.PacketNumber)         {}
func (*BrutalSender) OnRetransmissionTimeout(bool)                 {}
func (*BrutalSender) MaybeExitSlowStart()                          {}
func (*BrutalSender) InSlowStart() bool                            { return false }
func (*BrutalSender) InRecovery() bool                             { return false }
func (b *BrutalSender) SetMaxDatagramSize(size protocol.ByteCount) { b.packetSize = size }

var _ SendAlgorithmWithDebugInfos = (*BrutalSender)(nil)
