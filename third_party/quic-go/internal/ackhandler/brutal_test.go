package ackhandler

import (
	"github.com/quic-go/quic-go/brutal"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"testing"
)

func TestBrutalSelectionSurvivesPathMigration(t *testing.T) {
	h := NewSentPacketHandler(0, protocol.InitialPacketSize, &utils.RTTStats{}, &utils.ConnectionStats{}, true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	if _, ok := h.congestion.(*congestion.BrutalSender); ok {
		t.Fatal("default controller changed")
	}
	budget := brutal.NewBudget(1000000)
	h.SetBrutal(500000, budget)
	first := h.congestion
	h.SetBrutal(500000, budget)
	if first != h.congestion {
		t.Fatal("an additional authenticated stream reset congestion state")
	}
	h.MigratedPath(monotime.Now(), 1400)
	if _, ok := h.congestion.(*congestion.BrutalSender); !ok || h.brutalRate != 500000 || h.brutalBudget != budget {
		t.Fatal("path migration silently reverted congestion control")
	}
}
