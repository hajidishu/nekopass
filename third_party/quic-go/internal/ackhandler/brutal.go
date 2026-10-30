package ackhandler

import (
	"github.com/quic-go/quic-go/brutal"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
)

func (h *sentPacketHandler) SetBrutal(rate uint64, budget *brutal.Budget) {
	if rate == h.brutalRate && budget == h.brutalBudget {
		return
	}
	h.brutalRate = rate
	h.brutalBudget = budget
	h.congestion = congestion.NewBrutalSender(rate, budget, h.rttStats, protocol.InitialPacketSize)
}
