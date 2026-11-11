package control

import (
	"context"
	"time"

	"github.com/nekopass/nekopass/internal/probe"
	pb "github.com/nekopass/nekopass/internal/protocol"
)

// One sampler serves the admin dashboard and Telegram, independently of whether
// the bot is enabled. Requests never start additional sampling goroutines.
func (s *Server) RunPanelProbe(ctx context.Context) {
	sampler := probe.NewSampler()
	for ctx.Err() == nil {
		s.panelProbe.Store(sampler.Sample(&pb.NodeConfig{DiskPath: "/"}))
		if !telegramWait(ctx, 5*time.Second) {
			return
		}
	}
}
