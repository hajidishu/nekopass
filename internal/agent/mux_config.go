package agent

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
)

func validateMuxControl(c *pb.ControlMessage) error {
	if c.Node != nil {
		if err := tunnel.MuxSettings(c.Node.Mux).Validate(); err != nil {
			return err
		}
	}
	for _, r := range c.Rules {
		if err := tunnel.MuxSettings(r.Mux).Validate(); err != nil {
			return err
		}
		for _, p := range r.EgressPeers {
			if err := tunnel.MuxSettings(p.Mux).Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
