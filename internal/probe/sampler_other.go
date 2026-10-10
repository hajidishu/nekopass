//go:build !linux

package probe

import pb "github.com/nekopass/nekopass/internal/protocol"

type Sampler struct{}

func NewSampler() *Sampler                           { return &Sampler{} }
func (s *Sampler) Sample(c *pb.NodeConfig) *pb.Probe { return nil }
