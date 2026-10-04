//go:build !linux

package agent

import pb "github.com/nekopass/nekopass/internal/protocol"

type probeSampler struct{}

func newProbeSampler() *probeSampler                      { return &probeSampler{} }
func (s *probeSampler) sample(c *pb.NodeConfig) *pb.Probe { return nil }
