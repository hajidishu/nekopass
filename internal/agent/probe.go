package agent

import (
	"context"
	"github.com/nekopass/nekopass/internal/probe"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
	"time"
)

func defaultNodeConfig() *pb.NodeConfig {
	return &pb.NodeConfig{Enabled: true, ListenHost: "0.0.0.0", PortMin: 1024, PortMax: 65535, MaxConnections: 10000, DialTimeoutSeconds: 8, IdleTimeoutSeconds: 300, ProbeIntervalSeconds: 5, DiskPath: "/"}
}
func (e *Engine) nodeConfiguration() *pb.NodeConfig {
	if c := e.node.Load(); c != nil {
		return proto.Clone(c).(*pb.NodeConfig)
	}
	return defaultNodeConfig()
}
func (e *Engine) collectProbe(ctx context.Context) {
	sampler := probe.NewSampler()
	for {
		c := e.nodeConfiguration()
		if p := sampler.Sample(c); p != nil {
			e.probe.Store(p)
		}
		interval := max(int32(2), c.ProbeIntervalSeconds)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}
