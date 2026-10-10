package agent

import (
	"context"
	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"time"
)

// DDNS already reports observations. Independent discovery is enabled by the
// controller only for notification-enabled nodes without active DDNS.
func (e *Engine) configurePublicIP(enabled bool) {
	if enabled == (e.publicIPCancel != nil) {
		return
	}
	if e.publicIPCancel != nil {
		e.publicIPCancel()
		e.publicIPCancel = nil
	}
	e.publicIP.Store(nil)
	if !enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.publicIPCancel = cancel
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		client := e.ddnsClient()
		defer client.Close()
		cfg := ddns.DefaultConfig()
		for ctx.Err() == nil {
			cycle, finish := context.WithTimeout(ctx, 15*time.Second)
			v4, _ := client.Address(cycle, cfg.IPv4URL, false)
			v6, _ := client.Address(cycle, cfg.IPv6URL, true)
			finish()
			e.mu.Lock()
			if ctx.Err() == nil && !e.closed {
				e.publicIP.Store(&pb.PublicIPStatus{Ipv4: v4, Ipv6: v6, CheckedUnix: time.Now().Unix()})
			}
			e.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
		}
	}()
}
