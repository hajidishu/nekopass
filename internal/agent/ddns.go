package agent

import (
	"context"
	"strings"
	"time"

	"github.com/nekopass/nekopass/internal/ddns"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

// Called under Engine.mu; only the background loop performs network I/O.
func (e *Engine) configureDDNS(config *pb.DDNSConfig) {
	if proto.Equal(e.ddnsConfig, config) {
		return
	}
	if e.ddnsCancel != nil {
		e.ddnsCancel()
		e.ddnsCancel = nil
	}
	if config == nil {
		e.ddnsConfig = nil
		e.ddnsStatus.Store(nil)
		return
	}
	e.ddnsConfig = proto.Clone(config).(*pb.DDNSConfig)
	state := "disabled"
	if config.Enabled {
		state = "pending"
	}
	e.ddnsStatus.Store(&pb.DDNSStatus{Generation: config.Generation, State: state})
	if !config.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.ddnsCancel = cancel
	e.wg.Add(1)
	go func() { defer e.wg.Done(); e.runDDNS(ctx, proto.Clone(config).(*pb.DDNSConfig)) }()
}

func ddnsConfiguration(c *pb.DDNSConfig) ddns.Config {
	return ddns.Config{Enabled: c.Enabled, Provider: c.Provider, RecordName: c.RecordName, ZoneID: c.ZoneId, Token: c.Token, IPv4: c.Ipv4, IPv6: c.Ipv6, IntervalSeconds: int(c.IntervalSeconds), TTL: int(c.Ttl), IPv4URL: c.Ipv4Url, IPv6URL: c.Ipv6Url}
}

func (e *Engine) publishDDNS(ctx context.Context, status *pb.DDNSStatus) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed && ctx.Err() == nil && e.ddnsConfig != nil && e.ddnsConfig.Generation == status.Generation {
		e.ddnsStatus.Store(proto.Clone(status).(*pb.DDNSStatus))
	}
}

func (e *Engine) runDDNS(ctx context.Context, config *pb.DDNSConfig) {
	cfg := ddnsConfiguration(config)
	if err := cfg.Normalize(); err != nil {
		e.publishDDNS(ctx, &pb.DDNSStatus{Generation: config.Generation, State: "error", Error: "DDNS 配置无效"})
		return
	}
	client := e.ddnsClient()
	defer client.Close()
	status := &pb.DDNSStatus{Generation: config.Generation}
	lastIPv4, lastIPv6, zone := "", "", cfg.ZoneID
	var reconciled4, reconciled6 time.Time
	for ctx.Err() == nil {
		cycle, finishCycle := context.WithTimeout(ctx, 60*time.Second)
		now := time.Now()
		status.CheckedUnix = now.Unix()
		status.Error = ""
		status.ObservedIpv4, status.ObservedIpv6 = "", ""
		if status.UpdatedUnix > status.CheckedUnix {
			status.UpdatedUnix = status.CheckedUnix
		}
		errors := []string{}
		successes := 0
		for _, family := range []struct {
			enabled, v6  bool
			source, kind string
		}{{cfg.IPv4, false, cfg.IPv4URL, "A"}, {cfg.IPv6, true, cfg.IPv6URL, "AAAA"}} {
			if !family.enabled {
				continue
			}
			label := "IPv4"
			if family.v6 {
				label = "IPv6"
			}
			ip, err := client.Address(cycle, family.source, family.v6)
			if err != nil {
				errors = append(errors, label+"："+err.Error())
				continue
			}
			last, reconciled := lastIPv4, reconciled4
			if family.v6 {
				status.ObservedIpv6 = ip
			} else {
				status.ObservedIpv4 = ip
			}
			if family.v6 {
				last, reconciled = lastIPv6, reconciled6
			}
			if last == ip && now.Sub(reconciled) < time.Hour {
				successes++
				continue
			}
			if zone == "" {
				zone, err = client.Zone(cycle, cfg)
			}
			if err == nil {
				var changed bool
				changed, err = client.Sync(cycle, cfg, zone, family.kind, ip)
				if err == nil && changed {
					status.UpdatedUnix = time.Now().Unix()
				}
			}
			if err != nil {
				errors = append(errors, label+"："+err.Error())
				continue
			}
			successes++
			if family.v6 {
				lastIPv6, status.Ipv6, reconciled6 = ip, ip, now
			} else {
				lastIPv4, status.Ipv4, reconciled4 = ip, ip, now
			}
		}
		status.State = "ok"
		if len(errors) > 0 {
			status.State = "error"
			if successes > 0 {
				status.State = "partial"
			}
			status.Error = strings.Join(errors, "；")
		}
		status.CheckedUnix = time.Now().Unix()
		if status.UpdatedUnix > status.CheckedUnix {
			status.UpdatedUnix = status.CheckedUnix
		}
		finishCycle()
		e.publishDDNS(ctx, status)
		timer := time.NewTimer(time.Duration(cfg.IntervalSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
