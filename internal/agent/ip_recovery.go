package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nekopass/nekopass/internal/iprecovery"
	pb "github.com/nekopass/nekopass/internal/protocol"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"strings"
)

func (s *State) LoadRecovery(key string) (iprecovery.Durable, error) {
	var result iprecovery.Durable
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("meta"))
		selected := []byte("ip_recovery_" + key)
		if data := bucket.Get(selected); data != nil {
			if err := json.Unmarshal(data, &result); err != nil {
				return err
			}
		}
		choose := func(data []byte, other bool) error {
			var value iprecovery.Durable
			if err := json.Unmarshal(data, &value); err != nil {
				return err
			}
			if value.Generation > result.Generation || value.Generation == result.Generation && value.ResetSequence >= result.ResetSequence {
				result = value
				if other && result.Pending && result.Instance.ID == "" {
					result.LegacyTargetUnknown = true
				}
			}
			return nil
		}
		// An agent has one recovery binding. A node-wide latest record preserves
		// its pending task and cooldown even when mode, profile, or target changes.
		if latest := bucket.Get([]byte("ip_recovery_latest")); latest != nil {
			return choose(latest, false)
		}
		// One-time migration of pre-profile agents, whose records only had a
		// resource hash. An unidentified old pending target must fail closed.
		cursor := bucket.Cursor()
		prefix := []byte("ip_recovery_")
		for k, data := cursor.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, data = cursor.Next() {
			if err := choose(data, string(k) != string(selected)); err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}
func (s *State) SaveRecovery(key string, value iprecovery.Durable) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("meta"))
		k := []byte("ip_recovery_" + key)
		for _, target := range [][]byte{k, []byte("ip_recovery_latest")} {
			if old := bucket.Get(target); old != nil {
				var previous iprecovery.Durable
				if err := json.Unmarshal(old, &previous); err != nil {
					return err
				}
				if value.Generation < previous.Generation || value.ResetSequence < previous.ResetSequence {
					return errors.New("refusing stale IP recovery state")
				}
			}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := bucket.Put(k, data); err != nil {
			return err
		}
		return bucket.Put([]byte("ip_recovery_latest"), data)
	})
}
func (e *Engine) configureIPRecovery(config *pb.IPRecoveryConfig) {
	if proto.Equal(e.ipRecoveryConfig, config) {
		return
	}
	if e.ipRecoveryCancel != nil {
		e.ipRecoveryCancel()
		e.ipRecoveryCancel = nil
	}
	if config == nil {
		e.ipRecoveryConfig = nil
		e.ipRecoveryStatus.Store(nil)
		return
	}
	e.ipRecoveryConfig = proto.Clone(config).(*pb.IPRecoveryConfig)
	e.ipRecoveryStatus.Store(&pb.IPRecoveryStatus{Generation: config.Generation, State: "disabled"})
	if !config.Enabled {
		return
	}
	cfg := iprecovery.Config{Enabled: config.Enabled, TargetIP: config.TargetIp, FailureThreshold: int(config.FailureThreshold), CooldownSeconds: int(config.CooldownSeconds), InstanceType: config.InstanceType, AuthToken: config.AuthToken, ShareGroupToken: config.ShareGroupToken, AccountID: config.AccountId, RegionName: config.RegionName, InstanceID: config.InstanceId, StaticIP: config.StaticIp, Generation: config.Generation, ResetSequence: config.ResetSequence, BindingMode: config.BindingMode, ProfileID: config.ProfileId}
	if cfg.Normalize() != nil {
		e.ipRecoveryStatus.Store(&pb.IPRecoveryStatus{Generation: config.Generation, State: "error", Error: "自动换 IP 配置无效"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.ipRecoveryCancel = cancel
	previous := e.ipRecoveryDone
	done := make(chan struct{})
	e.ipRecoveryDone = done
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer close(done)
		// Wait outside Engine.mu so the previous runner can finish publishing
		// and persisting its operation before the replacement reads that state.
		if previous != nil {
			<-previous
		}
		if ctx.Err() != nil {
			return
		}
		runner := iprecovery.Runner{Config: cfg, Store: e.state, API: e.ipRecoveryAPI(), Probe: e.ipRecoveryProbe,
			Publish: func(status iprecovery.Status) {
				e.mu.Lock()
				defer e.mu.Unlock()
				if ctx.Err() != nil || e.closed || e.ipRecoveryConfig == nil || e.ipRecoveryConfig.Generation != cfg.Generation {
					return
				}
				e.ipRecoveryStatus.Store(&pb.IPRecoveryStatus{Generation: status.Generation, State: status.State, Failures: int32(status.Failures), Reachable: status.Reachable, CheckedUnix: status.CheckedUnix, LastAttemptUnix: status.LastAttemptUnix, LastChangedUnix: status.LastChangedUnix, CooldownUntilUnix: status.CooldownUntilUnix, OldIp: status.OldIP, NewIp: status.NewIP, Error: status.Error, InstanceId: status.InstanceID, AccountId: status.AccountID, RegionName: status.RegionName})
			},
			Changed: func() {
				if ctx.Err() == nil {
					e.refreshNetworkAddresses()
				}
			},
		}
		runner.Run(ctx)
	}()
}
func (e *Engine) refreshNetworkAddresses() {
	for _, wake := range []chan struct{}{e.ddnsWake, e.publicIPWake} {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
