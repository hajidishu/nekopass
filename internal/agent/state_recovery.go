package agent

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"sync/atomic"

	pb "github.com/nekopass/nekopass/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

func (s *State) RestorePending() (bool, error) {
	var pending bool
	err := s.db.View(func(tx *bolt.Tx) error {
		pending = len(tx.Bucket([]byte("meta")).Get([]byte("restore_pending"))) > 0
		return nil
	})
	return pending, err
}

func (e *Engine) restoreState(c *pb.ControlMessage) error {
	if c.StateRestore == nil {
		return nil
	}
	pending, err := e.state.RestorePending()
	if err != nil {
		return err
	}
	if !pending || c.StateRestore.InstanceId != e.state.Instance || len(e.users) != 0 || len(e.retired) != 0 || len(e.counters) != 0 || e.revision != 0 {
		return errors.New("unexpected Agent state restore")
	}
	users := map[int64]DiskUser{}
	counts := map[int64]int64{}
	for _, v := range c.StateRestore.Users {
		if v.UserId <= 0 || v.QuotaEpoch < 0 || v.Issued < 0 || v.Spent < 0 || v.Released < 0 || v.UnlimitedSpent < 0 || v.Traffic < 0 || v.Spent > v.Issued || v.Released > v.Issued-v.Spent || v.Spent > math.MaxInt64-v.UnlimitedSpent || v.Traffic > v.Spent+v.UnlimitedSpent {
			return errors.New("invalid restored usage")
		}
		if _, ok := users[v.UserId]; ok {
			return errors.New("duplicate restored user")
		}
		users[v.UserId] = DiskUser{Epoch: v.QuotaEpoch, Issued: v.Issued, Spent: v.Spent, Released: v.Released, Traffic: v.Traffic, UnlimitedSpent: v.UnlimitedSpent}
	}
	for _, v := range c.StateRestore.Rules {
		if v.RuleId <= 0 || v.Traffic < 0 {
			return errors.New("invalid restored rule usage")
		}
		counts[v.RuleId] = v.Traffic
	}
	// Baselines and marker commit together before any forwarding can start.
	err = e.state.db.Update(func(tx *bolt.Tx) error {
		for id, d := range users {
			data, err := json.Marshal(d)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("users")).Put([]byte(strconv.FormatInt(id, 10)), data); err != nil {
				return err
			}
		}
		for id, count := range counts {
			if err := tx.Bucket([]byte("rules")).Put([]byte(strconv.FormatInt(id, 10)), []byte(strconv.FormatInt(count, 10))); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("meta")).Delete([]byte("restore_pending"))
	})
	if err != nil {
		return err
	}
	for id, d := range users {
		e.users[id] = newAccount(id, d, e.state)
	}
	for id, count := range counts {
		v := &atomic.Int64{}
		v.Store(count)
		e.counters[id] = v
	}
	return nil
}
