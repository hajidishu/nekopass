package agent

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/nekopass/nekopass/internal/control"
	pb "github.com/nekopass/nekopass/internal/protocol"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

type State struct {
	db       *bolt.DB
	Instance string
}
type DiskUser struct {
	Epoch          int64
	Issued         int64
	Spent          int64
	Released       int64
	Traffic        int64
	UnlimitedSpent int64
}

func OpenState(path string) (*State, error) {
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	s := &State{db: db}
	e = db.Update(func(tx *bolt.Tx) error {
		for _, n := range []string{"meta", "users", "rules", "retired_users"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(n)); e != nil {
				return e
			}
		}
		b := tx.Bucket([]byte("meta"))
		s.Instance = string(b.Get([]byte("instance")))
		if s.Instance == "" {
			s.Instance = control.Secret()
			return b.Put([]byte("instance"), []byte(s.Instance))
		}
		return nil
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *State) Close() error { return s.db.Close() }
func (s *State) Config() (*pb.ControlMessage, error) {
	c := &pb.ControlMessage{}
	e := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta")).Get([]byte("config"))
		if b == nil {
			return nil
		}
		return proto.Unmarshal(b, c)
	})
	return c, e
}
func (s *State) SaveConfig(c *pb.ControlMessage) error {
	data, e := proto.Marshal(c)
	if e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("meta")).Put([]byte("config"), data) })
}
func (s *State) LoadUsers() (map[int64]DiskUser, error) {
	out := map[int64]DiskUser{}
	e := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("users")).ForEach(func(k, v []byte) error {
			id, e := strconv.ParseInt(string(k), 10, 64)
			if e != nil {
				return e
			}
			var d DiskUser
			if e = json.Unmarshal(v, &d); e != nil {
				return e
			}
			if d.UnlimitedSpent < 0 || d.Traffic < 0 || d.Spent > math.MaxInt64-d.UnlimitedSpent || d.Traffic > d.Spent+d.UnlimitedSpent || d.Spent < 0 || d.Released < 0 || d.Issued < d.Spent || d.Issued-d.Spent < d.Released {
				return errors.New("corrupt quota state")
			}
			out[id] = d
			return nil
		})
	})
	return out, e
}
func (s *State) SaveUser(id int64, d DiskUser) error {
	data, e := json.Marshal(d)
	if e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		key := []byte(strconv.FormatInt(id, 10))
		if old := b.Get(key); old != nil {
			var previous DiskUser
			if e := json.Unmarshal(old, &previous); e != nil {
				return e
			}
			if d.Epoch < previous.Epoch {
				return errors.New("refusing stale current-period state")
			}
			if d.Epoch > previous.Epoch {
				if e := tx.Bucket([]byte("retired_users")).Put([]byte(epochKey(id, previous.Epoch)), old); e != nil {
					return e
				}
			}
		}
		return b.Put(key, data)
	})
}

func epochKey(id, epoch int64) string {
	return strconv.FormatInt(id, 10) + ":" + strconv.FormatInt(epoch, 10)
}
func (s *State) LoadRetired() (map[string]DiskUser, error) {
	out := map[string]DiskUser{}
	e := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("retired_users")).ForEach(func(k, v []byte) error {
			var d DiskUser
			if e := json.Unmarshal(v, &d); e != nil {
				return e
			}
			out[string(k)] = d
			return nil
		})
	})
	return out, e
}
func (s *State) DropRetired(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("retired_users")).Delete([]byte(key)) })
}
func (s *State) LoadRules() (map[int64]int64, error) {
	out := map[int64]int64{}
	e := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("rules")).ForEach(func(k, v []byte) error {
			id, e := strconv.ParseInt(string(k), 10, 64)
			if e != nil {
				return e
			}
			n, e := strconv.ParseInt(string(v), 10, 64)
			out[id] = n
			return e
		})
	})
	return out, e
}
func (s *State) SaveRules(values map[int64]int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("rules"))
		for id, n := range values {
			if e := b.Put([]byte(strconv.FormatInt(id, 10)), []byte(strconv.FormatInt(n, 10))); e != nil {
				return e
			}
		}
		return nil
	})
}

func (s *State) Checkpoint(users map[int64]DiskUser, rules map[int64]int64) error {
	return s.checkpoint(users, rules, nil)
}
func (s *State) checkpoint(users map[int64]DiskUser, rules map[int64]int64, retired map[string]DiskUser) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		for id, d := range users {
			data, e := json.Marshal(d)
			if e != nil {
				return e
			}
			if e = b.Put([]byte(strconv.FormatInt(id, 10)), data); e != nil {
				return e
			}
		}
		b = tx.Bucket([]byte("rules"))
		for id, n := range rules {
			if e := b.Put([]byte(strconv.FormatInt(id, 10)), []byte(strconv.FormatInt(n, 10))); e != nil {
				return e
			}
		}
		b = tx.Bucket([]byte("retired_users"))
		for key, d := range retired {
			data, e := json.Marshal(d)
			if e != nil {
				return e
			}
			if e = b.Put([]byte(key), data); e != nil {
				return e
			}
		}
		return nil
	})
}
