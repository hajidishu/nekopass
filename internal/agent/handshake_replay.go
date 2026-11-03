package agent

import (
	"encoding/binary"
	"time"

	"github.com/nekopass/nekopass/internal/handshakereplay"
	bolt "go.etcd.io/bbolt"
)

// Claim commits before the listener emits a response. The expiry index makes
// cleanup proportional to expired entries, rather than all live handshakes.
func (s *State) Claim(key [32]byte, expires int64) (claimed bool, err error) {
	now := time.Now().Unix()
	if expires <= now || expires > now+handshakereplay.PastSeconds+handshakereplay.FutureSeconds+2 {
		return false, handshakereplay.ErrReplay
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		entries := tx.Bucket([]byte("handshake_replay"))
		index := tx.Bucket([]byte("handshake_replay_expiry"))
		count := entries.Sequence()
		cursor := index.Cursor()
		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			if len(k) != 40 {
				return handshakereplay.ErrReplay
			}
			if int64(binary.BigEndian.Uint64(k[:8])) > now {
				break
			}
			if entries.Get(k[8:]) == nil || count == 0 {
				return handshakereplay.ErrReplay
			}
			if err := entries.Delete(k[8:]); err != nil {
				return err
			}
			count--
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		if err := entries.SetSequence(count); err != nil {
			return err
		}
		if entries.Get(key[:]) != nil || count >= handshakereplay.Limit {
			return nil
		}
		var end [8]byte
		binary.BigEndian.PutUint64(end[:], uint64(expires))
		if err := entries.Put(key[:], end[:]); err != nil {
			return err
		}
		var indexed [40]byte
		copy(indexed[:8], end[:])
		copy(indexed[8:], key[:])
		if err := index.Put(indexed[:], []byte{1}); err != nil {
			return err
		}
		if err := entries.SetSequence(count + 1); err != nil {
			return err
		}
		claimed = true
		return nil
	})
	return claimed && err == nil, err
}
