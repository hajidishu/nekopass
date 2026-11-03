package agent

import (
	"encoding/binary"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekopass/nekopass/internal/handshakereplay"
	bolt "go.etcd.io/bbolt"
)

func TestHandshakeReplayClaimsAreDurableAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	key := [32]byte{1}
	end := handshakereplay.Expiry(time.Now().Unix())
	var count atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := s.Claim(key, end)
			if e != nil {
				t.Error(e)
			}
			if ok {
				count.Add(1)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatal("duplicate claim committed", count.Load())
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ok, err := s.Claim(key, end); err != nil || ok {
		t.Fatal("reopen accepted old claim", ok, err)
	}
	// Seed an expired entry and its index to independently exercise pruning.
	if err = s.db.Update(func(tx *bolt.Tx) error {
		entries := tx.Bucket([]byte("handshake_replay"))
		index := tx.Bucket([]byte("handshake_replay_expiry"))
		var when [8]byte
		binary.BigEndian.PutUint64(when[:], uint64(time.Now().Unix()-1))
		for i := 2; i < 66; i++ {
			old := [32]byte{byte(i)}
			if err := entries.Put(old[:], when[:]); err != nil {
				return err
			}
			var indexed [40]byte
			copy(indexed[:8], when[:])
			copy(indexed[8:], old[:])
			if err := index.Put(indexed[:], []byte{1}); err != nil {
				return err
			}
		}
		return entries.SetSequence(65)
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Claim([32]byte{3}, end); err != nil || !ok {
		t.Fatal("new claim after pruning refused", err)
	}
	if err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("handshake_replay"))
		if b.Sequence() != 2 || b.Stats().KeyN != 2 {
			t.Error("expiry index or count corrupted", b.Sequence(), b.Stats().KeyN)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
