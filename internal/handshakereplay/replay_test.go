package handshakereplay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestMemoryBoundsExpiryAndTimestamp(t *testing.T) {
	now := time.Now().Unix()
	s := NewMemory()
	for i := 0; i < Limit; i++ {
		var key [32]byte
		binary.BigEndian.PutUint64(key[:8], uint64(i))
		ok, err := s.Claim(key, Expiry(now))
		if err != nil || !ok {
			t.Fatal(i, ok, err)
		}
	}
	var next [32]byte
	next[31] = 1
	if ok, err := s.Claim(next, Expiry(now)); err != nil || ok {
		t.Fatal("cache exceeded bound", ok, err)
	}
	for key := range s.seen {
		s.seen[key] = now - 1
	}
	if ok, err := s.Claim(next, Expiry(now)); err != nil || !ok || len(s.seen) != 1 {
		t.Fatal("expired entries not reclaimed", ok, err)
	}
	for _, stamp := range []int64{0, now - PastSeconds - 1, now + FutureSeconds + 1} {
		if ValidTimestamp(stamp, now) {
			t.Fatal("invalid timestamp accepted", stamp)
		}
	}
	for _, stamp := range []int64{now - PastSeconds, now, now + FutureSeconds} {
		if !ValidTimestamp(stamp, now) {
			t.Fatal("valid timestamp refused", stamp)
		}
	}
}

func TestChallengeIsSourceBoundIdempotentAndSurvivesRestart(t *testing.T) {
	store := NewMemory()
	gate := NewGate(store)
	key := [32]byte{1}
	expires := Expiry(time.Now().Unix())
	calls := 0
	makeChallenge := func() ([]byte, []byte, error) {
		calls++
		return []byte("opaque challenge"), []byte("secret cookie"), nil
	}
	first, verified, err := gate.Exchange(key, "source-a", expires, nil, makeChallenge)
	if err != nil || verified || len(first) == 0 {
		t.Fatal(verified, err)
	}
	for i := 0; i < 3; i++ {
		wire, ok, err := gate.Exchange(key, "source-a", expires, nil, makeChallenge)
		if err != nil || ok || !bytes.Equal(first, wire) {
			t.Fatal("retransmission changed challenge", ok, err)
		}
	}
	if wire, _, err := gate.Exchange(key, "source-b", expires, nil, makeChallenge); err == nil || wire != nil {
		t.Fatal("captured initial got response at another source")
	}
	if wire, _, err := gate.Exchange(key, "source-a", expires, []byte("wrong"), makeChallenge); err == nil || wire != nil {
		t.Fatal("invalid cookie accepted")
	}
	if _, ok, err := gate.Exchange(key, "source-a", expires, []byte("secret cookie"), makeChallenge); err != nil || !ok {
		t.Fatal("valid cookie refused", err)
	}
	if wire, _, err := gate.Exchange(key, "source-a", expires, nil, makeChallenge); err == nil || wire != nil {
		t.Fatal("completed initial got another challenge")
	}
	if _, ok, err := gate.Exchange(key, "source-a", expires, []byte("secret cookie"), makeChallenge); err != nil || !ok {
		t.Fatal("response-loss retry refused", err)
	}
	restarted := NewGate(store)
	for _, cookie := range [][]byte{nil, []byte("secret cookie")} {
		if wire, _, err := restarted.Exchange(key, "source-a", expires, cookie, makeChallenge); err == nil || wire != nil {
			t.Fatal("recreated gate answered old flight")
		}
	}
	if calls != 1 {
		t.Fatal("replay generated new challenge", calls)
	}
}

type brokenStore struct{}

func (brokenStore) Claim([32]byte, int64) (bool, error) { return false, errors.New("disk unavailable") }
func TestStoreFailureAndChallengeRetransmissionBounds(t *testing.T) {
	makeChallenge := func() ([]byte, []byte, error) { return []byte{1}, []byte{2}, nil }
	if wire, _, err := NewGate(brokenStore{}).Exchange([32]byte{}, "a", Expiry(time.Now().Unix()), nil, makeChallenge); err == nil || wire != nil {
		t.Fatal("failed store produced a response")
	}
	g := NewGate(nil)
	responses := 0
	for i := 0; i < 32; i++ {
		wire, _, _ := g.Exchange([32]byte{}, "a", Expiry(time.Now().Unix()), nil, makeChallenge)
		if len(wire) > 0 {
			responses++
		}
	}
	if responses != 8 {
		t.Fatal("unbounded challenge repeats", responses)
	}
}
