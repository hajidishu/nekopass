// Package handshakereplay bounds authenticated first-flight replays. Production
// listeners use the agent's durable state; isolated callers can use Memory.
package handshakereplay

import (
	"crypto/hmac"
	"errors"
	"sync"
	"time"
)

const Limit = 65536
const PastSeconds int64 = 120
const FutureSeconds int64 = 30

var ErrReplay = errors.New("replayed or expired handshake")

// Store must atomically and durably claim a fingerprint before returning true.
// Entries can be removed only after expires. Errors must fail authentication.
type Store interface {
	Claim(key [32]byte, expires int64) (bool, error)
}

func ValidTimestamp(stamp, now int64) bool {
	return stamp > 0 && stamp >= now-PastSeconds && stamp <= now+FutureSeconds
}

func Expiry(stamp int64) int64 { return stamp + PastSeconds + 1 }

type Memory struct {
	mu     sync.Mutex
	seen   map[[32]byte]int64
	pruned int64
}

func NewMemory() *Memory { return &Memory{seen: make(map[[32]byte]int64)} }

func (m *Memory) Claim(key [32]byte, expires int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Unix()
	if expires <= now || expires > now+PastSeconds+FutureSeconds+2 {
		return false, ErrReplay
	}
	if now != m.pruned || len(m.seen) >= Limit {
		for k, end := range m.seen {
			if end <= now {
				delete(m.seen, k)
			}
		}
		m.pruned = now
	}
	if _, exists := m.seen[key]; exists || len(m.seen) >= Limit {
		return false, nil
	}
	m.seen[key] = expires
	return true, nil
}

type challenge struct {
	source       string
	expires      int64
	cookie, wire []byte
	verified     bool
	sends        int
}

// Gate associates a durable first-flight claim with a short-lived source-bound
// challenge. A restart discards pending challenges, never their durable claims.
// Retransmissions from the original source are bounded and idempotent.
type Gate struct {
	mu      sync.Mutex
	store   Store
	pending map[[32]byte]*challenge
	pruned  int64
}

func NewGate(store Store) *Gate {
	if store == nil {
		store = NewMemory()
	}
	return &Gate{store: store, pending: make(map[[32]byte]*challenge)}
}

// Retire stops retransmission replies after session-key possession is confirmed.
// The durable claim remains until the authenticated first flight expires.
func (g *Gate) Retire(key [32]byte) { g.mu.Lock(); delete(g.pending, key); g.mu.Unlock() }

func (g *Gate) Pending(key [32]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.pending[key]
	return c != nil && c.expires > time.Now().Unix()
}

// Exchange is called only after first-flight authentication and timestamp
// validation. makeChallenge returns the opaque response and its secret cookie.
func (g *Gate) Exchange(key [32]byte, source string, expires int64, cookie []byte, makeChallenge func() ([]byte, []byte, error)) (wire []byte, verified bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().Unix()
	if expires <= now || expires > now+PastSeconds+FutureSeconds+2 || source == "" {
		return nil, false, ErrReplay
	}
	if now != g.pruned || len(g.pending) >= Limit {
		for k, c := range g.pending {
			if c.expires <= now {
				delete(g.pending, k)
			}
		}
		g.pruned = now
	}
	c := g.pending[key]
	if c == nil {
		if len(cookie) != 0 || len(g.pending) >= Limit {
			return nil, false, ErrReplay
		}
		ok, err := g.store.Claim(key, expires)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, ErrReplay
		}
		response, secret, err := makeChallenge()
		if err != nil {
			return nil, false, err
		}
		if len(response) == 0 || len(secret) == 0 {
			return nil, false, ErrReplay
		}
		c = &challenge{source: source, expires: expires, wire: append([]byte(nil), response...), cookie: append([]byte(nil), secret...)}
		g.pending[key] = c
	}
	if c.source != source || c.expires != expires {
		return nil, false, ErrReplay
	}
	if len(cookie) > 0 {
		if !hmac.Equal(cookie, c.cookie) {
			return nil, false, ErrReplay
		}
		c.verified = true
		return nil, true, nil
	}
	if c.verified || c.sends >= 8 {
		return nil, false, ErrReplay
	}
	c.sends++
	return append([]byte(nil), c.wire...), false, nil
}
