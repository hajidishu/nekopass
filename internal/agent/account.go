package agent

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"golang.org/x/time/rate"
)

const BufferSize = 32 << 10
const ReservationBlock int64 = 16 << 20

var ErrQuota = errors.New("quota exhausted or no offline allowance")

type Account struct {
	mu              sync.Mutex
	id              int64
	disk            DiskUser
	credit          int64
	unlimitedCredit int64
	unlimitedMode   bool
	state           *State
	policy          *pb.UserPolicy
	limiter         *rate.Limiter
	active          atomic.Int64
	wanted          time.Time
	fatal           error
	ips             map[string]int
}

func newAccount(id int64, d DiskUser, s *State) *Account {
	return &Account{id: id, disk: d, state: s, limiter: rate.NewLimiter(1, BufferSize)}
}
func (a *Account) configure(p *pb.UserPolicy) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.QuotaEpoch != a.disk.Epoch {
		return errors.New("quota epoch requires a new account instance")
	}
	if a.unlimitedMode != p.QuotaUnlimited {
		a.credit = 0
		a.unlimitedCredit = 0
	}
	a.unlimitedMode = p.QuotaUnlimited
	a.policy = p
	limit := rate.Limit(p.SpeedBps)
	if p.SpeedBps == 0 {
		limit = rate.Inf
	}
	a.limiter.SetLimit(limit)
	// About 10 ms of burst capacity, bounded to avoid large short transfers bypassing the cap.
	a.limiter.SetBurst(int(max(int64(BufferSize), min(p.SpeedBps/100, 1<<20))))
	if p.Issued > a.disk.Issued {
		a.disk.Issued = p.Issued
		return a.persist()
	}
	return nil
}
func (a *Account) persist() error {
	e := a.state.SaveUser(a.id, a.disk)
	if e != nil {
		a.fatal = e
	}
	return e
}
func (a *Account) validLocked() bool {
	return a.fatal == nil && a.policy != nil && a.policy.Enabled && (a.policy.ExpiresUnix == 0 || time.Now().Unix() < a.policy.ExpiresUnix)
}
func (a *Account) valid() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.validLocked() }
func (a *Account) acquire() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.validLocked() || (a.policy.MaxConnections > 0 && a.active.Load() >= a.policy.MaxConnections) {
		return false
	}
	a.active.Add(1)
	a.wanted = time.Now()
	return true
}

// Local accounting is durable in blocks in both modes. Unlimited traffic
// never requests or consumes a finite grant, including while disconnected.
func (a *Account) tryTake(n int) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.validLocked() {
		return 0, errors.New("user disabled, expired or persistence failed")
	}
	a.wanted = time.Now()
	if a.policy.QuotaUnlimited {
		if a.unlimitedCredit == 0 {
			block := min(ReservationBlock, math.MaxInt64-a.disk.Spent-a.disk.UnlimitedSpent)
			if block <= 0 {
				return 0, errors.New("traffic accounting counter exhausted")
			}
			a.disk.UnlimitedSpent += block
			if err := a.persist(); err != nil {
				return 0, err
			}
			a.unlimitedCredit = block
		}
		size := min(int64(n), a.unlimitedCredit)
		a.unlimitedCredit -= size
		return int(size), nil
	}
	if a.credit == 0 {
		available := a.disk.Issued - a.disk.Spent - a.disk.Released
		if available > 0 {
			block := min(ReservationBlock, available)
			if block > math.MaxInt64-a.disk.Spent-a.disk.UnlimitedSpent {
				return 0, errors.New("traffic accounting counter exhausted")
			}
			a.disk.Spent += block
			if err := a.persist(); err != nil {
				return 0, err
			}
			a.credit = block
		}
	}
	size := min(int64(n), a.credit)
	a.credit -= size
	return int(size), nil
}
func (a *Account) take(ctx context.Context, n int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if size, err := a.tryTake(n); size > 0 || err != nil {
		return size, err
	}
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline.C:
			return 0, ErrQuota
		case <-ticker.C:
			if size, err := a.tryTake(n); size > 0 || err != nil {
				return size, err
			}
		}
	}
}
func (a *Account) count(n int) { a.mu.Lock(); a.disk.Traffic += int64(n); a.mu.Unlock() }

// Caller holds mu through the atomic checkpoint so a reservation cannot be overwritten.
func (a *Account) report() (*pb.Usage, bool, error) {
	// Release only durable, unused allowance. Reserved blocks never re-enter the global pool.
	wanted := a.validLocked() && (a.active.Load() > 0 || time.Since(a.wanted) < 10*time.Second)
	unlimited := a.policy != nil && a.policy.QuotaUnlimited
	if unlimited || (!wanted && time.Since(a.wanted) > 30*time.Second) {
		available := a.disk.Issued - a.disk.Spent - a.disk.Released
		if available > 0 {
			a.disk.Released += available
		}
	}
	return &pb.Usage{UserId: a.id, Spent: a.disk.Spent, Released: a.disk.Released, Traffic: a.disk.Traffic, UnlimitedSpent: a.disk.UnlimitedSpent, QuotaUnlimited: unlimited, QuotaEpoch: a.disk.Epoch}, wanted && !unlimited, nil
}

func (a *Account) addIP(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.validLocked() {
		return false
	}
	if a.ips == nil {
		a.ips = map[string]int{}
	}
	if a.ips[ip] == 0 && a.policy.IpLimit > 0 && len(a.ips) >= int(a.policy.IpLimit) {
		return false
	}
	a.ips[ip]++
	return true
}
func (a *Account) removeIP(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ips[ip]--
	if a.ips[ip] <= 0 {
		delete(a.ips, ip)
	}
}
