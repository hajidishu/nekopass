// Package brutal implements a fixed-rate, loss-compensating packet scheduler.
// It has no dependency on TCP or on the format of a tunnel's datagrams.
package brutal

import (
	"context"
	"sync"
	"time"
)

type sample struct {
	second      int64
	acked, lost uint64
}
type clock struct {
	rate    uint64
	next    time.Time
	samples [5]sample
}

func (p *clock) effective(now time.Time) float64 {
	var acked, lost uint64
	for _, s := range p.samples {
		if age := now.Unix() - s.second; age >= 0 && age < 5 {
			acked += s.acked
			lost += s.lost
		}
	}
	ratio := 1.0
	if acked+lost >= 50 {
		ratio = max(.8, float64(acked)/float64(acked+lost))
	}
	return float64(p.rate) / ratio
}
func (p *clock) outcome(now time.Time, acked, lost uint64) {
	i := now.Unix() % 5
	if p.samples[i].second != now.Unix() {
		p.samples[i] = sample{second: now.Unix()}
	}
	// Bounded counters also bound the effect of malformed remote feedback.
	p.samples[i].acked += min(acked, 1<<20)
	p.samples[i].lost += min(lost, 1<<20)
}
func (p *clock) sent(now time.Time, n int) {
	if p.rate == 0 {
		return
	}
	rate := p.effective(now)
	burst := time.Duration(float64(3000) * float64(time.Second) / rate)
	p.next = maxTime(p.next, now.Add(-burst)).Add(time.Duration(float64(n) * float64(time.Second) / rate))
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Budget is a shared, bounded-memory budget for all senders on one node.
type Budget struct {
	mu    sync.Mutex
	clock clock
}

func NewBudget(rate uint64) *Budget { return &Budget{clock: clock{rate: rate}} }
func (b *Budget) SetRate(rate uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.clock.rate != rate {
		b.clock = clock{rate: rate}
	}
}

type Controller struct {
	mu     sync.Mutex
	clock  clock
	budget *Budget
}

func New(rate uint64, budget *Budget) *Controller {
	if rate == 0 {
		panic("brutal requires a positive send rate")
	}
	return &Controller{clock: clock{rate: rate}, budget: budget}
}
func (c *Controller) nextLocked(now time.Time) time.Time {
	next := maxTime(now, c.clock.next)
	if c.budget != nil && c.budget.clock.rate > 0 {
		next = maxTime(next, c.budget.clock.next)
	}
	return next
}
func (c *Controller) lock() {
	c.mu.Lock()
	if c.budget != nil {
		c.budget.mu.Lock()
	}
}
func (c *Controller) unlock() {
	if c.budget != nil {
		c.budget.mu.Unlock()
	}
	c.mu.Unlock()
}
func (c *Controller) Next(now time.Time) time.Time {
	c.lock()
	defer c.unlock()
	return c.nextLocked(now)
}
func (c *Controller) Sent(now time.Time, n int) {
	c.lock()
	defer c.unlock()
	c.clock.sent(now, n)
	if c.budget != nil {
		c.budget.clock.sent(now, n)
	}
}
func (c *Controller) Outcome(now time.Time, acked, lost uint64) {
	c.lock()
	defer c.unlock()
	c.clock.outcome(now, acked, lost)
	if c.budget != nil {
		c.budget.clock.outcome(now, acked, lost)
	}
}
func (c *Controller) Window(now time.Time, rtt time.Duration) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(15000, int64(c.clock.effective(now)*max(rtt.Seconds(), .001)*2))
}

// Wait reserves only an immediately available packet slot. Cancellation never
// leaves a reservation in a future queue, and waiting allocates no packet queue.
func (c *Controller) Wait(ctx context.Context, n int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		c.lock()
		next := c.nextLocked(now)
		if !next.After(now) {
			c.clock.sent(now, n)
			if c.budget != nil {
				c.budget.clock.sent(now, n)
			}
			c.unlock()
			return nil
		}
		c.unlock()
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
