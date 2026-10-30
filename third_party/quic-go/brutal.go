package quic

import (
	"errors"
	"github.com/quic-go/quic-go/brutal"
)

type brutalUpdate struct {
	rate   uint64
	budget *brutal.Budget
	done   chan error
}

// EnableBrutal switches only this connection's sending direction. Applications
// should call it after authenticating their peer; unrecognized HTTP requests
// and TLS handshakes keep the default congestion controller.
func (c *Conn) EnableBrutal(rate uint64, budget *brutal.Budget) error {
	if rate == 0 || rate > 125000000000 {
		return errors.New("invalid Brutal bandwidth")
	}
	u := brutalUpdate{rate: rate, budget: budget, done: make(chan error, 1)}
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case c.brutalUpdates <- u:
	}
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case err := <-u.done:
		return err
	}
}
func (c *Conn) applyBrutal(u brutalUpdate) {
	setter, ok := c.sentPacketHandler.(interface{ SetBrutal(uint64, *brutal.Budget) })
	if !ok {
		u.done <- errors.New("Brutal controller unavailable")
		return
	}
	setter.SetBrutal(u.rate, u.budget)
	u.done <- nil
}
