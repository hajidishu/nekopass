package brutal

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLossCompensationIsBoundedAndExpires(t *testing.T) {
	now := time.Now()
	c := New(100000, nil)
	c.Outcome(now, 80, 20)
	if got := c.clock.effective(now); got != 125000 {
		t.Fatal("20% loss did not compensate to 125%", got)
	}
	c.Outcome(now, 0, 10000)
	if got := c.clock.effective(now); got != 125000 {
		t.Fatal("loss compensation escaped its cap", got)
	}
	if got := c.clock.effective(now.Add(6 * time.Second)); got != 100000 {
		t.Fatal("loss history did not expire", got)
	}
}
func TestConnectionsShareOneSendingBudget(t *testing.T) {
	budget := NewBudget(100000)
	first, second := New(1000000, budget), New(1000000, budget)
	now := time.Now()
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			first.Sent(now, 1000)
		} else {
			second.Sent(now, 1000)
		}
	}
	if delay := first.Next(now).Sub(now); delay < 69*time.Millisecond {
		t.Fatal("connections multiplied node bandwidth", delay)
	}
	if first.Next(now) != second.Next(now) {
		t.Fatal("senders did not see the same shared backlog")
	}
	budget.SetRate(200000)
	if delay := first.Next(now).Sub(now); delay > 20*time.Millisecond {
		t.Fatal("changing node rate kept stale reservations", delay)
	}
}
func TestCancelledWaitDoesNotConsumeFutureBandwidth(t *testing.T) {
	c := New(1000, nil)
	now := time.Now()
	c.Sent(now, 10000)
	before := c.clock.next
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := c.Wait(ctx, 1000); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if c.clock.next != before {
		t.Fatal("cancelled sender left a reservation")
	}
}
