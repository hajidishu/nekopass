package agent

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/nekopass/nekopass/internal/networkpolicy"
)

func (e *Engine) dialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{KeepAlive: 30 * time.Second, ControlContext: func(_ context.Context, _, resolved string, _ syscall.RawConn) error {
		return e.targetPolicy.Load().CheckResolved(resolved)
	}}
	c, err := d.DialContext(ctx, network, address)
	if err == nil && !e.targetAllowed(c) {
		c.Close()
		return nil, errors.New("target rejected by administrator network policy")
	}
	return c, err
}

func (e *Engine) targetAllowed(c net.Conn) bool {
	p := e.targetPolicy.Load()
	return p == nil || p.CheckResolved(c.RemoteAddr().String()) == nil
}

// Compile before accepting configuration so malformed policies fail closed.
func targetPolicy(configured bool, values []string) (*networkpolicy.Policy, error) {
	if !configured {
		return nil, nil
	}
	return networkpolicy.Compile(values)
}
