package agent

import (
	"net"
	"sync"
)

type limitedTLSListener struct {
	net.Listener
	slots chan struct{}
}
type limitedTLSConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedTLSConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedTLSListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedTLSConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			conn.Close()
		}
	}
}
