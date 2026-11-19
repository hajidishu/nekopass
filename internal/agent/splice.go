package agent

import (
	"io"
	"net"
)

// Each send consumes exactly n bytes or returns an error. write reports how
// many bytes reached the destination, including when a partial write fails.
type sendStreamChunk func(n int, write func(int) (int, error)) error

func copyTunnelStream(dst, src net.Conn) error {
	handled, err := spliceStream(dst, src, func(n int, write func(int) (int, error)) error {
		written, err := write(n)
		if err == nil && written != n {
			return io.ErrShortWrite
		}
		return err
	})
	if handled {
		return err
	}
	holder := buffers.Get().(*[]byte)
	defer buffers.Put(holder)
	// The standard library may also splice a pair of TCP sockets, outside
	// our pipe budget. Use buffered I/O after this path has declined.
	_, err = io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *holder)
	return err
}
