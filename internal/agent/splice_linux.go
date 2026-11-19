package agent

import (
	"errors"
	"io"
	"net"

	"golang.org/x/sys/unix"
)

type splicePipe [2]int

type splicePipePool struct {
	idle      chan splicePipe
	allocated chan struct{}
}

// Limit both active and cached pipes across all rules. Each pipe uses two FDs.
var streamSplicePipes = splicePipePool{
	idle:      make(chan splicePipe, 32),
	allocated: make(chan struct{}, 128),
}

func (p *splicePipePool) get() (splicePipe, bool) {
	select {
	case pipe := <-p.idle:
		return pipe, true
	default:
	}
	select {
	case p.allocated <- struct{}{}:
	default:
		return splicePipe{}, false
	}
	var pipe splicePipe
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		<-p.allocated
		return splicePipe{}, false
	}
	return pipe, true
}

func (p *splicePipePool) put(pipe splicePipe, empty bool) {
	if empty {
		select {
		case p.idle <- pipe:
			return
		default:
		}
	}
	_ = unix.Close(pipe[0])
	_ = unix.Close(pipe[1])
	<-p.allocated
}

// Only unwrap metadata and read-ahead. A TLS, AEAD or multiplexed stream
// needs its own Read and Write methods even when carried by a TCP socket.
func spliceTCP(c net.Conn) *net.TCPConn {
	switch v := c.(type) {
	case *net.TCPConn:
		return v
	case *billedConn:
		return spliceTCP(v.Conn)
	case *bufferedConn:
		return spliceTCP(v.Conn)
	default:
		return nil
	}
}

func spliceBufferedLen(c net.Conn) int {
	switch v := c.(type) {
	case *billedConn:
		return spliceBufferedLen(v.Conn)
	case *bufferedConn:
		if len(v.prefix) > 0 {
			return len(v.prefix)
		}
		if v.reader != nil && v.reader.Buffered() > 0 {
			return v.reader.Buffered()
		}
		return spliceBufferedLen(v.Conn)
	default:
		return 0
	}
}

func sendSpliceReadAhead(dst, src net.Conn, send sendStreamChunk) error {
	cached := spliceBufferedLen(src)
	if cached == 0 {
		return nil
	}
	holder := buffers.Get().(*[]byte)
	defer buffers.Put(holder)
	buf := *holder
	offset := 0
	write := func(size int) (int, error) {
		n, err := dst.Write(buf[offset : offset+size])
		offset += n
		return n, err
	}
	for cached > 0 {
		n, err := src.Read(buf[:min(cached, len(buf))])
		if n > 0 {
			offset = 0
			if sendErr := send(n, write); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		cached = spliceBufferedLen(src)
	}
	return nil
}

func spliceStream(dst, src net.Conn, send sendStreamChunk) (bool, error) {
	return streamSplicePipes.copy(dst, src, send)
}

func (p *splicePipePool) copy(dst, src net.Conn, send sendStreamChunk) (bool, error) {
	in, out := spliceTCP(src), spliceTCP(dst)
	if in == nil || out == nil {
		return false, nil
	}
	input, err := in.SyscallConn()
	if err != nil {
		return false, nil
	}
	output, err := out.SyscallConn()
	if err != nil {
		return false, nil
	}
	if err := sendSpliceReadAhead(dst, src, send); err != nil {
		return true, err
	}

	var pipe splicePipe
	var pending, drained, sent int
	var readErr, writeErr error
	var fallback bool
	read := func(fd uintptr) bool {
		var ok bool
		pipe, ok = p.get()
		if !ok {
			fallback = true
			return true
		}
		drained, readErr = spliceBytes(int(fd), pipe[1], BufferSize)
		if drained == 0 {
			// Release the pipe before netpoll waits for an idle socket.
			p.put(pipe, true)
			if spliceUnsupported(readErr) {
				fallback = true
			}
		}
		return readErr != unix.EAGAIN
	}
	pump := func(fd uintptr) bool {
		for pending > 0 {
			var n int
			n, writeErr = spliceBytes(pipe[0], int(fd), pending)
			pending -= n
			sent += n
			if writeErr != nil {
				return writeErr != unix.EAGAIN
			}
			if n == 0 {
				writeErr = io.ErrShortWrite
				return true
			}
		}
		return true
	}
	write := func(size int) (int, error) {
		pending, sent, writeErr = size, 0, nil
		if err := output.Write(pump); err != nil {
			return sent, err
		}
		return sent, writeErr
	}
	for {
		drained, readErr = 0, nil
		err := input.Read(read)
		if drained == 0 {
			if fallback {
				// No bytes are outstanding and fallback resumes at the
				// same position in the stream.
				return false, nil
			}
			return true, errors.Join(err, readErr)
		}
		err = send(drained, write)
		// A failed send might leave unread bytes in the pipe. Destroy it
		// so that no data can carry over to another connection.
		p.put(pipe, err == nil)
		if err != nil {
			return true, err
		}
	}
}

func spliceBytes(src, dst, size int) (int, error) {
	for {
		n, err := unix.Splice(src, nil, dst, nil, size, unix.SPLICE_F_NONBLOCK)
		if err != unix.EINTR {
			return max(0, int(n)), err
		}
	}
}

func spliceUnsupported(err error) bool {
	switch err {
	case unix.EINVAL, unix.ENOSYS, unix.EOPNOTSUPP, unix.EPERM:
		return true
	default:
		return false
	}
}
