package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func spliceSocketPair(t testing.TB) (left, right *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	left, err = net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { left.Close() })
	right, err = ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { right.Close() })
	return left, right
}

func TestSplicePreservesReadAheadAndFallback(t *testing.T) {
	for _, capacity := range []int{1, 0} {
		name := "kernel"
		if capacity == 0 {
			name = "no_pipes"
		}
		t.Run(name, func(t *testing.T) {
			pool := splicePipePool{allocated: make(chan struct{}, capacity)}
			sender, input := spliceSocketPair(t)
			output, receiver := spliceSocketPair(t)
			for _, c := range []*net.TCPConn{sender, input, output, receiver} {
				c.SetDeadline(time.Now().Add(3 * time.Second))
			}
			payload := bytes.Repeat([]byte("0123456789abcdef"), BufferSize/8)
			sender.Write(payload)
			sender.CloseWrite()
			readAhead := bufio.NewReaderSize(input, 32)
			if _, err := readAhead.Peek(8); err != nil {
				t.Fatal(err)
			}
			prefix := []byte("captured ClientHello")
			var src net.Conn = &bufferedConn{Conn: &bufferedConn{Conn: input, reader: readAhead}, prefix: prefix}
			dst := &billedConn{Conn: output}
			sent := 0
			handled, err := pool.copy(dst, src, func(n int, write func(int) (int, error)) error {
				written, err := write(n)
				sent += written
				return err
			})
			if err != nil || handled != (capacity > 0) {
				t.Fatalf("handled=%v sent=%d err=%v", handled, sent, err)
			}
			if !handled {
				if sent != len(prefix)+32 {
					t.Fatalf("fallback did not start after buffered bytes: sent=%d", sent)
				}
				if _, err = io.Copy(dst, src); err != nil {
					t.Fatal(err)
				}
			}
			closeForwardWrite(dst)
			got, err := io.ReadAll(receiver)
			want := append(prefix, payload...)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("received %d of %d bytes, in order=%v, err=%v", len(got), len(want), bytes.Equal(got, want), err)
			}
			if len(pool.allocated) != 0 {
				t.Fatal("pipe wasn't released")
			}
		})
	}
}

func TestSpliceSettlesPartialWriteAndDiscardsPipe(t *testing.T) {
	pool := splicePipePool{allocated: make(chan struct{}, 1), idle: make(chan splicePipe, 1)}
	sender, input := spliceSocketPair(t)
	output, receiver := spliceSocketPair(t)
	for _, c := range []*net.TCPConn{sender, input, output, receiver} {
		c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	payload := []byte("forwarded then discarded")
	sender.Write(payload)
	sender.CloseWrite()
	written := 0
	handled, err := pool.copy(output, input, func(n int, write func(int) (int, error)) error {
		w, err := write(n / 2)
		written += w
		if err != nil {
			return err
		}
		output.SetWriteDeadline(time.Now().Add(-time.Second))
		w, err = write(n - w)
		written += w
		return err
	})
	if !handled || !errors.Is(err, os.ErrDeadlineExceeded) || written != len(payload)/2 {
		t.Fatalf("handled=%v written=%d err=%v", handled, written, err)
	}
	if len(pool.allocated) != 0 || len(pool.idle) != 0 {
		t.Fatal("dirty pipe was retained")
	}
}

func TestSpliceFiniteQuotaInBothDirections(t *testing.T) {
	_, account := testAccount(t, 8193, 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, activityKey{}, &atomic.Int64{})
	var count atomic.Int64
	type direction struct {
		input, output *net.TCPConn
		reader        *net.TCPConn
	}
	var directions []direction
	for range 2 {
		sender, input := spliceSocketPair(t)
		output, reader := spliceSocketPair(t)
		if _, err := sender.Write(bytes.Repeat([]byte("x"), BufferSize)); err != nil {
			t.Fatal(err)
		}
		sender.CloseWrite()
		directions = append(directions, direction{input, output, reader})
	}
	errs := make(chan error, len(directions))
	for _, d := range directions {
		go func() {
			err := copyData(ctx, d.output, d.input, account, &count)
			d.output.Close()
			errs <- err
		}()
	}
	total := 0
	for _, d := range directions {
		d.reader.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := io.Copy(io.Discard, d.reader)
		if err != nil {
			t.Fatal(err)
		}
		total += int(n)
		if err = <-errs; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected exhausted allowance to stall until cancellation, got %v", err)
		}
	}
	if total != 8193 || count.Load() != 8193 || account.disk.Charged != 8193 {
		t.Fatalf("quota accounting: received=%d counter=%d charged=%d", total, count.Load(), account.disk.Charged)
	}
}
