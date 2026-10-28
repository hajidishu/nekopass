package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func waitH3PoolRemoved(t *testing.T, transport *h3Transport, key string) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		transport.mu.Lock()
		pool := transport.pools[key]
		transport.mu.Unlock()
		if pool == nil {
			return
		}
		if time.Now().After(until) {
			t.Fatal("retired pool was not collected after its last lease")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestH3PoolRetirementCollectsLastLease(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, rule := h3Fixture(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	first, err := h.h3.Dial(ctx, ctx, rule, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := h.h3.Dial(ctx, ctx, rule, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	key := h2PoolKey(rule)
	pool := h.h3.pools[key]
	peer := pool.peers[0]
	h.h3.Prune(nil)
	first.Close()
	if peer.conn.Context().Err() != nil {
		t.Fatal("retirement closed another stream's connection")
	}
	second.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 5)
	if _, err := io.ReadFull(second, body); err != nil || string(body) != "alive" {
		t.Fatal("active stream did not survive retirement", err)
	}

	second.Close()
	waitH3PoolRemoved(t, h.h3, key)
	if peer.conn.Context().Err() == nil {
		t.Fatal("retired QUIC peer survived collection")
	}
}

func TestH3DetachedPoolCannotDialAfterPrune(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, rule := h3Fixture(t, target)
	key := h2PoolKey(rule)
	// This is the deterministic interleaving of Dial's map lookup and reserve:
	// Prune runs after the caller has obtained its pool pointer.
	pool := &h3Pool{}
	h.h3.mu.Lock()
	h.h3.pools[key] = pool
	h.h3.mu.Unlock()
	h.h3.Prune(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peer, release, _, err := pool.reserve(ctx, rule)
	if err == nil {
		release()
		peer.conn.CloseWithError(0, "")
		t.Fatal("detached pool established an unmanaged connection")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestH3PoolRetirementCanBeCancelled(t *testing.T) {
	target, _ := inboundEcho(t, false)
	_, h, _, rule := h3Fixture(t, target)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	first, err := h.h3.Dial(ctx, ctx, rule, target, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	key := h2PoolKey(rule)
	pool := h.h3.pools[key]
	h.h3.Prune(nil)
	wanted := proto.Clone(rule).(*pb.Rule)
	wanted.Enabled = true
	h.h3.Prune([]*pb.Rule{wanted})
	second, err := h.h3.Dial(ctx, ctx, wanted, target, false, nil)
	if err != nil {
		t.Fatal("wanted pool stayed retired", err)
	}
	defer second.Close()
	if h.h3.pools[key] != pool {
		t.Fatal("reintroduced pool lost its live connections")
	}
	first.Close()
	second.Close()
	h.h3.Prune(nil)
	waitH3PoolRemoved(t, h.h3, key)
}

func TestH3PoolRetirementDrainsReverseHalfClose(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	result := make(chan []byte, 1)
	go func() {
		raw, err := target.Accept()
		if err != nil {
			result <- nil
			return
		}
		defer raw.Close()
		conn := raw.(*net.TCPConn)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write(bytes.Repeat([]byte("response"), 10000))
		conn.CloseWrite()
		body, _ := io.ReadAll(conn)
		result <- body
	}()
	_, h, _, rule := h3Fixture(t, target.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := h.h3.Dial(ctx, ctx, rule, target.Addr().String(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h.h3.Prune(nil)
	if response, err := io.ReadAll(conn); err != nil || len(response) != 80000 {
		t.Fatal("response FIN", len(response), err)
	}
	payload := bytes.Repeat([]byte("upload-after-response-fin"), 300000)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*h3StreamConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case got := <-result:
		if !bytes.Equal(got, payload) {
			t.Fatal("retirement truncated queued upload", len(got), len(payload))
		}
	case <-ctx.Done():
		t.Fatal("target did not receive upload FIN")
	}
	waitH3PoolRemoved(t, h.h3, h2PoolKey(rule))
}
