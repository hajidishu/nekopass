package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestH2RevocationClosesExistingTarget(t *testing.T) {
	for _, mode := range []string{"rule_removed", "key_rotated", "expired"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := listener.Accept()
				if err == nil {
					accepted <- c
				}
			}()
			engine, transport, cfg, rule := h2Fixture(t, listener.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			client, err := transport.Dial(ctx, ctx, rule, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var target net.Conn
			select {
			case target = <-accepted:
			case <-ctx.Done():
				t.Fatal("target not connected")
			}
			// Always unblock the handler even when reproducing the old defect.
			defer target.Close()
			switch mode {
			case "rule_removed":
				cfg.EgressRules = nil
			case "key_rotated":
				cfg.TunnelLinks[0].Token = strings.Repeat("b", 64)
			case "expired":
				cfg.EgressRules[0].ExpiresUnix = time.Now().Add(-time.Second).Unix()
			}
			if err = engine.Apply(cfg); err != nil {
				t.Fatal(err)
			}
			target.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
			_, err = target.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("revoked target still receiving data")
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("revocation left target socket open")
			}
		})
	}
}

func TestH2PayloadRequiresCompleteFramesAndFIN(t *testing.T) {
	frame := func(size uint32, payload string) []byte {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], size)
		return append(length[:], []byte(payload)...)
	}
	for _, data := range [][]byte{nil, frame(8, "short"), frame(3, "abc")} {
		reader := &h2PayloadReader{body: io.NopCloser(bytes.NewReader(data))}
		if _, err := io.ReadAll(reader); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal("truncated stream treated as normal FIN")
		}
	}
	valid := append(frame(3, "abc"), frame(0, "")...)
	reader := &h2PayloadReader{body: io.NopCloser(bytes.NewReader(valid))}
	if data, err := io.ReadAll(reader); err != nil || string(data) != "abc" {
		t.Fatal("valid FIN rejected", err)
	}
}

// A stale timer callback can run after Timer.Stop returns false. The callback
// must use the current deadline generation rather than closing a renewed stream.
func TestH2DeadlineCallbacksFromPreviousGenerationAreIgnored(t *testing.T) {
	for _, read := range []bool{true, false} {
		reader, writer := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		c := &h2StreamConn{r: reader, w: writer, cancel: cancel}
		defer c.Close()
		if err := c.setDeadline(time.Now().Add(time.Hour), read); err != nil {
			t.Fatal(err)
		}
		generation := c.writeGeneration
		if read {
			generation = c.readGeneration
		}
		if err := c.setDeadline(time.Time{}, read); err != nil {
			t.Fatal(err)
		}
		c.expireDeadline(read, generation)
		if c.closed || ctx.Err() != nil {
			t.Fatal("stale deadline killed renewed stream")
		}
		if err := c.setDeadline(time.Now().Add(10*time.Millisecond), read); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("current deadline ignored")
		}
	}
}
