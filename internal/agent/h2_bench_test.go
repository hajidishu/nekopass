package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

// Loopback measures implementation overhead only, never real cross-border or
// NIC throughput. Transfers reuse the same authenticated HTTP/2 streams.
func BenchmarkH2Bulk(b *testing.B) {
	for _, streams := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("streams_%d", streams), func(b *testing.B) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { target.Close() })
			go func() {
				for {
					conn, err := target.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); io.Copy(conn, conn) }()
				}
			}()
			_, transport, _, rule := h2Fixture(b, target.Addr().String())
			ctx, cancel := context.WithCancel(context.Background())
			b.Cleanup(cancel)
			connections := make([]net.Conn, streams)
			for i := range streams {
				connections[i], err = transport.Dial(ctx, ctx, rule, target.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { connections[i].Close() })
			}
			payload := make([]byte, 1<<20)
			buffers := make([][]byte, streams)
			for i := range streams {
				buffers[i] = make([]byte, len(payload))
			}
			b.SetBytes(int64(streams * len(payload) * 2))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var wg sync.WaitGroup
				results := make(chan error, streams)
				for i := range streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := connections[i].Write(payload)
						if err == nil {
							_, err = io.ReadFull(connections[i], buffers[i])
						}
						results <- err
					}()
				}
				wg.Wait()
				for range streams {
					if err := <-results; err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
