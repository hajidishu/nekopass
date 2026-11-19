//go:build !linux

package agent

import "net"

func spliceStream(_, _ net.Conn, _ sendStreamChunk) (bool, error) { return false, nil }
