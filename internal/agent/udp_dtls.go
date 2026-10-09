package agent

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DTLS is a record/datagram transport, not a reliable byte stream. Each
// application fragment therefore carries its own message ID and position.
type dtlsDatagram struct {
	net.Conn
	readMu, writeMu sync.Mutex
	next            atomic.Uint32
	parts           map[uint32]*udpParts
	queued          *atomic.Int64
}

func newDTLSDatagram(c net.Conn, queued *atomic.Int64) *dtlsDatagram {
	return &dtlsDatagram{Conn: c, parts: map[uint32]*udpParts{}, queued: queued}
}
func (c *dtlsDatagram) Write(b []byte) (int, error) {
	if len(b) > maxDatagram {
		return 0, errors.New("DTLS datagram too large")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	id := c.next.Add(1)
	count := max(1, (len(b)+899)/900)
	for index := 0; index < count; index++ {
		part := b[min(len(b), index*900):min(len(b), (index+1)*900)]
		record := make([]byte, 8+len(part))
		binary.BigEndian.PutUint32(record[:4], id)
		binary.BigEndian.PutUint16(record[4:6], uint16(index))
		binary.BigEndian.PutUint16(record[6:8], uint16(count))
		copy(record[8:], part)
		n, err := c.Conn.Write(record)
		if err != nil {
			return 0, err
		}
		if n != len(record) {
			return 0, errors.New("short DTLS record")
		}
	}
	return len(b), nil
}
func (c *dtlsDatagram) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	record := make([]byte, 8192)
	for {
		n, err := c.Conn.Read(record)
		if err != nil {
			return 0, err
		}
		if n < 8 || n > 908 {
			continue
		}
		now := time.Now()
		for id, p := range c.parts {
			if p.expires.Before(now) {
				c.queued.Add(-int64(p.bytes))
				delete(c.parts, id)
			}
		}
		id := binary.BigEndian.Uint32(record[:4])
		index, count := int(binary.BigEndian.Uint16(record[4:6])), int(binary.BigEndian.Uint16(record[6:8]))
		if count < 1 || count > 73 || index >= count {
			continue
		}
		parts := c.parts[id]
		if parts == nil {
			if len(c.parts) >= 8 {
				continue
			}
			parts = &udpParts{fragments: make([][]byte, count), expires: now.Add(3 * time.Second)}
			c.parts[id] = parts
		}
		if len(parts.fragments) != count || parts.fragments[index] != nil || parts.bytes+n-8 > maxDatagram {
			continue
		}
		if c.queued.Add(int64(n-8)) > maxQueuedUDPBytes {
			c.queued.Add(-int64(n - 8))
			continue
		}
		parts.fragments[index] = append([]byte{}, record[8:n]...)
		parts.bytes += n - 8
		parts.seen++
		if parts.seen == count {
			delete(c.parts, id)
			c.queued.Add(-int64(parts.bytes))
			if parts.bytes > len(b) {
				return 0, errors.New("DTLS receive buffer too small")
			}
			offset := 0
			for _, part := range parts.fragments {
				offset += copy(b[offset:], part)
			}
			return offset, nil
		}
	}
}
func (c *dtlsDatagram) Close() error {
	err := c.Conn.Close()
	c.readMu.Lock()
	for _, p := range c.parts {
		c.queued.Add(-int64(p.bytes))
	}
	c.parts = map[uint32]*udpParts{}
	c.readMu.Unlock()
	return err
}
