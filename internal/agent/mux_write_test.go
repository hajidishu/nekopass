package agent

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type muxWriteCapture struct {
	bytes.Buffer
	writes [][]byte
}

func (c *muxWriteCapture) Write(p []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(p))
	return c.Buffer.Write(p)
}
func (c *muxWriteCapture) Close() error                     { return nil }
func (c *muxWriteCapture) LocalAddr() net.Addr              { return nil }
func (c *muxWriteCapture) RemoteAddr() net.Addr             { return nil }
func (c *muxWriteCapture) SetDeadline(time.Time) error      { return nil }
func (c *muxWriteCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *muxWriteCapture) SetWriteDeadline(time.Time) error { return nil }

func TestMuxWriteCoalescesBodiesWithoutDelayingControl(t *testing.T) {
	raw := &muxWriteCapture{}
	c := &muxWriteConn{Conn: raw}
	var header [12]byte
	binary.BigEndian.PutUint32(header[4:], 1)
	body := bytes.Repeat([]byte{42}, 70000)
	binary.BigEndian.PutUint32(header[8:], uint32(len(body)))
	if _, err := c.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if len(raw.writes) != 0 {
		t.Fatal("standalone DATA header escaped")
	}
	if n, err := c.Write(body[:3]); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if len(raw.writes) != 1 || !bytes.Equal(raw.writes[0], append(header[:], body[:3]...)) {
		t.Fatal("header not coalesced with first partial body")
	}
	if n, err := c.Write(body[3:]); err != nil || n != len(body)-3 {
		t.Fatal(n, err)
	}
	control := make([]byte, 12)
	control[1] = 1
	prior := len(raw.writes)
	if _, err := c.Write(control); err != nil {
		t.Fatal(err)
	}
	if len(raw.writes) != prior+1 {
		t.Fatal("control frame was delayed")
	}
	if !bytes.Equal(raw.Bytes(), append(append(header[:], body...), control...)) {
		t.Fatal("stream bytes changed")
	}
}
