package padding

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestMuxPaddingContinuesBeyondStopAndLifetimeBudget(t *testing.T) {
	s, _ := Parse([]string{"stop=0"})
	raw := &memoryConn{}
	sender := NewMuxConn(raw, s)
	const count = 8192
	for i := 0; i < count; i++ {
		if n, err := sender.Write([]byte{byte(i)}); err != nil || n != 1 {
			t.Fatal(i, n, err)
		}
	}
	if raw.Len()-count <= MaxBudget {
		t.Fatal("test did not pass the former lifetime budget")
	}
	sizes := map[int]int{}
	for _, n := range raw.writes {
		sizes[n]++
		if n < overhead+2+1+1 || n > overhead+2+1+256 {
			t.Fatal("short write was not continuously shaped", n)
		}
	}
	if len(sizes) < 64 {
		t.Fatal("continuous short writes retained a fixed length", len(sizes))
	}
	if err := sender.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(NewMuxConn(raw, s))
	if err != nil || len(got) != count {
		t.Fatal("long-lived receiver refused valid frames", len(got), err)
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatal("padding changed payload", i)
		}
	}
}

func TestMuxPaddingExactLargeDataAndWireVersionIsolation(t *testing.T) {
	s, _ := Parse([]string{"stop=3", "1=100-400", "2=400-500,c,500-1000"})
	base := &memoryConn{}
	sender := NewMuxConn(base, s)
	payload := bytes.Repeat([]byte("mux-independent-data"), 10000)
	if n, err := sender.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	if err := sender.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	wire := bytes.Clone(base.Bytes())
	got, err := io.ReadAll(NewMuxConn(base, s))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch", err)
	}
	legacy := &memoryConn{}
	legacy.Buffer.Write(wire)
	if _, err := NewConn(legacy, s).Read(make([]byte, 1)); err == nil {
		t.Fatal("legacy reader silently accepted the new Mux wire format")
	}
	for _, size := range []int{0, 1, 257} {
		raw := &memoryConn{}
		h := header(shapedDataCommand, 2+1+size)
		raw.Buffer.Write(h[:])
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], 1)
		raw.Buffer.Write(n[:])
		raw.Buffer.Write(make([]byte, 1+size))
		_, err := NewMuxConn(raw, s).Read(make([]byte, 1))
		if size == 1 {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("unbounded or empty continuous padding accepted", size)
		}
	}
}
