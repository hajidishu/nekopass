package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type testClientTCPSocketOptions struct {
	current                 string
	params                  []byte
	failParams, failRestore bool
}

func (s *testClientTCPSocketOptions) algorithm() (string, error) { return s.current, nil }
func (s *testClientTCPSocketOptions) setAlgorithm(algorithm string) error {
	if s.failRestore && algorithm != "brutal" {
		return unix.EPERM
	}
	s.current = algorithm
	return nil
}
func (s *testClientTCPSocketOptions) parameters() ([]byte, error) { return bytes.Clone(s.params), nil }
func (s *testClientTCPSocketOptions) setParameters(data []byte) error {
	if s.failParams {
		return unix.EPERM
	}
	s.params = bytes.Clone(data)
	return nil
}

func TestClientTCPKernelUsesPackedV2ParametersAndRestoresPreviousSettings(t *testing.T) {
	socket := &testClientTCPSocketOptions{current: "cubic"}
	original, err := clientTCPApplySocket(socket, 12500000, 456)
	if err != nil {
		t.Fatal(err)
	}
	if socket.current != "brutal" || len(socket.params) != 20 || binary.NativeEndian.Uint64(socket.params) != 12500000 || binary.NativeEndian.Uint32(socket.params[8:]) != 20 || binary.NativeEndian.Uint64(socket.params[12:]) != 456 {
		t.Fatal("incorrect kernel ABI", socket.params)
	}
	if err := clientTCPRestoreSocket(socket, original); err != nil || socket.current != "cubic" {
		t.Fatal(err)
	}
	socket.current = "brutal"
	old := bytes.Clone(socket.params)
	original, err = clientTCPApplySocket(socket, 25000000, 999)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTCPRestoreSocket(socket, original); err != nil || !bytes.Equal(socket.params, old) {
		t.Fatal("existing manual Brutal configuration was lost", err)
	}
}
func TestClientTCPKernelParameterFailureRollsBackAlgorithm(t *testing.T) {
	socket := &testClientTCPSocketOptions{current: "cubic", failParams: true}
	if _, err := clientTCPApplySocket(socket, 1250000, 17); err == nil || socket.current != "cubic" {
		t.Fatal("partial kernel setup remained active", err)
	}
	socket.failRestore = true
	if _, err := clientTCPApplySocket(socket, 1250000, 17); !errors.Is(err, errClientTCPRestore) {
		t.Fatal("rollback failure not reported", err)
	}
}
func TestClientTCPKernelSocketAdapterPreservesExistingAlgorithm(t *testing.T) {
	server, client := clientTCPPair(t)
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var before, after string
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		before, optionErr = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	}); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	original, err := (systemClientTCPKernel{}).Apply(server, 1250000, 123)
	if err == nil {
		if err := (systemClientTCPKernel{}).Restore(server, original); err != nil {
			t.Fatal(err)
		}
	} else if errors.Is(err, errClientTCPRestore) {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		after, optionErr = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	}); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if before != after {
		t.Fatal("socket adapter did not restore the original algorithm", before, after)
	}
	if _, err := server.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := client.Read(b[:]); err != nil || b[0] != 'x' {
		t.Fatal(err)
	}
}
