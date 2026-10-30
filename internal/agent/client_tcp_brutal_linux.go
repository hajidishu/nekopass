package agent

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tcpBrutalParamsOption = 23301

type systemClientTCPKernel struct{}
type clientTCPSocketOptions interface {
	algorithm() (string, error)
	setAlgorithm(string) error
	parameters() ([]byte, error)
	setParameters([]byte) error
}
type linuxClientTCPSocket struct{ fd int }

func (s linuxClientTCPSocket) algorithm() (string, error) {
	return unix.GetsockoptString(s.fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
}
func (s linuxClientTCPSocket) setAlgorithm(value string) error {
	return unix.SetsockoptString(s.fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, value)
}
func (s linuxClientTCPSocket) parameters() ([]byte, error) {
	data := make([]byte, 20)
	size := uint32(len(data))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s.fd), unix.IPPROTO_TCP, tcpBrutalParamsOption, uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, errno
	}
	if size != 20 {
		return nil, errors.New("unsupported TCP Brutal parameter size")
	}
	return data, nil
}
func (s linuxClientTCPSocket) setParameters(data []byte) error {
	if len(data) != 20 {
		return unix.EINVAL
	}
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s.fd), unix.IPPROTO_TCP, tcpBrutalParamsOption, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func clientTCPApplySocket(socket clientTCPSocketOptions, rate, group uint64) (clientTCPOriginal, error) {
	var original clientTCPOriginal
	if rate == 0 || rate > 125000000000 || group == 0 {
		return original, errors.New("invalid TCP Brutal rate or group")
	}
	var err error
	original.algorithm, err = socket.algorithm()
	if err != nil {
		return original, err
	}
	if original.algorithm == "brutal" {
		original.parameters, err = socket.parameters()
		if err != nil {
			return original, err
		}
	}
	if err = socket.setAlgorithm("brutal"); err != nil {
		return original, err
	}
	data := make([]byte, 20)
	binary.NativeEndian.PutUint64(data, rate)
	binary.NativeEndian.PutUint32(data[8:], 20)
	binary.NativeEndian.PutUint64(data[12:], group)
	if err = socket.setParameters(data); err != nil {
		if restoreErr := clientTCPRestoreSocket(socket, original); restoreErr != nil {
			return original, errors.Join(err, errClientTCPRestore, restoreErr)
		}
		return original, err
	}
	return original, nil
}
func clientTCPRestoreSocket(socket clientTCPSocketOptions, original clientTCPOriginal) error {
	if err := socket.setAlgorithm(original.algorithm); err != nil {
		return err
	}
	if original.algorithm == "brutal" {
		return socket.setParameters(original.parameters)
	}
	return nil
}
func (systemClientTCPKernel) Apply(conn *net.TCPConn, rate, group uint64) (clientTCPOriginal, error) {
	var original clientTCPOriginal
	raw, err := conn.SyscallConn()
	if err != nil {
		return original, err
	}
	var operationErr error
	if err = raw.Control(func(fd uintptr) {
		original, operationErr = clientTCPApplySocket(linuxClientTCPSocket{int(fd)}, rate, group)
	}); err != nil {
		return original, err
	}
	return original, operationErr
}
func (systemClientTCPKernel) Restore(conn *net.TCPConn, original clientTCPOriginal) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	if err = raw.Control(func(fd uintptr) { operationErr = clientTCPRestoreSocket(linuxClientTCPSocket{int(fd)}, original) }); err != nil {
		return err
	}
	return operationErr
}
