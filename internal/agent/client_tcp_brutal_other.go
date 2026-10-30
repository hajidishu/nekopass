//go:build !linux

package agent

import (
	"errors"
	"net"
)

type systemClientTCPKernel struct{}

func (systemClientTCPKernel) Apply(*net.TCPConn, uint64, uint64) (clientTCPOriginal, error) {
	return clientTCPOriginal{}, errors.New("TCP Brutal is unavailable")
}
func (systemClientTCPKernel) Restore(*net.TCPConn, clientTCPOriginal) error {
	return errors.New("TCP Brutal is unavailable")
}
