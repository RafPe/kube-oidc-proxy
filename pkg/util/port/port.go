// Copyright Jetstack Ltd. See LICENSE for details.

// Package port provides helpers for discovering free TCP ports, primarily for
// tests that need to bind ephemeral listeners.
package port

import (
	"net"
	"strconv"
)

// Free asks the kernel for a free ephemeral TCP port on the loopback interface
// and returns it as a string. The port is released before Free returns, so
// there is an inherent race: another process may claim it before the caller
// binds.
func Free() (string, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = l.Close() }()

	port := l.Addr().(*net.TCPAddr).Port
	return strconv.Itoa(port), nil
}
