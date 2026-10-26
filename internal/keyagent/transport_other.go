//go:build !darwin && !linux && !windows

package keyagent

import (
	"net"
	"os/exec"
)

func agentEndpoint(string) (string, error)             { return "", ErrUnavailable }
func dialAgent(string) (net.Conn, error)               { return nil, ErrUnavailable }
func listenAgent(string) (net.Listener, func(), error) { return nil, nil, ErrUnavailable }
func detachProcess(*exec.Cmd)                          {}
func verifyPeer(net.Conn, bool) error                  { return ErrUnavailable }
