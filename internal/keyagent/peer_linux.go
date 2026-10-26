package keyagent

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func checkPeerUID(fd int) error {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return err
	}
	if cred.Uid != uint32(os.Geteuid()) {
		return errors.New("key agent belongs to another user")
	}
	return nil
}
