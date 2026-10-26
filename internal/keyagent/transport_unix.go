//go:build darwin || linux

package keyagent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"apigo.cc/go/crypto"
	"apigo.cc/go/timer"
	"golang.org/x/sys/unix"
)

func agentEndpoint(root string) (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("keys-agent-%d", os.Geteuid()))
	return filepath.Join(dir, crypto.SHA256ToHex([]byte(root))[:24]+".sock"), nil
}
func secureDirectory(endpoint string, create bool) error {
	dir := filepath.Dir(endpoint)
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe key agent directory")
	}
	return nil
}
func dialAgent(endpoint string) (net.Conn, error) {
	if err := secureDirectory(endpoint, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNotRunning
		}
		return nil, err
	}
	conn, err := net.DialTimeout("unix", endpoint, 500*time.Millisecond)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, errNotRunning
	}
	return conn, err
}
func listenAgent(endpoint string) (net.Listener, func(), error) {
	if err := secureDirectory(endpoint, true); err != nil {
		return nil, nil, err
	}
	// This persistent file contains no credentials; the kernel lock is released
	// when the process exits, including crashes and reboot.
	lock, err := os.OpenFile(endpoint+".lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err := timer.Retry(func() error { return unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) }, timer.WithMaxRetries(40), timer.WithBackoff(25*time.Millisecond, 1)); err != nil {
		lock.Close()
		return nil, nil, err
	}
	fail := func(err error) (net.Listener, func(), error) { lock.Close(); return nil, nil, err }
	if info, err := os.Lstat(endpoint); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fail(errors.New("agent endpoint is not a socket"))
		}
		if err := os.Remove(endpoint); err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	if err := os.Chmod(endpoint, 0600); err != nil {
		ln.Close()
		return fail(err)
	}
	return ln, func() { ln.Close(); lock.Close() }, nil
}
func detachProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func verifyPeer(conn net.Conn, server bool) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("unexpected agent transport")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	var checkErr error
	err = raw.Control(func(fd uintptr) { checkErr = checkPeerUID(int(fd)) })
	if err != nil {
		return err
	}
	return checkErr
}
