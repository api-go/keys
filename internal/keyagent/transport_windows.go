package keyagent

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/api-go/crypto"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func logonSID(token windows.Token) (string, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return "", err
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			return group.Sid.String(), nil
		}
	}
	return "", errors.New("cannot determine Windows logon identity")
}
func agentEndpoint(root string) (string, error) {
	sid, err := logonSID(windows.GetCurrentProcessToken())
	if err != nil {
		return "", err
	}
	return `\\.\pipe\keys-agent-` + crypto.SHA256ToHex([]byte(root+"\x00"+sid)), nil
}
func dialAgent(endpoint string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, endpoint)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil, errNotRunning
	}
	return conn, err
}
func listenAgent(endpoint string) (net.Listener, func(), error) {
	sid, err := logonSID(windows.GetCurrentProcessToken())
	if err != nil {
		return nil, nil, err
	}
	// Protected DACL, current logon only. go-winio also rejects remote clients
	// and creates the first instance exclusively, avoiding pipe-name squatting.
	ln, err := winio.ListenPipe(endpoint, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")"})
	if err != nil {
		return nil, nil, err
	}
	return ln, func() { ln.Close() }, nil
}
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS, HideWindow: true}
}
func verifyPeer(conn net.Conn, server bool) error {
	pipe, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("unexpected agent transport")
	}
	var pid uint32
	var err error
	if server {
		err = windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid)
	} else {
		err = windows.GetNamedPipeServerProcessId(windows.Handle(pipe.Fd()), &pid)
	}
	if err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	peer, err := logonSID(token)
	if err != nil {
		return err
	}
	self, err := logonSID(windows.GetCurrentProcessToken())
	if err != nil {
		return err
	}
	if peer != self {
		return errors.New("key agent belongs to another logon session")
	}
	return nil
}
