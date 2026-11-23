package keyagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/api-go/keys/lib"
	"github.com/api-go/safe"
	"github.com/api-go/timer"
)

type Client struct{ root, endpoint string }

func New(root string) (*Client, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if resolved, e := filepath.EvalSymlinks(abs); e == nil {
		abs = resolved
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	endpoint, err := agentEndpoint(abs)
	if err != nil {
		return nil, err
	}
	return &Client{root: abs, endpoint: endpoint}, nil
}
func (c *Client) call(r request) ([]byte, error) {
	conn, err := dialAgent(c.endpoint)
	if err != nil {
		if errors.Is(err, errNotRunning) {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return nil, fmt.Errorf("connect key agent: %w", err)
	}
	defer conn.Close()
	if err := verifyPeer(conn, false); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	frame, err := encodeRequest(r)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(frame)
	if err := writeFrame(conn, frame, maxFrame); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	data, err := readFrame(conn, replyLimit(r.Op))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if data[0] != 0 {
		defer safe.ZeroMemory(data)
		if data[0] == 2 {
			return nil, ErrNotKept
		}
		if data[0] == 3 {
			return nil, ErrUnavailable
		}
		if string(data[1:]) == "unsupported agent operation" {
			switch r.Op {
			case opUnlockCipher:
				return nil, ErrUnavailable
			case opList:
				return nil, errors.New("旧版密钥代理不支持查询；请运行 keys forget-key --all 后重新保留密钥")
			}
		}
		return nil, fmt.Errorf("key agent: %s", data[1:])
	}
	return data[1:], nil
}

// Keep transfers only an already-unlocked key, never its master password.
// start is invoked only if the agent cannot be reached, typically StartProcess.
func (c *Client) Keep(ks *lib.KeySet, ttl time.Duration, start func() error) error {
	if ttl < 0 {
		return errors.New("TTL cannot be negative")
	}
	if ks == nil || ks.Name == "default" {
		return errors.New("a named keystore is required")
	}
	key, iv, err := ks.GetRaw()
	if err != nil {
		return err
	}
	defer safe.ZeroMemory(key)
	defer safe.ZeroMemory(iv)
	packed, err := lib.PackMemoryKey(key, iv)
	if err != nil {
		return err
	}
	defer safe.ZeroMemory(packed)
	if _, err := c.call(request{Op: opPing}); err != nil {
		if !errors.Is(err, ErrUnavailable) {
			return err
		}
		if start == nil {
			return err
		}
		if err := start(); err != nil {
			return err
		}
		if err := timer.Retry(func() error { _, err := c.call(request{Op: opPing}); return err }, timer.WithMaxRetries(60), timer.WithBackoff(50*time.Millisecond, 1)); err != nil {
			return fmt.Errorf("start key agent: %w", err)
		}
	}
	_, err = c.call(request{Op: opKeep, Name: ks.Name, TTL: int64(ttl), Fingerprint: ks.SourceFingerprint(), Secret: packed})
	return err
}
func (c *Client) Export(name, language string) (string, error) {
	data, err := c.call(request{Op: opExport, Name: name, Language: language})
	if err != nil {
		return "", err
	}
	defer safe.ZeroMemory(data)
	return string(data), nil
}

// UnlockCipher opens a temporary keyset for a cipher command. The caller closes it.
func (c *Client) UnlockCipher(name string) (*lib.KeySet, error) {
	data, err := c.call(request{Op: opUnlockCipher, Name: name})
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(data)
	return lib.OpenMemoryKeySet(name, data)
}

type KeptKey struct {
	Name    string
	Expires time.Time
}

// List returns only names and expiration times for currently usable keys.
func (c *Client) List() ([]KeptKey, error) {
	data, err := c.call(request{Op: opList})
	if errors.Is(err, errNotRunning) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []KeptKey
	for len(data) > 0 {
		nameLen := int(data[0])
		if nameLen == 0 || len(data) < 9+nameLen {
			return nil, errors.New("invalid agent list response")
		}
		entry := KeptKey{Name: string(data[9 : 9+nameLen])}
		if expiry := int64(binary.BigEndian.Uint64(data[1:9])); expiry != 0 {
			entry.Expires = time.Unix(expiry, 0)
		}
		entries = append(entries, entry)
		data = data[9+nameLen:]
	}
	return entries, nil
}

func (c *Client) Forget(name string, all bool) error {
	if !all && !validName(name) {
		return errors.New("invalid key name")
	}
	op := opForget
	if all {
		op = opForgetAll
	}
	_, err := c.call(request{Op: op, Name: name})
	if errors.Is(err, errNotRunning) {
		return nil
	}
	return err
}

// StartProcess launches the current CLI without inherited master-password data.
// The agent is not installed as a service and never reloads keys on startup.
func (c *Client) StartProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "__keys-agent", c.root)
	for _, env := range os.Environ() {
		name, _, _ := strings.Cut(env, "=")
		if !strings.EqualFold(name, "MASTER_PASSWORD") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	detachProcess(cmd)
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap short-lived startup losers while the parent remains alive.
	go func() { _ = cmd.Wait() }()
	return nil
}
