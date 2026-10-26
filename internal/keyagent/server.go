package keyagent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"apigo.cc/go/crypto"
	"apigo.cc/go/keys/lib"
	"apigo.cc/go/safe"
	"apigo.cc/go/timer"
)

type entry struct {
	secret      *safe.SafeBuf
	fingerprint [32]byte
	expires     time.Time
}
type server struct {
	mu        sync.Mutex
	client    *Client
	listener  net.Listener
	entries   map[string]*entry
	closed    bool
	idleSince time.Time
}

func validName(name string) bool {
	return name != "" && !strings.HasPrefix(name, ".") && filepath.IsLocal(name) && !strings.ContainsAny(name, `/\:`) && name != "default"
}
func (c *Client) fingerprint(name string) ([32]byte, error) {
	var result [32]byte
	if !validName(name) {
		return result, errors.New("invalid key name")
	}
	root, err := os.OpenRoot(c.root)
	if err != nil {
		return result, err
	}
	defer root.Close()
	store, err := root.OpenRoot("keystore")
	if err != nil {
		return result, err
	}
	defer store.Close()
	data, err := store.ReadFile(name)
	if err != nil {
		return result, err
	}
	copy(result[:], crypto.SHA256(data))
	return result, nil
}

// Serve blocks until ctx ends, forget-key --all is received, or the empty agent
// reaches its idle timeout. No persisted state is loaded by a new process.
func (c *Client) Serve(ctx context.Context) error {
	if os.Getenv("MASTER_PASSWORD") != "" {
		return errors.New("agent must not inherit MASTER_PASSWORD")
	}
	if err := safe.DisableCoreDump(); err != nil {
		return err
	}
	ln, cleanup, err := listenAgent(c.endpoint)
	if err != nil {
		return err
	}
	defer cleanup()
	s := &server{client: c, listener: ln, entries: make(map[string]*entry), idleSince: time.Now()}
	defer s.close()
	stop := context.AfterFunc(ctx, s.close)
	defer stop()
	var sweep *timer.Debouncer
	sweep = timer.NewDebouncer(time.Second, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return
		}
		now := time.Now()
		for name, e := range s.entries {
			if !e.expires.IsZero() && !now.Before(e.expires) {
				s.remove(name)
			}
		}
		if len(s.entries) == 0 {
			if s.idleSince.IsZero() {
				s.idleSince = now
			}
			if now.Sub(s.idleSince) >= 30*time.Second {
				s.closed = true
				_ = s.listener.Close()
				return
			}
		}
		sweep.Trigger()
	})
	sweep.Trigger()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.handle(conn)
	}
}
func (s *server) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.listener.Close()
	for name := range s.entries {
		s.remove(name)
	}
}
func (s *server) remove(name string) {
	if e := s.entries[name]; e != nil {
		e.secret.Close()
		delete(s.entries, name)
	}
}
func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if err := verifyPeer(conn, true); err != nil {
		return
	}
	frame, err := readFrame(conn)
	if err != nil {
		return
	}
	defer safe.ZeroMemory(frame)
	r, err := decodeRequest(frame)
	if err != nil {
		_ = writeFrame(conn, append([]byte{1}, []byte("invalid agent request")...))
		return
	}
	s.mu.Lock()
	data, err, stop := s.apply(r)
	s.mu.Unlock()
	status := byte(0)
	if err != nil {
		status = 1
		if errors.Is(err, ErrNotKept) {
			status = 2
		}
		if errors.Is(err, ErrUnavailable) {
			status = 3
		}
		data = []byte(err.Error())
	}
	reply := append([]byte{status}, data...)
	defer safe.ZeroMemory(reply)
	defer safe.ZeroMemory(data)
	_ = writeFrame(conn, reply)
	if stop {
		s.close()
	}
}
func (s *server) apply(r request) ([]byte, error, bool) {
	if s.closed {
		return nil, ErrUnavailable, false
	}
	switch r.Op {
	case opPing:
		return nil, nil, false
	case opKeep:
		if !validName(r.Name) || len(r.Secret) != lib.MemoryKeySize || r.TTL < 0 {
			return nil, errors.New("invalid keep request"), false
		}
		fingerprint, err := s.client.fingerprint(r.Name)
		if err != nil || fingerprint != r.Fingerprint {
			return nil, errors.New("key file changed; unlock it again"), false
		}
		key, iv, err := lib.UnpackMemoryKey(r.Secret)
		if err != nil {
			return nil, err, false
		}
		safe.ZeroMemory(key)
		safe.ZeroMemory(iv)
		if len(s.entries) >= 1024 && s.entries[r.Name] == nil {
			return nil, errors.New("too many kept keys"), false
		}
		s.remove(r.Name)
		e := &entry{secret: safe.NewSafeBuf(r.Secret), fingerprint: fingerprint}
		if r.TTL > 0 {
			e.expires = time.Now().Add(time.Duration(r.TTL))
		}
		s.entries[r.Name] = e
		s.idleSince = time.Time{}
		return nil, nil, false
	case opExport:
		if !validName(r.Name) {
			return nil, errors.New("invalid key name"), false
		}
		e := s.entries[r.Name]
		if e == nil {
			return nil, ErrNotKept, false
		}
		if !e.expires.IsZero() && !time.Now().Before(e.expires) {
			s.remove(r.Name)
			return nil, ErrNotKept, false
		}
		fingerprint, err := s.client.fingerprint(r.Name)
		if err != nil || fingerprint != e.fingerprint {
			s.remove(r.Name)
			return nil, ErrNotKept, false
		}
		plain := e.secret.Open()
		defer plain.Close()
		key, iv, err := lib.UnpackMemoryKey(plain.Data)
		if err != nil {
			s.remove(r.Name)
			return nil, err, false
		}
		defer safe.ZeroMemory(key)
		defer safe.ZeroMemory(iv)
		code, err := lib.MakeCode(r.Language, key, iv)
		if err != nil {
			return nil, err, false
		}
		return []byte(code), nil, false
	case opForget:
		if !validName(r.Name) {
			return nil, errors.New("invalid key name"), false
		}
		s.remove(r.Name)
		if len(s.entries) == 0 {
			s.idleSince = time.Now()
		}
		return nil, nil, false
	case opForgetAll:
		for name := range s.entries {
			s.remove(name)
		}
		return nil, nil, true
	default:
		return nil, errors.New("unsupported agent operation"), false
	}
}
