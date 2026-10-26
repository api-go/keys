//go:build darwin || linux

package keyagent_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"apigo.cc/go/crypto"
	"apigo.cc/go/file"
)

func TestAgentSocketAndMalformedRequests(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 0)
	root, err := filepath.EvalSymlinks(f.store)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("keys-agent-%d", os.Geteuid()))
	endpoint := filepath.Join(dir, crypto.SHA256ToHex([]byte(root))[:24]+".sock")
	for path, want := range map[string]os.FileMode{dir: 0700, endpoint: 0600, endpoint + ".lock": 0600} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("permissions of %s: %o", filepath.Base(path), info.Mode().Perm())
		}
	}
	lock, err := file.ReadBytes(endpoint + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(lock) != 0 {
		t.Fatal("lock file contains unexpected data")
	}
	for _, frame := range [][]byte{{0, 1, 0, 1}, {0, 0, 0, 1, 0}, {0, 0, 0, 0}} {
		conn, err := net.Dial("unix", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
		var header [4]byte
		if _, err := io.ReadFull(conn, header[:]); err == nil {
			length := binary.BigEndian.Uint32(header[:])
			if length > 1024 {
				t.Fatal("unbounded error response")
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(conn, body); err != nil {
				t.Fatal(err)
			}
			if len(body) == 0 || body[0] != 1 {
				t.Fatal("malformed request accepted")
			}
		}
		conn.Close()
		assertKept(t, f.client, "one")
	}
	// Refuse discovery through a runtime directory accessible to other users.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Export("one", "go"); err == nil {
		t.Fatal("unsafe directory accepted")
	}
	if err := f.client.Forget("", true); err == nil {
		t.Fatal("reported cleared despite inaccessible agent")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	assertKept(t, f.client, "one")
}
