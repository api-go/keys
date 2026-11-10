package keyagent_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/api-go/file"
	"github.com/api-go/keys/internal/keyagent"
	"github.com/api-go/keys/lib"
	"github.com/api-go/timer"
)

func TestAgentHelper(t *testing.T) {
	root := os.Getenv("KEYS_TEST_AGENT_ROOT")
	if root == "" {
		return
	}
	client, err := keyagent.New(root)
	if err != nil {
		os.Exit(2)
	}
	if err := client.Serve(context.Background()); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

type fixture struct {
	client   *keyagent.Client
	start    func() error
	store    string
	password []byte
	crash    func()
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("agent transport unsupported")
	}
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "keys-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("TMPDIR", dir)
	store := filepath.Join(dir, "store")
	t.Setenv("KEYSPATH", store)
	t.Setenv("MASTER_PASSWORD", "")
	password := []byte("fixture master password")
	for _, name := range []string{"one", "two"} {
		ks, err := lib.CreateKeystore(name, password)
		if err != nil {
			t.Fatal(err)
		}
		ks.Close()
	}
	client, err := keyagent.New(store)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var processes []*exec.Cmd
	start := func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAgentHelper$")
		cmd.Env = append(os.Environ(), "KEYS_TEST_AGENT_ROOT="+store)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		mu.Lock()
		processes = append(processes, cmd)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		_ = client.Forget("", true)
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range processes {
			if cmd.ProcessState == nil {
				done := make(chan struct{})
				go func() { _ = cmd.Wait(); close(done) }()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				select {
				case <-done:
				case <-ctx.Done():
					_ = cmd.Process.Kill()
					<-done
				}
				cancel()
			}
			if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 66 {
				t.Error("agent subprocess failed the race detector")
			}
		}
	})
	crash := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, cmd := range processes {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	return fixture{client: client, start: start, store: store, password: password, crash: crash}
}
func (f fixture) keep(t testing.TB, name string, ttl time.Duration) {
	t.Helper()
	ks, err := lib.LoadKeystore(name, f.password)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	if err := f.client.Keep(ks, ttl, f.start); err != nil {
		t.Fatal(err)
	}
}
func assertKept(t *testing.T, c *keyagent.Client, name string) {
	t.Helper()
	code, err := c.Export(name, "go")
	if err != nil || !strings.HasPrefix(code, "package main") {
		t.Fatalf("cached export failed: %v", err)
	}
}
func assertNotKept(t *testing.T, c *keyagent.Client, name string) {
	t.Helper()
	code, err := c.Export(name, "go")
	if code != "" || (!errors.Is(err, keyagent.ErrNotKept) && !errors.Is(err, keyagent.ErrUnavailable)) {
		t.Fatalf("expected cache miss, got %v", err)
	}
}

func TestKeepExportForget(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 0)
	f.keep(t, "two", 0)
	other, err := keyagent.New(f.store)
	if err != nil {
		t.Fatal(err)
	}
	assertKept(t, other, "one")
	assertKept(t, other, "two")
	if err := other.Forget("one", false); err != nil {
		t.Fatal(err)
	}
	assertNotKept(t, f.client, "one")
	assertKept(t, f.client, "two")
	if err := other.Forget("", true); err != nil {
		t.Fatal(err)
	}
	assertNotKept(t, f.client, "two")
	// A newly started agent must never recover the other key from disk.
	f.keep(t, "one", 0)
	assertKept(t, f.client, "one")
	assertNotKept(t, f.client, "two")
}
func TestKeptKeyExpiry(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 50*time.Millisecond)
	err := timer.Retry(func() error {
		_, err := f.client.Export("one", "go")
		if errors.Is(err, keyagent.ErrNotKept) {
			return nil
		}
		return errors.New("still kept")
	}, timer.WithMaxRetries(50), timer.WithBackoff(10*time.Millisecond, 1))
	if err != nil {
		t.Fatal(err)
	}
	assertNotKept(t, f.client, "one")
}
func TestKeptSourceInvalidation(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 0)
	path := filepath.Join(f.store, "keystore", "one")
	original, err := file.ReadBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[len(changed)-1] ^= 1
	if err := file.WriteBytes(path, changed); err != nil {
		t.Fatal(err)
	}
	assertNotKept(t, f.client, "one")
	if err := file.WriteBytes(path, original); err != nil {
		t.Fatal(err)
	}
	// Restoring the old source cannot resurrect an invalidated cache entry.
	assertNotKept(t, f.client, "one")
	ks, err := lib.LoadKeystore("one", f.password)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	if err := file.WriteBytes(path, changed); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Keep(ks, 0, f.start); err == nil {
		t.Fatal("source changed during unlock was accepted")
	}
}
func TestKeptStoreIsolation(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 0)
	other, err := keyagent.New(filepath.Join(filepath.Dir(f.store), "other"))
	if err != nil {
		t.Fatal(err)
	}
	assertNotKept(t, other, "one")
}
func TestConcurrentKeep(t *testing.T) {
	f := newFixture(t)
	ks, err := lib.LoadKeystore("one", f.password)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- f.client.Keep(ks, time.Hour, f.start) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertKept(t, f.client, "one")
}

func TestAgentCrashDropsKeys(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 0)
	f.keep(t, "two", 0)
	f.crash()
	assertNotKept(t, f.client, "one")
	f.keep(t, "one", 0)
	assertKept(t, f.client, "one")
	assertNotKept(t, f.client, "two")
}

func BenchmarkKeptExport(b *testing.B) {
	f := newFixture(b)
	f.keep(b, "one", 0)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := f.client.Export("one", "go"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAgentRejectsInheritedPassword(t *testing.T) {
	f := newFixture(t)
	t.Setenv("MASTER_PASSWORD", "must-not-be-in-agent-environment")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := f.client.Serve(ctx); err == nil {
		t.Fatal("agent accepted an inherited master password")
	}
}

func TestKeepReplacesExpiry(t *testing.T) {
	f := newFixture(t)
	f.keep(t, "one", 50*time.Millisecond)
	f.keep(t, "one", 0)
	done := make(chan struct{})
	timer.NewDebouncer(75*time.Millisecond, func() { close(done) }).Trigger()
	<-done
	assertKept(t, f.client, "one")
}
