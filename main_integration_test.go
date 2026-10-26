package main_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"apigo.cc/go/keys/lib"
	"apigo.cc/go/timer"
)

func TestExportCLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYSPATH", filepath.Join(dir, "store"))
	t.Setenv("MASTER_PASSWORD", "correct-password")
	ks, err := lib.CreateKeystore("test", []byte("correct-password"))
	if err != nil {
		t.Fatal(err)
	}
	ks.Close()
	tool := filepath.Join(dir, "keys_tool")
	cmd := exec.Command("go", "build", "-o", tool, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name, pwd string
		args      []string
		ok        bool
	}{
		{"success", "correct-password", []string{"export", "test", "go"}, true},
		{"wrong-password", "wrong", []string{"export", "test", "go"}, false},
		{"no-terminal", "", []string{"export", "test", "go"}, false},
		{"unknown-language", "correct-password", []string{"export", "test", "unknown"}, false},
		{"extra-argument", "correct-password", []string{"export", "test", "go", "extra"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MASTER_PASSWORD", tc.pwd)
			cmd := exec.Command(tool, tc.args...)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if tc.ok {
				if err != nil {
					t.Fatalf("export: %v: %s", err, stderr.String())
				}
				if !strings.HasPrefix(string(out), "package main") || stderr.Len() != 0 {
					t.Fatal("source output polluted")
				}
			} else {
				if err == nil || len(out) != 0 || stderr.Len() == 0 {
					t.Fatalf("failure contract: err=%v stdout bytes=%d stderr bytes=%d", err, len(out), stderr.Len())
				}
			}
		})
	}
}

func TestKeepKeyCLI(t *testing.T) {
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "keys-cli-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("TMPDIR", dir)
	t.Setenv("KEYSPATH", filepath.Join(dir, "store"))
	t.Setenv("MASTER_PASSWORD", "correct-password")
	for _, name := range []string{"one", "two"} {
		ks, err := lib.CreateKeystore(name, []byte("correct-password"))
		if err != nil {
			t.Fatal(err)
		}
		ks.Close()
	}
	tool := filepath.Join(dir, "keys_tool")
	cmd := exec.Command("go", "build", "-o", tool, ".")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	run := func(args ...string) (string, string, error) {
		cmd := exec.Command(tool, args...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}
	t.Cleanup(func() { _, _, _ = run("forget-key", "--all") })
	for _, args := range [][]string{{"keep-key", "one"}, {"keep-key", "two"}} {
		out, _, err := run(args...)
		if err != nil || out != "" {
			t.Fatalf("keep-key failed: %v", err)
		}
	}
	t.Setenv("MASTER_PASSWORD", "")
	for _, name := range []string{"one", "two"} {
		out, stderr, err := run("export", name, "go")
		if err != nil || !strings.HasPrefix(out, "package main") || stderr != "" {
			t.Fatalf("cached export: %v", err)
		}
	}
	t.Setenv("MASTER_PASSWORD", "wrong-password")
	if out, _, err := run("keep-key", "one"); err == nil || out != "" {
		t.Fatal("keep-key did not verify the password again")
	}
	t.Setenv("MASTER_PASSWORD", "")
	if _, _, err := run("export", "one", "go"); err != nil {
		t.Fatal("failed keep-key replaced a valid cache entry")
	}
	// Cache authorization applies to export only.
	if out, _, err := run("one", "list"); err == nil || out != "" {
		t.Fatal("password command used export cache")
	}
	for _, args := range [][]string{
		{"keep-key", "one", "--ttl", "0"}, {"keep-key", "one", "--ttl", "-1h"},
		{"keep-key", "one", "--ttl", ""}, {"keep-key", "one", "--ttl", "invalid"},
		{"keep-key", "one", "extra"}, {"forget-key", "--unknown"},
	} {
		if out, stderr, err := run(args...); err == nil || out != "" || stderr == "" {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
	if _, _, err := run("forget-key", "one"); err != nil {
		t.Fatal(err)
	}
	if out, _, err := run("export", "one", "go"); err == nil || out != "" {
		t.Fatal("forgotten key was exported")
	}
	if _, _, err := run("export", "two", "go"); err != nil {
		t.Fatal("forget-key removed another key")
	}
	if _, _, err := run("forget-key", "--all"); err != nil {
		t.Fatal(err)
	}
	if out, _, err := run("export", "two", "go"); err == nil || out != "" {
		t.Fatal("forget-key --all did not clear keys")
	}
	t.Setenv("MASTER_PASSWORD", "correct-password")
	if _, _, err := run("keep-key", "one", "--ttl", "150ms"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MASTER_PASSWORD", "")
	if err := timer.Retry(func() error {
		out, _, err := run("export", "one", "go")
		if err != nil && out == "" {
			return nil
		}
		return errors.New("cache has not expired")
	}, timer.WithMaxRetries(30), timer.WithBackoff(10*time.Millisecond, 1)); err != nil {
		t.Fatal(err)
	}
}
