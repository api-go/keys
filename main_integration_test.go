package main_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/api-go/keys/lib"
	"github.com/api-go/timer"
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
	runInput := func(input string, args ...string) (string, string, error) {
		cmd := exec.Command(tool, args...)
		cmd.Stdin = strings.NewReader(input)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		return string(out), stderr.String(), err
	}
	run := func(args ...string) (string, string, error) { return runInput("", args...) }
	t.Cleanup(func() { _, _, _ = run("forget-key", "--all") })
	checkEmpty := func() {
		t.Helper()
		out, stderr, err := run("list-keep-key")
		if err != nil || stderr != "" || !strings.Contains(out, "当前没有保留的密钥") {
			t.Fatalf("expected empty cache, got %q %q %v", out, stderr, err)
		}
	}
	checkEmpty()
	for _, args := range [][]string{{"keep-key", "one"}, {"keep-key", "two", "--ttl", "1d"}} {
		out, _, err := run(args...)
		if err != nil || out != "" {
			t.Fatalf("keep-key failed: %v", err)
		}
	}
	t.Setenv("MASTER_PASSWORD", "")
	out, stderr, err := run("--non-interactive", "list-keep-key")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil || stderr != "" || len(lines) != 3 {
		t.Fatalf("list kept keys: %q %q %v", out, stderr, err)
	}
	for i, name := range []string{"one", "two"} {
		gotName, expiryText, _ := strings.Cut(lines[i+1], "\t")
		expiry, err := time.Parse(time.RFC3339, expiryText)
		remaining := time.Until(expiry)
		if gotName != fmt.Sprintf("%q", name) || err != nil || remaining > 24*time.Hour || remaining < 24*time.Hour-time.Minute {
			t.Fatalf("unexpected cache entry: %q", lines[i+1])
		}
	}
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
	input := "  first line\nsecond line\x00\n"
	for _, name := range []string{"default", "one"} {
		enc, stderr, err := runInput(input, name, "encrypt")
		if err != nil || enc == "" || stderr != "" {
			t.Fatalf("pipe encrypt with %s: %v %s", name, err, stderr)
		}
		dec, stderr, err := runInput(enc, name, "decrypt")
		if err != nil || dec != input || stderr != "" {
			t.Fatalf("pipe decrypt with %s: %v %s (got %q)", name, err, stderr, dec)
		}
	}
	// Listing retains its own authentication.
	if out, _, err := run("one", "list"); err == nil || out != "" {
		t.Fatal("password command used export cache")
	}
	for _, args := range [][]string{
		{"keep-key", "one", "--ttl", "0"}, {"keep-key", "one", "--ttl", "-1h"},
		{"keep-key", "one", "--ttl", ""}, {"keep-key", "one", "--ttl", "invalid"},
		{"keep-key", "one", "extra"}, {"forget-key", "--unknown"},
		{"keep-key", "one", "--ttl", "0d"}, {"keep-key", "one", "--ttl", "106752d"},
		{"keep-key", "one", "--ttl", "1.2d"}, {"list-keep-key", "extra"},
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
	if out, _, err := runInput(input, "one", "encrypt"); err == nil || out != "" {
		t.Fatal("forgotten key was used to encrypt")
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
	checkEmpty()
	t.Setenv("MASTER_PASSWORD", "correct-password")
	if _, _, err := run("keep-key", "one", "--ttl", "150ms"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MASTER_PASSWORD", "")
	if err := timer.Retry(func() error {
		out, _, err := run("list-keep-key")
		if err == nil && strings.Contains(out, "当前没有保留的密钥") {
			return nil
		}
		return errors.New("cache has not expired")
	}, timer.WithMaxRetries(30), timer.WithBackoff(10*time.Millisecond, 1)); err != nil {
		t.Fatal(err)
	}
}
