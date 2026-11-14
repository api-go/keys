package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIHelpAndNonInteractive(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "go-keys-cli")
	build := exec.Command("go", "build", "-o", tool, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	for _, args := range [][]string{{"list"}, {"create"}, {"remove"}, {"export"}, {"keep-key"}, {"forget-key"}, {"-status"}, {"-setpath"}, {"missing", "list"}, {"missing", "create"}, {"missing", "remove"}, {"missing", "encrypt"}, {"missing", "decrypt"}} {
		for _, help := range []string{"-h", "--help"} {
			cmd := exec.Command(tool, append(append([]string{}, args...), help)...)
			cmd.Env = append(os.Environ(), "KEYSPATH="+t.TempDir(), "MASTER_PASSWORD=")
			if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "用法") {
				t.Fatalf("%v %v %s", args, err, output)
			}
		}
	}
	for _, args := range [][]string{{"--non-interactive"}, {"--non-interactive", "missing"}, {"--non-interactive", "create", "test"}, {"default", "unknown"}, {"--bad"}, {"default", "decrypt", "invalid-ciphertext"}} {
		cmd := exec.Command(tool, args...)
		cmd.Env = append(os.Environ(), "KEYSPATH="+t.TempDir(), "MASTER_PASSWORD=")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("accepted %v: %s", args, output)
		}
		if strings.Contains(string(output), "输入主密码:") {
			t.Fatalf("prompted: %v", args)
		}
	}
	root := t.TempDir()
	env := append(os.Environ(), "KEYSPATH="+root, "MASTER_PASSWORD=go-keys-automation-test")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(tool, append([]string{"--non-interactive"}, args...)...)
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, output)
		}
		return string(output)
	}
	run("create", "automation")
	run("automation", "create", "item", "value")
	if output := run("automation", "decrypt", "item"); strings.TrimSpace(output) != "value" {
		t.Fatalf("wrong stored plaintext: %q", output)
	}
	run("automation", "list")
	if output := run("export", "automation", "go"); !strings.HasPrefix(output, "package main") {
		t.Fatal("missing export")
	}
	bad := exec.Command(tool, "--non-interactive", "automation", "decrypt", "item")
	bad.Env = append(append([]string{}, env...), "MASTER_PASSWORD=incorrect")
	var stdout, stderr bytes.Buffer
	bad.Stdout = &stdout
	bad.Stderr = &stderr
	if err := bad.Run(); err == nil || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("authentication failure: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	run("automation", "remove", "item")
	run("remove", "automation")
}
