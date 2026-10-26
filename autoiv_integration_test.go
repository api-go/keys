package main_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"apigo.cc/go/encoding"
	"apigo.cc/go/keys/lib"
	"apigo.cc/go/safe"
)

func TestAutoIVCLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYSPATH", filepath.Join(dir, "store"))
	t.Setenv("MASTER_PASSWORD", "migration password")
	ks, err := lib.CreateKeystore("migration", []byte("migration password"))
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	key, iv, err := ks.GetRaw()
	if err != nil {
		t.Fatal(err)
	}
	defer safe.ZeroMemory(key)
	defer safe.ZeroMemory(iv)
	tool := filepath.Join(dir, "keys_tool")
	build := exec.Command("go", "build", "-o", tool, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	run := func(operation, input string) string {
		t.Helper()
		cmd := exec.Command(tool, "migration", operation, input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", operation, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	plain := []byte("new CLI encryption standard")
	encoded := run("encrypt", string(plain))
	wire, err := encoding.UnURLBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != len(plain)+28 {
		t.Fatal("CLI did not write auto IV")
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	decoded, err := gcm.Open(nil, wire[:12], wire[12:], nil)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("CLI wire format", err)
	}
	if run("decrypt", encoded) != string(plain) {
		t.Fatal("new CLI decrypt")
	}
	legacy := gcm.Seal(nil, iv[:12], plain, nil)
	if run("decrypt", encoding.URLBase64(legacy)) != string(plain) {
		t.Fatal("legacy CLI decrypt")
	}
	second, err := encoding.UnURLBase64(run("encrypt", string(plain)))
	if err != nil || bytes.Equal(wire[:12], second[:12]) {
		t.Fatal("CLI reused nonce", err)
	}
}
