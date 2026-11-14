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

	"github.com/api-go/encoding"
	"github.com/api-go/file"
	"github.com/api-go/keys/lib"
	"github.com/api-go/safe"
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
	// A nonce beginning with 0xf8 produces a '-' URL-base64 prefix deterministically.
	nonce := bytes.Repeat([]byte{0xf8}, 12)
	leadingDash := append(bytes.Clone(nonce), gcm.Seal(nil, nonce, plain, nil)...)
	dashEncoded := encoding.URLBase64(leadingDash)
	if !strings.HasPrefix(dashEncoded, "-") {
		t.Fatal("missing regression prefix")
	}
	if run("decrypt", dashEncoded) != string(plain) {
		t.Fatal("leading-dash ciphertext rejected")
	}
	legacy := gcm.Seal(nil, iv[:12], plain, nil)
	if run("decrypt", encoding.URLBase64(legacy)) != string(plain) {
		t.Fatal("legacy CLI decrypt")
	}
	// Stored ciphertext failures must not become successful decoys in CLI.
	if err := lib.SavePassword("migration", "damaged", plain, key, iv, "aes-gcm"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(lib.GetPasswordPath("migration"), "damaged")
	damaged, err := file.ReadBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	damaged[len(damaged)-1] ^= 1
	if err := file.WriteBytes(path, damaged); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(tool, "--non-interactive", "migration", "decrypt", "damaged")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("stored failure: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	second, err := encoding.UnURLBase64(run("encrypt", string(plain)))
	if err != nil || bytes.Equal(wire[:12], second[:12]) {
		t.Fatal("CLI reused nonce", err)
	}
}
