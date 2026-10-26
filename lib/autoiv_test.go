package lib_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"path/filepath"
	"testing"

	"apigo.cc/go/crypto"
	"apigo.cc/go/file"
	"apigo.cc/go/keys/lib"
	"apigo.cc/go/safe"
)

func TestAutoIVStorageAndLegacyRead(t *testing.T) {
	t.Setenv("KEYSPATH", t.TempDir())
	password := []byte("migration master password")
	ks, err := lib.CreateKeystore("migration", password)
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
	keyPath := filepath.Join(lib.GetKeystorePath(), "migration")
	content, err := file.ReadBytes(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	salt, _, padding, err := lib.UnpackFileHeader(content[:lib.FileHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	start := lib.FileHeaderSize + padding
	// Independent KDF and standard GCM authenticate the new keystore wire format.
	derived := crypto.DeriveKey(bytes.Clone(password), bytes.Clone(salt), 44)
	defer safe.ZeroMemory(derived)
	block, _ := aes.NewCipher(derived[:32])
	gcm, _ := cipher.NewGCM(block)
	payload := content[start:]
	plain, err := gcm.Open(nil, payload[:12], payload[12:], nil)
	if err != nil || len(plain) != lib.MemoryKeySize {
		t.Fatal("new keystore format", err)
	}
	defer safe.ZeroMemory(plain)
	// Replace only the payload with a genuine legacy fixture, retaining all headers.
	legacy := gcm.Seal(nil, derived[32:], plain, nil)
	if err := file.WriteBytes(keyPath, append(bytes.Clone(content[:start]), legacy...)); err != nil {
		t.Fatal(err)
	}
	loaded, err := lib.LoadKeystore("migration", password)
	if err != nil {
		t.Fatal("legacy keystore", err)
	}
	loaded.Close()

	value := []byte("password migration value long enough for both formats")
	if err := lib.SavePassword("migration", "secret", value, key, iv, "aes-gcm"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(lib.GetPasswordPath("migration"), "secret")
	content, err = file.ReadBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	_, fileIV, padding, err := lib.UnpackFileHeader(content[:lib.FileHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	start = lib.FileHeaderSize + padding
	block, _ = aes.NewCipher(key)
	gcm, _ = cipher.NewGCM(block)
	payload = content[start:]
	decoded, err := gcm.Open(nil, payload[:12], payload[12:], nil)
	if err != nil || !bytes.Equal(decoded, value) {
		t.Fatal("new password format", err)
	}
	safe.ZeroMemory(decoded)
	got, err := lib.LoadPassword("migration", "secret", key, iv, "aes-gcm")
	if err != nil || !bytes.Equal(got, value) {
		t.Fatal("new password read", err)
	}
	safe.ZeroMemory(got)
	legacy = gcm.Seal(nil, fileIV, value, nil)
	if err := file.WriteBytes(path, append(bytes.Clone(content[:start]), legacy...)); err != nil {
		t.Fatal(err)
	}
	got, err = lib.LoadPassword("migration", "secret", key, iv, "aes-gcm")
	if err != nil || !bytes.Equal(got, value) {
		t.Fatal("legacy password read", err)
	}
	safe.ZeroMemory(got)
	// Updating a legacy password writes the new format again.
	if err := lib.SavePassword("migration", "secret", value, key, iv, "aes-gcm"); err != nil {
		t.Fatal(err)
	}
	content, err = file.ReadBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, padding, err = lib.UnpackFileHeader(content[:lib.FileHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	payload = content[lib.FileHeaderSize+padding:]
	if len(payload) != len(value)+28 {
		t.Fatal("legacy update did not migrate")
	}
}
