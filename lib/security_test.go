package lib_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"apigo.cc/go/file"
	"apigo.cc/go/keys/lib"
)

func TestKeystoreAuthentication(t *testing.T) {
	t.Setenv("KEYSPATH", t.TempDir())
	pwd := []byte("test master password")
	ks, err := lib.CreateKeystore("valid", pwd)
	if err != nil {
		t.Fatal(err)
	}
	ks.Close()
	for _, bad := range [][]byte{nil, []byte("wrong")} {
		ks, err := lib.LoadKeystore("valid", bad)
		if err == nil || ks != nil {
			t.Fatal("invalid password accepted")
		}
	}
	path := filepath.Join(lib.GetKeystorePath(), "valid")
	data, err := file.ReadBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := file.WriteBytes(path, data); err != nil {
		t.Fatal(err)
	}
	if ks, err := lib.LoadKeystore("valid", pwd); err == nil || ks != nil {
		t.Fatal("corruption accepted")
	}
}

func TestSecretPathBoundaries(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KEYSPATH", root)
	key := bytes.Repeat([]byte{1}, 32)
	iv := bytes.Repeat([]byte{2}, 12)
	for _, name := range []string{"", ".", "..", "../outside", "/outside", `a\b`, "a/b", "a:b", "default"} {
		if ks, err := lib.CreateKeystore(name, []byte("password")); err == nil || ks != nil {
			t.Errorf("accepted key name %q", name)
		}
	}
	for _, name := range []string{"", ".", "..", "../outside", "/outside", "nested/../../outside", `a\b`, "a:b"} {
		if err := lib.SavePassword("valid", name, []byte("secret"), key, iv, ""); err == nil {
			t.Errorf("accepted password path %q", name)
		}
		if _, err := lib.LoadPassword("valid", name, key, iv, ""); err == nil {
			t.Errorf("read path %q", name)
		}
		if err := lib.RemovePassword("valid", name); err == nil {
			t.Errorf("removed path %q", name)
		}
	}
	if err := lib.SavePassword("../outside", "item", []byte("secret"), key, iv, ""); err == nil {
		t.Fatal("invalid key name accepted")
	}
	if err := lib.SavePassword("valid", "nested/item", []byte("secret"), key, iv, ""); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(lib.GetPasswordPath("valid"), "escape")); err != nil {
			t.Fatal(err)
		}
		if err := lib.SavePassword("valid", "escape/item", []byte("secret"), key, iv, ""); err == nil {
			t.Fatal("symlink escape accepted")
		}
		if _, err := lib.LoadPassword("valid", "escape/item", key, iv, ""); err == nil {
			t.Fatal("symlink read escape accepted")
		}
		if err := lib.RemovePassword("valid", "escape/item"); err == nil {
			t.Fatal("symlink removal escape accepted")
		}
	}
}

func TestConcurrentKeystoreCreation(t *testing.T) {
	t.Setenv("KEYSPATH", t.TempDir())
	pwd := []byte("test password")
	var wg sync.WaitGroup
	results := make(chan *lib.KeySet, 4)
	for range 4 {
		wg.Go(func() {
			ks, err := lib.CreateKeystore("same", pwd)
			if err == nil {
				results <- ks
			}
		})
	}
	wg.Wait()
	close(results)
	count := 0
	for ks := range results {
		count++
		ks.Close()
	}
	if count != 1 {
		t.Fatalf("successful creations = %d", count)
	}
	ks, err := lib.LoadKeystore("same", pwd)
	if err != nil {
		t.Fatal(err)
	}
	ks.Close()
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(lib.GetKeystorePath(), "same"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("permissions = %o", info.Mode().Perm())
		}
	}
	if err := lib.RemoveKeystore("../same"); err == nil {
		t.Fatal("invalid removal accepted")
	}
	if err := lib.RemoveKeystore("same"); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordStorage(t *testing.T) {
	t.Setenv("KEYSPATH", t.TempDir())
	key := bytes.Repeat([]byte{3}, 32)
	iv := bytes.Repeat([]byte{4}, 12)
	for _, algo := range []string{"aes-gcm", "aes-cbc", "sm4-gcm", "sm4-cbc"} {
		t.Run(algo, func(t *testing.T) {
			name := "nested/" + algo
			for _, value := range []string{"first secret", "replacement secret"} {
				if err := lib.SavePassword("valid", name, []byte(value), key, iv, algo); err != nil {
					t.Fatal(err)
				}
				data, err := lib.LoadPassword("valid", name, key, iv, algo)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != value {
					t.Fatal("stored value mismatch")
				}
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(filepath.Join(lib.GetPasswordPath("valid"), name))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0600 {
					t.Fatalf("permissions = %o", info.Mode().Perm())
				}
			}
			if err := lib.RemovePassword("valid", name); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestKeySetAlgorithms(t *testing.T) {
	ks := lib.GetDefaultKeySet()
	defer ks.Close()
	for _, algo := range []string{"aes-gcm", "aes-cbc", "sm4-gcm", "sm4-cbc"} {
		t.Run(algo, func(t *testing.T) {
			sym, err := ks.NewSymmetric(algo)
			if err != nil {
				t.Fatal(err)
			}
			defer sym.Close()
			encrypted, err := sym.EncryptBytes([]byte("round trip"))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := sym.DecryptBytes(encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != "round trip" {
				t.Fatal("plaintext mismatch")
			}
		})
	}
}
