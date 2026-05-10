package lib

import (
	"bytes"
	"os"
	"testing"
)

func TestKeystoreAndPassword(t *testing.T) {
	// Setup a temporary KEYSPATH
	tmpDir, err := os.MkdirTemp("", "keys_test_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	os.Setenv("KEYSPATH", tmpDir)
	defer os.Unsetenv("KEYSPATH")

	masterPassword := []byte("super_secret_master_password")
	keyName := "test_key"

	// 1. Create Keystore
	ks, err := CreateKeystore(keyName, masterPassword)
	if err != nil {
		t.Fatalf("CreateKeystore failed: %v", err)
	}

	key1, iv1, err := ks.GetRaw()
	if err != nil {
		t.Fatalf("GetRaw failed: %v", err)
	}
	ks.Close()

	// 2. Load Keystore
	ks2, err := LoadKeystore(keyName, masterPassword)
	if err != nil {
		t.Fatalf("LoadKeystore failed: %v", err)
	}

	key2, iv2, err := ks2.GetRaw()
	if err != nil {
		t.Fatalf("GetRaw on loaded failed: %v", err)
	}

	if !bytes.Equal(key1, key2) || !bytes.Equal(iv1, iv2) {
		t.Fatalf("Loaded key/iv does not match created key/iv")
	}

	// 3. Save Password
	pwdName := "db.mysql.root"
	pwdValue := []byte("123456")

	err = SavePassword(keyName, pwdName, pwdValue, key2, iv2, "aes-gcm")
	if err != nil {
		t.Fatalf("SavePassword failed: %v", err)
	}

	// 4. List Passwords
	pwds, err := ListPasswords(keyName)
	if err != nil {
		t.Fatalf("ListPasswords failed: %v", err)
	}
	if len(pwds) != 1 || pwds[0] != pwdName {
		t.Fatalf("ListPasswords returned unexpected results: %v", pwds)
	}

	// 5. Load Password
	loadedPwd, err := LoadPassword(keyName, pwdName, key2, iv2, "aes-gcm")
	if err != nil {
		t.Fatalf("LoadPassword failed: %v", err)
	}
	if !bytes.Equal(pwdValue, loadedPwd) {
		t.Fatalf("Loaded password does not match. Got: %s, Want: %s", string(loadedPwd), string(pwdValue))
	}

	// 6. Delete Password
	err = RemovePassword(keyName, pwdName)
	if err != nil {
		t.Fatalf("RemovePassword failed: %v", err)
	}

	pwds2, _ := ListPasswords(keyName)
	if len(pwds2) != 0 {
		t.Fatalf("Password was not deleted properly")
	}

	ks2.Close()
}
