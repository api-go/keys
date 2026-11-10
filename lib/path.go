package lib

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/api-go/file"
)

// GetKeysRootPath returns the root path for all keys and passwords.
// Resolution order:
// 1. KEYSPATH environment variable
// 2. Path stored in ~/.keyspath
// 3. Default: ~/.keys
func GetKeysRootPath() string {
	if p := os.Getenv("KEYSPATH"); p != "" {
		return p
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	keyspathFile := filepath.Join(homeDir, ".keyspath")
	if file.Exists(keyspathFile) {
		content, err := file.ReadBytes(keyspathFile)
		if err == nil {
			p := strings.TrimSpace(string(content))
			if p != "" {
				return p
			}
		}
	}

	return filepath.Join(homeDir, ".keys")
}

// GetKeystorePath returns the path for the keystore directory.
func GetKeystorePath() string {
	return filepath.Join(GetKeysRootPath(), "keystore")
}

// GetPasswordBasePath returns the base path for passwords.
func GetPasswordBasePath() string {
	return filepath.Join(GetKeysRootPath(), "passwords")
}

// GetPasswordPath returns the path for passwords associated with a specific key.
func GetPasswordPath(keyName string) string {
	return filepath.Join(GetPasswordBasePath(), keyName)
}

// EnsureDir ensures the specified directory exists.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0700)
}

// GetStatus returns the root path, number of keystores, and total number of passwords.
func GetStatus() (rootPath string, keystoreCount int, passwordCount int) {
	rootPath = GetKeysRootPath()

	ksPath := GetKeystorePath()
	if entries, err := os.ReadDir(ksPath); err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				keystoreCount++
			}
		}
	}

	pwPath := GetPasswordBasePath()
	_ = filepath.Walk(pwPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			passwordCount++
		}
		return nil
	})

	return
}
