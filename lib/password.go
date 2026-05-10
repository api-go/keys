package lib

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"apigo.cc/go/crypto"
	"apigo.cc/go/crypto-sm"
	"apigo.cc/go/file"
	"apigo.cc/go/safe"
)

// PwdNameToPath returns the name as is, allowing subdirectories via slashes.
func PwdNameToPath(pwdName string) string {
	return pwdName
}

// SavePassword encrypts and saves a password value associated with a specific key.
func SavePassword(keyName, pwdName string, data []byte, activeKey, activeIV []byte, algo string) error {
	if keyName == "" || pwdName == "" {
		return errors.New("key name and password name cannot be empty")
	}

	basePath := GetPasswordPath(keyName)
	relPath := PwdNameToPath(pwdName)
	filePath := filepath.Join(basePath, relPath)

	dir := filepath.Dir(filePath)
	if err := EnsureDir(dir); err != nil {
		return err
	}

	fileIv, err := CryptoRandBytes(12)
	if err != nil {
		return err
	}

	dummySalt, _ := CryptoRandBytes(16)

	sym, err := createSymmetric(activeKey, activeIV, fileIv, algo)
	if err != nil {
		return err
	}

	encData, err := sym.EncryptBytes(data)
	if err != nil {
		return err
	}

	header, cipherPadding, err := PackFileHeader(dummySalt, fileIv)
	if err != nil {
		return err
	}

	paddingBuf, _ := CryptoRandBytes(cipherPadding)
	finalBuf := append([]byte(nil), header...)
	finalBuf = append(finalBuf, paddingBuf...)
	finalBuf = append(finalBuf, encData...)

	return file.WriteBytes(filePath, finalBuf)
}

// LoadPassword loads and decrypts a password value.
func LoadPassword(keyName, pwdName string, activeKey, activeIV []byte, algo string) ([]byte, error) {
	basePath := GetPasswordPath(keyName)
	relPath := PwdNameToPath(pwdName)
	filePath := filepath.Join(basePath, relPath)

	if !file.Exists(filePath) {
		return nil, errors.New("password not found")
	}

	data, err := file.ReadBytes(filePath)
	if err != nil {
		return nil, err
	}

	if len(data) < FileHeaderSize {
		return nil, errors.New("invalid password file format")
	}

	header := data[:FileHeaderSize]
	_, fileIv, cipherPadding, err := UnpackFileHeader(header)
	if err != nil {
		return nil, errors.New("invalid password file header")
	}

	cipherStart := FileHeaderSize + cipherPadding
	if len(data) <= cipherStart {
		return nil, errors.New("invalid password file format (no ciphertext)")
	}

	cipherText := data[cipherStart:]

	sym, err := createSymmetric(activeKey, activeIV, fileIv, algo)
	if err != nil {
		return nil, err
	}

	dec, err := sym.DecryptBytes(cipherText)
	if err != nil {
		// --- 🛡️ 诱饵模式 (Decoy Mode) 🛡️ ---
		// 解密失败不报错，而是返回一段随机的 12-24 位字符
		// 让攻击者无法确定是算法选错了、Key错了，还是密码本身就是这样。
		return CryptoRandDecoy(12, 24), nil
	}

	return dec, nil
}

func createSymmetric(key, keyIv, fileIv []byte, algo string) (*crypto.Symmetric, error) {
	k := append([]byte(nil), key...)
	v := append([]byte(nil), fileIv...)
	defer safe.ZeroMemory(k)
	defer safe.ZeroMemory(v)

	switch strings.ToLower(algo) {
	case "aes-gcm", "gcm", "":
		return crypto.NewAESGCMWithoutEraseKey(k, v)
	case "aes-cbc", "cbc":
		return crypto.NewAESCBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	case "sm4-gcm", "sm4":
		return sm.NewSM4GCMWithoutEraseKey(k, v)
	case "sm4-cbc":
		return sm.NewSM4CBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	default:
		return nil, errors.New("unsupported algorithm: " + algo)
	}
}

// CryptoRandDecoy generates a random string for decoy purposes.
func CryptoRandDecoy(min, max int) []byte {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	n := min
	if max > min {
		rb, _ := CryptoRandBytes(1)
		n = min + (int(rb[0]) % (max - min + 1))
	}
	res := make([]byte, n)
	rb, _ := CryptoRandBytes(n)
	for i := 0; i < n; i++ {
		res[i] = chars[int(rb[i])%len(chars)]
	}
	return res
}

// RemovePassword deletes a password file.
func RemovePassword(keyName, pwdName string) error {
	basePath := GetPasswordPath(keyName)
	relPath := PwdNameToPath(pwdName)
	filePath := filepath.Join(basePath, relPath)

	if !file.Exists(filePath) {
		return errors.New("password not found")
	}

	return os.Remove(filePath)
}

// ListPasswords lists all passwords under a key, returning them as path names.
func ListPasswords(keyName string) ([]string, error) {
	basePath := GetPasswordPath(keyName)
	if !file.Exists(basePath) {
		return nil, nil // No passwords yet
	}

	var passwords []string
	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(basePath, path)
			if err == nil {
				passwords = append(passwords, rel)
			}
		}
		return nil
	})

	return passwords, err
}
