package lib

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"apigo.cc/go/crypto"
	"apigo.cc/go/crypto-sm"
	"apigo.cc/go/safe"
)

// PwdNameToPath returns the name as is, allowing subdirectories via slashes.
func PwdNameToPath(pwdName string) string {
	return pwdName
}

// SavePassword encrypts and saves a password value associated with a specific key.
func SavePassword(keyName, pwdName string, data []byte, activeKey, activeIV []byte, algo string) error {
	if err := validateItemName(pwdName); err != nil {
		return err
	}
	root, err := openStore("passwords", keyName, true)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(filepath.Dir(pwdName), 0700); err != nil {
		return err
	}

	fileIv, err := CryptoRandBytes(12)
	if err != nil {
		return err
	}

	dummySalt, err := CryptoRandBytes(16)
	if err != nil {
		return err
	}

	sym, err := createSymmetric(activeKey, activeIV, fileIv, algo)
	if err != nil {
		return err
	}

	defer sym.Close()
	encData, err := sym.EncryptBytes(data)
	if err != nil {
		return err
	}

	header, cipherPadding, err := PackFileHeader(dummySalt, fileIv)
	if err != nil {
		return err
	}

	paddingBuf, err := CryptoRandBytes(cipherPadding)
	if err != nil {
		return err
	}
	finalBuf := append([]byte(nil), header...)
	finalBuf = append(finalBuf, paddingBuf...)
	finalBuf = append(finalBuf, encData...)

	return writeSecret(root, pwdName, finalBuf, false)
}

// LoadPassword loads and decrypts a password value.
func LoadPassword(keyName, pwdName string, activeKey, activeIV []byte, algo string) ([]byte, error) {
	if err := validateItemName(pwdName); err != nil {
		return nil, err
	}
	root, err := openStore("passwords", keyName, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := root.ReadFile(pwdName)
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

	defer sym.Close()
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
	if len(key) < 16 {
		return nil, errors.New("key size is too short, at least 16 bytes required")
	}
	k := append([]byte(nil), key...)
	v := append([]byte(nil), fileIv...)
	defer safe.ZeroMemory(k)
	defer safe.ZeroMemory(v)

	switch strings.ToLower(algo) {
	case "aes-gcm", "gcm", "":
		return crypto.NewAESGCMWithoutEraseKey(k, v)
	case "aes-cbc", "cbc":
		cbcIv := v
		if len(cbcIv) == 12 {
			cbcIv = append(cbcIv, 0, 0, 0, 0)
		}
		return crypto.NewAESCBCWithoutEraseKey(k, cbcIv)
	case "sm4-gcm", "sm4":
		return sm.NewSM4GCMWithoutEraseKey(k[:16], v)
	case "sm4-cbc":
		cbcIv := v
		if len(cbcIv) == 12 {
			cbcIv = append(cbcIv, 0, 0, 0, 0)
		}
		return sm.NewSM4CBCWithoutEraseKey(k[:16], cbcIv)
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
	if err := validateItemName(pwdName); err != nil {
		return err
	}
	root, err := openStore("passwords", keyName, false)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(pwdName)
}

// ListPasswords lists password item paths without following symbolic links.
func ListPasswords(keyName string) ([]string, error) {
	root, err := openStore("passwords", keyName, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return listPasswordFiles(root)
}
