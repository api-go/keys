package lib

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"apigo.cc/go/crypto"
	"apigo.cc/go/crypto-sm"
	"apigo.cc/go/file"
	"apigo.cc/go/safe"
)

type KeySet struct {
	Name string
	buf  *safe.SafeBuf // Holds the 128-byte obfuscated key
}

// Close safely erases the memory buffer.
func (k *KeySet) Close() {
	if k == nil || k.buf == nil {
		return
	}
	k.buf.Close()
}

// GetRaw extracts the actual 32-byte Key and 12-byte IV from the obfuscated buffer.
func (k *KeySet) GetRaw() ([]byte, []byte, error) {
	if k == nil || k.buf == nil {
		return nil, nil, errors.New("invalid keyset")
	}
	
	plain := k.buf.Open()
	defer plain.Close()
	
	key, iv, err := UnpackMemoryKey(plain.Data)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// NewSymmetric creates a symmetric cipher from the keyset using the specified algorithm.
func (k *KeySet) NewSymmetric(algo string) (*crypto.Symmetric, error) {
	key, iv, err := k.GetRaw()
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(key)
	defer safe.ZeroMemory(iv)

	switch strings.ToLower(algo) {
	case "aes-gcm", "gcm", "":
		return crypto.NewAESGCMWithoutEraseKey(key, iv[:12])
	case "aes-cbc", "cbc":
		cbcIv := iv
		if len(cbcIv) == 12 {
			cbcIv = append(cbcIv, 0, 0, 0, 0)
		}
		return crypto.NewAESCBCWithoutEraseKey(key, cbcIv)
	case "sm4-gcm", "sm4":
		return sm.NewSM4GCMWithoutEraseKey(key, iv[:12])
	case "sm4-cbc":
		cbcIv := iv
		if len(cbcIv) == 12 {
			cbcIv = append(cbcIv, 0, 0, 0, 0)
		}
		return sm.NewSM4CBCWithoutEraseKey(key, cbcIv)
	default:
		return nil, errors.New("unsupported algorithm: " + algo)
	}
}

// CreateKeystore creates a new master key, obfuscates it, encrypts it with the master password, and saves it.
func CreateKeystore(name string, masterPassword []byte) (*KeySet, error) {
	if name == "" {
		return nil, errors.New("key name cannot be empty")
	}

	keyPath := GetKeystorePath()
	if err := EnsureDir(keyPath); err != nil {
		return nil, err
	}

	filePath := filepath.Join(keyPath, name)
	if file.Exists(filePath) {
		return nil, errors.New("key exists")
	}

	key, err := CryptoRandBytes(32)
	if err != nil {
		return nil, err
	}
	iv, err := CryptoRandBytes(12)
	if err != nil {
		return nil, err
	}

	// Pack to 128 bytes
	memKeyBuf, err := PackMemoryKey(key, iv)
	if err != nil {
		return nil, err
	}

	// Encrypt the 128 bytes with master password
	salt, _ := CryptoRandBytes(16)
	fileIv, _ := CryptoRandBytes(12)

	passCopy := append([]byte(nil), masterPassword...)
	saltCopy := append([]byte(nil), salt...)
	sym, err := crypto.NewAESGCMByPassword(passCopy, saltCopy)
	if err != nil {
		return nil, err
	}
	
	encData, err := sym.EncryptBytes(memKeyBuf)
	if err != nil {
		return nil, err
	}

	// Pack file header
	header, cipherPadding, err := PackFileHeader(salt, fileIv)
	if err != nil {
		return nil, err
	}

	// Construct final file content: Header (256) + Padding + Ciphertext
	paddingBuf, _ := CryptoRandBytes(cipherPadding)
	
	finalBuf := append([]byte(nil), header...)
	finalBuf = append(finalBuf, paddingBuf...)
	finalBuf = append(finalBuf, encData...)

	// Write raw binary
	if err := file.WriteBytes(filePath, finalBuf); err != nil {
		return nil, err
	}

	return &KeySet{
		Name: name,
		buf:  safe.NewSafeBufAndErase(memKeyBuf),
	}, nil
}

// LoadKeystore loads and decrypts a master key from disk.
func LoadKeystore(name string, masterPassword []byte) (*KeySet, error) {
	if name == "default" {
		return GetDefaultKeySet(), nil
	}
	keyPath := GetKeystorePath()
	filePath := filepath.Join(keyPath, name)

	if !file.Exists(filePath) {
		return nil, errors.New("key not found")
	}

	data, err := file.ReadBytes(filePath)
	if err != nil {
		return nil, err
	}

	if len(data) < FileHeaderSize {
		return nil, errors.New("invalid key file format (too short)")
	}

	header := data[:FileHeaderSize]
	salt, _, cipherPadding, err := UnpackFileHeader(header)
	if err != nil {
		return nil, errors.New("invalid key file header")
	}

	cipherStart := FileHeaderSize + cipherPadding
	if len(data) <= cipherStart {
		return nil, errors.New("invalid key file format (no ciphertext)")
	}

	cipherText := data[cipherStart:]

	passCopy := append([]byte(nil), masterPassword...)
	sym, err := crypto.NewAESGCMByPassword(passCopy, salt)
	if err != nil {
		return nil, err
	}

	dec, err := sym.DecryptBytes(cipherText)
	if err != nil {
		// --- 🛡️ 诱饵模式 (Decoy Mode) 🛡️ ---
		// 密码错误不报错，而是返回一个随机生成的 KeySet。
		// 这会让攻击者无法通过报错来判断暴力破解是否成功。
		// 同时增加 1.5s 延迟，大幅降低自动化破解效率。
		time.Sleep(1500 * time.Millisecond)
		garbage, _ := CryptoRandBytes(MemoryKeySize)
		return &KeySet{
			Name: name,
			buf:  safe.NewSafeBufAndErase(garbage),
		}, nil
	}

	if len(dec) != MemoryKeySize {
		return nil, errors.New("corrupted key data (invalid length)")
	}

	return &KeySet{
		Name: name,
		buf:  safe.NewSafeBufAndErase(dec),
	}, nil
}

// HasMasterPassword checks if there are any keys in the keystore.
// If there are none, we might prompt the user to create a master password.
func HasMasterPassword() bool {
	// In the new design, the master password is just a mental concept that decrypts individual files.
	// If there are any files in the keystore, it implies the system is initialized.
	keyPath := GetKeystorePath()
	if !file.Exists(keyPath) {
		return false
	}
	files, _ := file.ReadDir(keyPath)
	return len(files) > 0
}

const (
	DefaultKey = "?GQ$0K0GgLdO=f+~L68PLm$uhKr4'=tV"
	DefaultIV  = "VFs7@sK61cj^f?HZ"
)

// GetDefaultKeySet returns a pre-defined keyset that doesn't require a password.
func GetDefaultKeySet() *KeySet {
	key := []byte(DefaultKey)
	iv := []byte(DefaultIV)
	memKeyBuf, _ := PackMemoryKey(key, iv)
	return &KeySet{
		Name: "default",
		buf:  safe.NewSafeBufAndErase(memKeyBuf),
	}
}
