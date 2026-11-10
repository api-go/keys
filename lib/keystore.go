package lib

import (
	"errors"
	"strings"

	"github.com/api-go/crypto"
	"github.com/api-go/crypto-sm"
	"github.com/api-go/file"
	"github.com/api-go/safe"
)

type KeySet struct {
	Name              string
	buf               *safe.SafeBuf // Holds the 128-byte obfuscated key
	sourceFingerprint [32]byte
}

// SourceFingerprint identifies the encrypted file snapshot used to unlock this key.
// It contains no plaintext key or password material.
func (k *KeySet) SourceFingerprint() [32]byte {
	if k == nil {
		return [32]byte{}
	}
	return k.sourceFingerprint
}

// Close safely erases the memory buffer.
func (k *KeySet) Close() {
	if k == nil || k.buf == nil {
		return
	}
	k.buf.Close()
}

// GetRaw extracts the actual 32-byte Key and 12-16 byte IV from the obfuscated buffer.
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
		return sm.NewSM4GCMWithoutEraseKey(key[:16], iv[:12])
	case "sm4-cbc":
		cbcIv := iv
		if len(cbcIv) == 12 {
			cbcIv = append(cbcIv, 0, 0, 0, 0)
		}
		return sm.NewSM4CBCWithoutEraseKey(key[:16], cbcIv)
	default:
		return nil, errors.New("unsupported algorithm: " + algo)
	}
}

// CreateKeystore creates a new master key, obfuscates it, encrypts it with the master password, and saves it.
func CreateKeystore(name string, masterPassword []byte) (*KeySet, error) {
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	if name == "default" {
		return nil, errors.New("reserved key name")
	}
	if len(masterPassword) == 0 {
		return nil, errors.New("master password is required")
	}
	root, err := openStore("keystore", "", true)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	key, err := CryptoRandBytes(32)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(key)
	iv, err := CryptoRandBytes(12)
	if err != nil {
		return nil, err
	}

	defer safe.ZeroMemory(iv)

	// Pack to 128 bytes
	memKeyBuf, err := PackMemoryKey(key, iv)
	if err != nil {
		return nil, err
	}

	defer safe.ZeroMemory(memKeyBuf)

	// Encrypt the 128 bytes with master password
	salt, err := CryptoRandBytes(16)
	if err != nil {
		return nil, err
	}
	fileIv, err := CryptoRandBytes(12)
	if err != nil {
		return nil, err
	}

	passCopy := append([]byte(nil), masterPassword...)
	defer safe.ZeroMemory(passCopy)
	saltCopy := append([]byte(nil), salt...)
	sym, err := crypto.NewAESGCMByPassword(passCopy, saltCopy)
	if err != nil {
		return nil, err
	}

	defer sym.Close()
	encData, err := sym.EncryptBytesAutoIV(memKeyBuf)
	if err != nil {
		return nil, err
	}

	// Pack file header
	header, cipherPadding, err := PackFileHeader(salt, fileIv)
	if err != nil {
		return nil, err
	}

	// Construct final file content: Header (256) + Padding + Ciphertext
	paddingBuf, err := CryptoRandBytes(cipherPadding)
	if err != nil {
		return nil, err
	}

	finalBuf := append([]byte(nil), header...)
	finalBuf = append(finalBuf, paddingBuf...)
	finalBuf = append(finalBuf, encData...)

	// Write raw binary
	if err := writeSecret(root, name, finalBuf, true); err != nil {
		return nil, err
	}

	var fingerprint [32]byte
	copy(fingerprint[:], crypto.SHA256(finalBuf))
	return &KeySet{
		sourceFingerprint: fingerprint,
		Name:              name,
		buf:               safe.NewSafeBufAndErase(memKeyBuf),
	}, nil
}

// LoadKeystore loads and decrypts a master key from disk.
func LoadKeystore(name string, masterPassword []byte) (*KeySet, error) {
	if name == "default" {
		return GetDefaultKeySet(), nil
	}
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	if len(masterPassword) == 0 {
		return nil, errors.New("master password is required")
	}
	root, err := openStore("keystore", "", false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := root.ReadFile(name)
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
	defer safe.ZeroMemory(passCopy)
	sym, err := crypto.NewAESGCMByPassword(passCopy, salt)
	if err != nil {
		return nil, err
	}

	defer sym.Close()
	dec, err := sym.DecryptBytes(cipherText)
	if err != nil {
		return nil, errors.New("invalid master password or corrupted key file")
	}
	defer safe.ZeroMemory(dec)

	if len(dec) != MemoryKeySize {
		return nil, errors.New("corrupted key data (invalid length)")
	}

	key, iv, err := UnpackMemoryKey(dec)
	if err != nil {
		return nil, errors.New("corrupted key data")
	}
	safe.ZeroMemory(key)
	safe.ZeroMemory(iv)
	var fingerprint [32]byte
	copy(fingerprint[:], crypto.SHA256(data))
	return &KeySet{
		sourceFingerprint: fingerprint,
		Name:              name,
		buf:               safe.NewSafeBufAndErase(dec),
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
