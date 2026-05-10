package lib

import (
	"crypto/rand"
	"errors"
)

const (
	MemoryKeySize  = 128
	FileHeaderSize = 256
)

// CryptoRandBytes generates n cryptographically secure random bytes.
func CryptoRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// PackMemoryKey packs a 32-byte key and a up to 16-byte IV into a 128-byte obfuscated buffer.
func PackMemoryKey(key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key length must be 32 bytes")
	}
	if len(iv) < 12 || len(iv) > 16 {
		return nil, errors.New("iv length must be between 12 and 16 bytes")
	}

	buf, err := CryptoRandBytes(MemoryKeySize)
	if err != nil {
		return nil, err
	}

	// Indicator at the last byte (127)
	indicator := buf[127]
	var ptr1Index int
	if indicator%2 == 0 {
		ptr1Index = 126
	} else {
		ptr1Index = 125
	}

	// Offset_K is stored at ptr1Index.
	// Need space for: Key (32) + Offset_IV (1) + IV (16) + IV_Len (1) = 50 bytes.
	// Max offset is ptr1Index - 50. To be safe, constrain to [0, 64].
	offsetK := int(buf[ptr1Index]) % 64
	buf[ptr1Index] = byte(offsetK)

	// Write Key
	copy(buf[offsetK:offsetK+32], key)

	// Offset_IV is stored at offsetK + 32
	// Need space for IV (16). Max offset is ptr1Index - 16.
	minOffsetIV := offsetK + 34 // Leave 2 bytes for offset and len
	maxOffsetIV := 100 // Safe upper bound
	rangeIV := maxOffsetIV - minOffsetIV + 1

	offsetIVByte := buf[offsetK+32]
	offsetIV := minOffsetIV + (int(offsetIVByte) % rangeIV)
	buf[offsetK+32] = byte(offsetIV)
	
	// IV Length is stored at offsetK + 33
	buf[offsetK+33] = byte(len(iv))

	// Write IV
	copy(buf[offsetIV:offsetIV+len(iv)], iv)

	return buf, nil
}

// UnpackMemoryKey unpacks a 128-byte obfuscated buffer into a 32-byte key and a 12-16 byte IV.
func UnpackMemoryKey(buf []byte) (key, iv []byte, err error) {
	if len(buf) != MemoryKeySize {
		return nil, nil, errors.New("invalid memory key size")
	}

	indicator := buf[127]
	var ptr1Index int
	if indicator%2 == 0 {
		ptr1Index = 126
	} else {
		ptr1Index = 125
	}

	offsetK := int(buf[ptr1Index])
	if offsetK+34 > ptr1Index {
		return nil, nil, errors.New("invalid key offset")
	}

	key = make([]byte, 32)
	copy(key, buf[offsetK:offsetK+32])

	offsetIV := int(buf[offsetK+32])
	ivLen := int(buf[offsetK+33])
	if ivLen < 12 || ivLen > 16 || offsetIV+ivLen > ptr1Index {
		return nil, nil, errors.New("invalid iv offset or length")
	}

	iv = make([]byte, ivLen)
	copy(iv, buf[offsetIV:offsetIV+ivLen])

	return key, iv, nil
}

// PackFileHeader packs a 16-byte salt and a 12-byte iv into a 256-byte obfuscated header.
// It returns the header bytes and the number of random bytes that should be prepended to the ciphertext (cipherPadding).
func PackFileHeader(salt, iv []byte) (header []byte, cipherPadding int, err error) {
	if len(salt) != 16 {
		return nil, 0, errors.New("salt length must be 16 bytes")
	}
	if len(iv) != 12 {
		return nil, 0, errors.New("iv length must be 12 bytes")
	}

	header, err = CryptoRandBytes(FileHeaderSize)
	if err != nil {
		return nil, 0, err
	}

	// Token is 31 bytes total: 16 salt + 12 iv + 3 padding
	token := make([]byte, 31)
	copy(token[0:16], salt)
	copy(token[16:28], iv)
	randPad, _ := CryptoRandBytes(3)
	copy(token[28:31], randPad)

	// Indicator at 255
	indicator := header[255]
	var ptr1Index int
	if indicator%2 == 0 {
		ptr1Index = 254
	} else {
		ptr1Index = 253
	}

	// Offset_Token stored at ptr1Index.
	// Space needed for Token is 31 bytes.
	// Constrain Offset_Token to [0, 200].
	offsetToken := int(header[ptr1Index]) % 200
	header[ptr1Index] = byte(offsetToken)

	// Write Token
	copy(header[offsetToken:offsetToken+31], token)

	// CipherPadding stored at 252.
	// This determines how many random bytes are after the header before the real ciphertext begins.
	cipherPadding = int(header[252]) % 128
	header[252] = byte(cipherPadding)

	return header, cipherPadding, nil
}

// UnpackFileHeader unpacks a 256-byte header, extracting salt, iv, and the cipher padding length.
func UnpackFileHeader(header []byte) (salt, iv []byte, cipherPadding int, err error) {
	if len(header) != FileHeaderSize {
		return nil, nil, 0, errors.New("invalid file header size")
	}

	indicator := header[255]
	var ptr1Index int
	if indicator%2 == 0 {
		ptr1Index = 254
	} else {
		ptr1Index = 253
	}

	offsetToken := int(header[ptr1Index])
	if offsetToken+31 > ptr1Index {
		return nil, nil, 0, errors.New("invalid token offset")
	}

	salt = make([]byte, 16)
	copy(salt, header[offsetToken:offsetToken+16])

	iv = make([]byte, 12)
	copy(iv, header[offsetToken+16:offsetToken+28])

	cipherPadding = int(header[252])

	return salt, iv, cipherPadding, nil
}
