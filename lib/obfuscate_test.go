package lib

import (
	"bytes"
	"testing"
)

func TestPackUnpackMemoryKey(t *testing.T) {
	key, _ := CryptoRandBytes(32)
	iv, _ := CryptoRandBytes(12)

	buf, err := PackMemoryKey(key, iv)
	if err != nil {
		t.Fatalf("PackMemoryKey failed: %v", err)
	}

	if len(buf) != MemoryKeySize {
		t.Fatalf("PackMemoryKey length = %d, want %d", len(buf), MemoryKeySize)
	}

	unpackedKey, unpackedIv, err := UnpackMemoryKey(buf)
	if err != nil {
		t.Fatalf("UnpackMemoryKey failed: %v", err)
	}

	if !bytes.Equal(key, unpackedKey) {
		t.Errorf("unpacked key != original key")
	}

	if !bytes.Equal(iv, unpackedIv) {
		t.Errorf("unpacked iv != original iv")
	}
}

func TestPackUnpackFileHeader(t *testing.T) {
	salt, _ := CryptoRandBytes(16)
	iv, _ := CryptoRandBytes(12)

	header, padding, err := PackFileHeader(salt, iv)
	if err != nil {
		t.Fatalf("PackFileHeader failed: %v", err)
	}

	if len(header) != FileHeaderSize {
		t.Fatalf("PackFileHeader length = %d, want %d", len(header), FileHeaderSize)
	}

	unpackedSalt, unpackedIv, unpackedPadding, err := UnpackFileHeader(header)
	if err != nil {
		t.Fatalf("UnpackFileHeader failed: %v", err)
	}

	if !bytes.Equal(salt, unpackedSalt) {
		t.Errorf("unpacked salt != original salt")
	}

	if !bytes.Equal(iv, unpackedIv) {
		t.Errorf("unpacked iv != original iv")
	}

	if padding != unpackedPadding {
		t.Errorf("unpacked padding = %d, want %d", unpackedPadding, padding)
	}
}
