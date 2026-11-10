package lib_test

import (
	"bytes"
	"testing"

	"github.com/api-go/keys/lib"
)

func TestPackUnpackMemoryKey(t *testing.T) {
	key, _ := lib.CryptoRandBytes(32)
	iv, _ := lib.CryptoRandBytes(12)

	buf, err := lib.PackMemoryKey(key, iv)
	if err != nil {
		t.Fatalf("PackMemoryKey failed: %v", err)
	}

	if len(buf) != lib.MemoryKeySize {
		t.Fatalf("PackMemoryKey length = %d, want %d", len(buf), lib.MemoryKeySize)
	}

	unpackedKey, unpackedIv, err := lib.UnpackMemoryKey(buf)
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
	salt, _ := lib.CryptoRandBytes(16)
	iv, _ := lib.CryptoRandBytes(12)

	header, padding, err := lib.PackFileHeader(salt, iv)
	if err != nil {
		t.Fatalf("PackFileHeader failed: %v", err)
	}

	if len(header) != lib.FileHeaderSize {
		t.Fatalf("PackFileHeader length = %d, want %d", len(header), lib.FileHeaderSize)
	}

	unpackedSalt, unpackedIv, unpackedPadding, err := lib.UnpackFileHeader(header)
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
