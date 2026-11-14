package lib_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/api-go/cast"
	"github.com/api-go/file"
	"github.com/api-go/keys/lib"
	"github.com/api-go/safe"
)

func TestGoSelfContainedPayloads(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for n := 12; n <= 16; n++ {
		iv := []byte("abcdefghijklmnop"[:n])
		var previous string
		for range 4 {
			code, err := lib.MakeCode("go", key, iv)
			if err != nil {
				t.Fatal(err)
			}
			if code == previous {
				t.Fatal("export repeated")
			}
			previous = code
			parsed, err := parser.ParseFile(token.NewFileSet(), "generated.go", code, 0)
			if err != nil {
				t.Fatal(err)
			}
			var payloads [][]byte
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				array, ok := literal.Type.(*ast.ArrayType)
				if !ok {
					return true
				}
				element, ok := array.Elt.(*ast.Ident)
				if !ok || element.Name != "byte" {
					return true
				}
				payload := make([]byte, len(literal.Elts))
				for i, value := range literal.Elts {
					payload[i] = byte(cast.Int(value.(*ast.BasicLit).Value))
				}
				payloads = append(payloads, payload)
				return true
			})
			if len(payloads) != 2 {
				t.Fatalf("expected two payloads, got %d", len(payloads))
			}
			for i, payload := range payloads {
				if bytes.Contains(payload, key) || bytes.Contains(payload, iv) {
					t.Fatal("continuous plaintext in payload")
				}
				secret, err := safe.OpenSelfContained(payload)
				if err != nil {
					t.Fatal(err)
				}
				plain := secret.Open()
				expected := key
				if i == 1 {
					expected = iv
				}
				if !bytes.Equal(plain.Data, expected) {
					t.Fatal("wrong exported secret")
				}
				plain.Close()
				secret.Close()
			}
		}
	}
}

func TestGoExportBinaryAndCorruption(t *testing.T) {
	key := []byte("go-export-unique-key-0123456789a")
	iv := []byte("unique-export-IV")
	code, err := lib.MakeCode("go", key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := file.ReadBytes(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.WriteBytes(filepath.Join(dir, name), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Write(filepath.Join(dir, "main.go"), "package main\nfunc main() {}\n"); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(dir, "keys.go")
	if err := file.Write(generated, code); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "go-keys-export")
	command := exec.Command("go", "build", "-mod=readonly", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	data, err := file.ReadBytes(binary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, key) || bytes.Contains(data, iv) {
		t.Fatal("continuous plaintext in executable")
	}
	if output, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, output)
	}
	broken := strings.Replace(code, "83,66,83,67,1,", "82,66,83,67,1,", 1)
	if broken == code {
		t.Fatal("could not corrupt payload")
	}
	if err := file.Write(generated, broken); err != nil {
		t.Fatal(err)
	}
	command = exec.Command("go", "run", "-mod=readonly", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOWORK=off")
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "invalid self-contained payload") {
		t.Fatalf("corruption did not fail closed: %v %s", err, output)
	}
}
