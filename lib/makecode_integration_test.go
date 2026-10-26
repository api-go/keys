package lib_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"apigo.cc/go/file"
	"apigo.cc/go/keys/lib"
)

func TestGoExportInitialization(t *testing.T) {
	for n := 12; n <= 16; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key := []byte("0123456789abcdef0123456789abcdef")
			iv := []byte("abcdefghijklmnop"[:n])
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
			// The generated init deliberately sorts before main.go, so observer registration
			// must be complete during package variable initialization.
			if err := file.Write(filepath.Join(dir, "a_setKeys.go"), code); err != nil {
				t.Fatal(err)
			}
			mainCode := `package main
import (
 "bytes"
 "apigo.cc/go/crypto"
)
var confAES *crypto.Symmetric
var _ = func() bool {
 crypto.OnSetDefaultAES(func(aes *crypto.Symmetric) { confAES = aes })
 return true
}()
func main() {
 if confAES == nil { panic("observer not initialized") }
 expected, err := crypto.NewAESGCMWithoutEraseKey([]byte("0123456789abcdef0123456789abcdef"), []byte("0123456789ab"))
 if err != nil { panic(err) }
 defer expected.Close()
 plain := []byte("keys export integration")
 encrypted, err := expected.EncryptBytes(plain)
 if err != nil { panic(err) }
 decrypted, err := confAES.DecryptBytes(encrypted)
 if err != nil { panic(err) }
 if !bytes.Equal(decrypted, plain) { panic("wrong default AES") }
 a, err := expected.DeriveKey([]byte("full IV check"),32)
 if err != nil { panic(err) }; defer a.Close()
 b, err := confAES.DeriveKey([]byte("full IV check"),32)
 if err != nil { panic(err) }; defer b.Close()
 x,y := a.Open(),b.Open(); defer x.Close();defer y.Close()
 if !bytes.Equal(x.Data,y.Data) {panic("IV truncated")}

}
`
			mainCode = strings.ReplaceAll(mainCode, "0123456789ab\"", string(iv)+"\"")
			if err := file.Write(filepath.Join(dir, "main.go"), mainCode); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "run", "-mod=readonly", ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("generated code failed: %v\n%s", err, output)
			}
		})
	}
}
