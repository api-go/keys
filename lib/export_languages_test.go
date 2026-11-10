package lib_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/api-go/file"
	"github.com/api-go/keys/lib"
)

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := file.Write(filepath.Join(dir, name), content); err != nil {
		t.Fatal(err)
	}
}

func runFixture(t *testing.T, dir, command string, args ...string) {
	t.Helper()
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", command, err, out)
	}
}

func TestExportLanguages(t *testing.T) {
	for _, lang := range []string{"python", "js", "php", "java"} {
		t.Run(lang, func(t *testing.T) {
			runtime := map[string]string{"python": "python3", "js": "node", "php": "php", "java": "java"}[lang]
			if _, err := exec.LookPath(runtime); err != nil {
				t.Skip(err)
			}
			if lang == "java" {
				if _, err := exec.LookPath("javac"); err != nil {
					t.Skip(err)
				}
			}
			for n := 12; n <= 16; n++ {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					iv := "abcdefghijklmnop"[:n]
					code, err := lib.MakeCode(lang, []byte("0123456789abcdef0123456789abcdef"), []byte(iv))
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					switch lang {
					case "python":
						harness := fmt.Sprintf(`
try:
    init_sskey(None)
    raise AssertionError("missing callback accepted")
except TypeError:
    pass
class CallbackFailure(Exception): pass
def fail(k, v): raise CallbackFailure()
try:
    init_sskey(fail)
    raise AssertionError("callback error swallowed")
except CallbackFailure:
    pass
saved = []
init_sskey(lambda k, v: saved.extend([k, v]))
assert saved == [b"0123456789abcdef0123456789abcdef", b%q]
`, iv)
						writeFixture(t, dir, "check.py", code+harness)
						runFixture(t, dir, runtime, "check.py")
					case "js":
						harness := fmt.Sprintf(`
let rejected=false; try {initSSKey(null);} catch(e) {rejected=e instanceof TypeError;}
if(!rejected) throw Error("missing callback accepted");
const failure=new Error("callback failure");
rejected=false; try {initSSKey(()=>{throw failure;});} catch(e) {rejected=e===failure;}
if(!rejected) throw Error("callback error swallowed");
let saved; initSSKey((k,v)=>{saved=[k,v];});
if(Buffer.from(saved[0]).toString()!=="0123456789abcdef0123456789abcdef" || Buffer.from(saved[1]).toString()!==%q) throw Error("mismatch");
`, iv)
						writeFixture(t, dir, "check.js", code+harness)
						runFixture(t, dir, runtime, "check.js")
					case "php":
						writeFixture(t, dir, "keys.php", code)
						harness := fmt.Sprintf(`<?php
$count=0; $saved=null;
function set_sskey($k,$v) { global $count,$saved; if (++$count===1) throw new RuntimeException("callback failure"); $saved=[$k,$v]; }
$failed=false;
try { require 'keys.php'; } catch (RuntimeException $e) { $failed=true; }
if (!$failed) throw new Exception("callback error swallowed");
require 'keys.php';
if ($saved !== [array_values(unpack('C*','0123456789abcdef0123456789abcdef')),array_values(unpack('C*',%q))]) throw new Exception("mismatch");
`, iv)
						writeFixture(t, dir, "check.php", harness)
						runFixture(t, dir, runtime, "check.php")
						writeFixture(t, dir, "missing.php", `<?php
$failed=false;
try { require 'keys.php'; } catch (RuntimeException $e) { $failed=true; }
if (!$failed) throw new Exception("missing callback accepted");
`)
						runFixture(t, dir, runtime, "missing.php")
					case "java":
						writeFixture(t, dir, "SSKeyStarter.java", code)
						writeFixture(t, dir, "SSKeySetter.java", `public class SSKeySetter {
 static int calls=0; static byte[] key,iv;
 public static void set(byte[] k,byte[] v) { if(++calls==1) throw new RuntimeException("callback failure"); key=k; iv=v; }
}`)
						harness := fmt.Sprintf(`import java.util.Arrays;
public class Check {
 public static void main(String[] args) throws Exception {
  boolean failed=false;
  try { SSKeyStarter.init(); } catch(IllegalStateException e) { failed=true; }
  if(!failed) throw new AssertionError("callback failure swallowed");
  Thread[] threads=new Thread[8];
  for(int i=0;i<threads.length;i++) {threads[i]=new Thread(SSKeyStarter::init);threads[i].start();}
  for(Thread t:threads) t.join();
  if(SSKeySetter.calls!=2 || !Arrays.equals(SSKeySetter.key,"0123456789abcdef0123456789abcdef".getBytes()) || !Arrays.equals(SSKeySetter.iv,%q.getBytes())) throw new AssertionError("mismatch or repeated initialization");
 }
}`, iv)
						writeFixture(t, dir, "Check.java", harness)
						runFixture(t, dir, "javac", "SSKeyStarter.java", "SSKeySetter.java", "Check.java")
						runFixture(t, dir, runtime, "-cp", ".", "Check")
					}
				})
			}
		})
	}
}

func TestMakeCodeValidation(t *testing.T) {
	for _, tc := range []struct {
		name, lang string
		key, iv    []byte
	}{
		{"language", "unknown", make([]byte, 32), make([]byte, 12)},
		{"key", "go", make([]byte, 31), make([]byte, 12)},
		{"short-IV", "go", make([]byte, 32), make([]byte, 11)},
		{"long-IV", "go", make([]byte, 32), make([]byte, 17)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, err := lib.MakeCode(tc.lang, tc.key, tc.iv); err == nil || code != "" {
				t.Fatal("invalid export accepted")
			}
		})
	}
}

func BenchmarkMakeCode(b *testing.B) {
	key, iv := make([]byte, 32), make([]byte, 16)
	for _, lang := range []string{"go", "php", "java", "python", "js"} {
		b.Run(lang, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := lib.MakeCode(lang, key, iv); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
