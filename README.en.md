# Keys CLI

Local key and password management with obfuscated integration code exports.
See [the CLI guide](README.md) for commands and usage.

## AES-GCM wire format

Keystore/password writes and CLI/REPL AES-GCM encryption now produce
`12-byte random IV || ciphertext || 16-byte tag`, without a custom header or
padding. Existing file headers and exported key/IV callbacks remain intact.
Readers accept both embedded-IV and legacy configured-IV ciphertext. Reading
old files does not rewrite them; password updates write the new format.

Upgrade receivers first; old versions cannot read new ciphertext. Retain exported
IVs for legacy reads and stable derivation. Generated Go SetDefaultAES instances
read both formats; new application writes should use EncryptBytesAutoIV,
EncryptAutoIV or EncryptAndEraseAutoIV. KeySet.NewSymmetric retains its existing
semantics: explicitly call EncryptBytesAutoIV for AES-GCM writes. CBC/SM4 options
retain their existing formats. Rotate keys before 2^32 random-nonce encryptions
across all processes, and consider new keys when migrating from nonce reuse.

Release validation uses GOWORK=off with published crypto v1.5.9 and crypto-sm v1.5.8, without local replacements.

## Go integration

Generated Go files use `package main` and call `crypto.SetDefaultAES` directly
in `init()`. The application needs `github.com/api-go/crypto` and `github.com/api-go/safe`.
The original obfuscated buffer is erased before its memory is unlocked.
Regenerate existing exports and remove the old application `setSSKey` adapter.

Register observers during package variable initialization, before every `init()`
in the same package:

```go
var confAES *crypto.Symmetric

var _ = func() bool {
    crypto.OnSetDefaultAES(func(aes *crypto.Symmetric) {
        confAES = aes
    })
    return true
}()
```

A successful `SetDefaultAES` closes observer registration. Avoid depending on
file ordering. Imported packages initialize before `main`, so their initialization
cannot depend on keys injected by the generated `main` package file.

## Export and storage contracts

All five languages preserve the stored IV length (12–16 bytes). PHP requires
`set_sskey(array, array)` before including the file. Java requires a public
`SSKeySetter.set(byte[], byte[])` and an explicit `SSKeyStarter.init()` call;
initialization is synchronized, successful only once, and retryable after failure.
Python uses `init_sskey(callback)` with bytes; JavaScript uses
`initSSKey(callback)` with Uint8Array. Missing callbacks and callback errors fail
explicitly. Local obfuscated arrays are cleared; callback arguments remain
application-owned. Managed runtimes cannot guarantee physical memory erasure.

`keys export <name> <language>` writes source only to stdout, diagnostics to
stderr, and exits nonzero on failure. `MASTER_PASSWORD` enables noninteractive
use. Use `keep-key` for temporary export authorization; password files are not supported. Wrong master
passwords and invalid key files return errors rather than random keysets.
Creation requires a nonempty password and never overwrites existing keys.

Key names must be single non-hidden filenames. Password paths may contain
relative subdirectories, but cannot contain traversal components, backslashes,
or colons. Descriptor-relative operations confine access to the store, including
symlink traversal. Listing password files rejects symlinks. Secret files are
created with Unix mode 0600; password updates also restrict existing permissions.
On Windows, access depends on the user directory ACL; mode 0600 is not a separate
Windows ACL policy.

## Library API

- Keys: `CreateKeystore`, `LoadKeystore`, `GetDefaultKeySet`, `RemoveKeystore`, `HasMasterPassword`; `KeySet.Close/GetRaw/NewSymmetric/SourceFingerprint`. Erase the plaintext copies returned by `GetRaw`.
- Passwords: `SavePassword`, `LoadPassword`, `RemovePassword`, `ListPasswords`, `PwdNameToPath` (identity conversion only).
- Exports/format: `MakeCode`, `PackMemoryKey`, `UnpackMemoryKey`, `PackFileHeader`, `UnpackFileHeader`; constants `MemoryKeySize`, `FileHeaderSize`, `DefaultKey`, `DefaultIV`. Generated source contains recoverable key material.
- Paths/status: `GetKeysRootPath`, `GetKeystorePath`, `GetPasswordBasePath`, `GetPasswordPath`, `EnsureDir`, `GetStatus`. Path constructors do not authorize file access.
- Random helpers: `CryptoRandBytes`, `CryptoRandDecoy`.

SM4 uses the first 16 bytes of the master key (128-bit SM4 key); AES uses all 32 bytes.

Platform validation: tests ran on macOS. The library cross-compiles for Windows; the CLI currently fails to build because shell v1.5.8 has unguarded Unix system calls. Windows CLI support is not verified.

## Temporary export authorization

```sh
keys keep-key xxx
keys export xxx go > setKeys.go
keys keep-key xxx --ttl 8h
keys forget-key xxx
keys forget-key --all
```

`keep-key` validates the master password and starts a per-user background agent
when needed. Other terminals can export the authorized key without prompting.
The default lifetime ends when the agent exits or the computer restarts; an
optional positive TTL expires access immediately, with background erasure on a
one-second scan. Keeping the key again replaces its cache and deadline.

Only export uses this authorization. Password commands retain their normal
master-password requirement. Cache misses fall back to MASTER_PASSWORD or a
terminal prompt; noninteractive commands without credentials fail. Authorization
is scoped to the canonical keystore root and key name; `forget-key --all` applies to
the current store and stops that agent. Empty agents exit after 30 idle seconds.

The agent holds unlocked Key/IV in SafeBuf, never receives the master password,
and is launched without MASTER_PASSWORD in its environment. Every export checks
the encrypted source file fingerprint. Changes or deletion invalidate the cache.
`KeySet.SourceFingerprint` identifies the source snapshot used when loading or
creating a key; it is not an authentication credential.

On macOS/Linux, the agent uses an owner-only 0700 temporary directory and a 0600
Unix socket, with peer UID checks in both directions. Empty lock files contain
no credentials and cannot restore authorization after process exit or reboot.
Windows uses local named pipes, an explicit current-logon DACL, and peer-process
logon checks. The agent package cross-compiles, but the CLI remains blocked by
the shell dependency noted above; Windows runtime behavior is unverified.
No service, startup registration, or persistent credential is created. The trust
boundary is the OS user/logon; it does not isolate other processes of that user
or administrators.
