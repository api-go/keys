package lib

import (
	"bytes"
	"errors"
	"text/template"

	"github.com/api-go/safe"
)

var codeTemplates = map[string]string{
	"go":     goTpl,
	"php":    phpTpl,
	"java":   javaTpl,
	"python": pythonTpl,
	"js":     jsTpl,
}

var goTpl = `package main

import (
 "github.com/api-go/crypto"
 "github.com/api-go/safe"
)

// Self-contained obfuscation: all recovery material is embedded.
func init() {
 keyPayload := []byte{ {{range $i, $v := .keyPayload}}{{if $i}},{{end}}{{$v}}{{end}} }
 ivPayload := []byte{ {{range $i, $v := .ivPayload}}{{if $i}},{{end}}{{$v}}{{end}} }
 defer safe.ZeroMemory(keyPayload)
 defer safe.ZeroMemory(ivPayload)
 key, err := safe.OpenSelfContained(keyPayload)
 if err != nil { panic(err) }
 iv, err := safe.OpenSelfContained(ivPayload)
 if err != nil { key.Close(); panic(err) }
 if err := crypto.SetDefaultAESFromSafeBuf(key, iv); err != nil {
  key.Close()
  iv.Close()
  panic(err)
 }
 // Default AES owns key and iv after successful installation.
}
`

var phpTpl = `<?php

$__sskeyStarter = function () {
    if (!function_exists('set_sskey')) throw new \RuntimeException('set_sskey is required');
    $buf = [{{range $i, $v := .buf}}{{if $i}},{{end}}{{$v}}{{end}}];

    $indicator = $buf[127];
    $ptr1Index = ($indicator % 2 == 0) ? 126 : 125;
    
    $offsetK = $buf[$ptr1Index];
    $key = array_slice($buf, $offsetK, 32);
    
    $offsetIV = $buf[$offsetK + 32];
    $iv = array_slice($buf, $offsetIV, $buf[$offsetK + 33]);

    try {
        set_sskey($key, $iv);
    } finally {
        $buf = array_fill(0, count($buf), 0);
    }
};

$__sskeyStarter();
unset($__sskeyStarter);
`

var javaTpl = `
import java.lang.reflect.Method;
import java.util.Arrays;

public final class SSKeyStarter {
    private static boolean inited = false;
    public static synchronized void init() {
        if (inited) return;

        byte[] buf = new byte[]{ {{range $i, $v := .buf}}{{if $i}},{{end}}(byte){{$v}}{{end}} };

        int indicator = buf[127] & 0xFF;
        int ptr1Index = (indicator % 2 == 0) ? 126 : 125;

        int offsetK = buf[ptr1Index] & 0xFF;
        byte[] key = Arrays.copyOfRange(buf, offsetK, offsetK + 32);

        int offsetIV = buf[offsetK + 32] & 0xFF;
        byte[] iv = Arrays.copyOfRange(buf, offsetIV, offsetIV + (buf[offsetK + 33] & 0xFF));

        try {
            Class<?> c = Class.forName("SSKeySetter");
            Method m = c.getMethod("set", byte[].class, byte[].class);
            m.invoke(null, key, iv);
            inited = true;
        } catch (Exception e) {
            throw new IllegalStateException("SSKey initialization failed", e);
        } finally {
            Arrays.fill(buf, (byte) 0);
        }
    }
}
`

var pythonTpl = `
def init_sskey(set_sskey_func):
    if not callable(set_sskey_func):
        raise TypeError("set_sskey_func must be callable")
    buf = [{{range $i, $v := .buf}}{{if $i}},{{end}}{{$v}}{{end}}]

    indicator = buf[127]
    ptr1Index = 126 if indicator % 2 == 0 else 125
    
    offsetK = buf[ptr1Index]
    key = bytes(buf[offsetK : offsetK + 32])
    
    offsetIV = buf[offsetK + 32]
    iv = bytes(buf[offsetIV : offsetIV + buf[offsetK + 33]])
    
    try:
        set_sskey_func(key, iv)
    finally:
        for i in range(len(buf)):
            buf[i] = 0
`

var jsTpl = `
const initSSKey = (setSSKeyFunc) => {
    if (typeof setSSKeyFunc !== 'function') throw new TypeError('setSSKeyFunc must be callable');
    const buf = [{{range $i, $v := .buf}}{{if $i}},{{end}}{{$v}}{{end}}];

    const indicator = buf[127];
    const ptr1Index = (indicator % 2 === 0) ? 126 : 125;
    
    const offsetK = buf[ptr1Index];
    const key = new Uint8Array(buf.slice(offsetK, offsetK + 32));
    
    const offsetIV = buf[offsetK + 32];
    const iv = new Uint8Array(buf.slice(offsetIV, offsetIV + buf[offsetK + 33]));

    try {
        setSSKeyFunc(key, iv);
    } finally {
        buf.fill(0);
    }
};
`

// MakeCode generates integration code. Go uses authenticated self-contained payloads;
// other languages retain the legacy offset buffer. Neither format prevents offline recovery.
func MakeCode(codeName string, key, iv []byte) (string, error) {
	tpl := codeTemplates[codeName]
	if tpl == "" {
		return "", errors.New("tpl not exists: " + codeName)
	}

	if len(key) != 32 || len(iv) < 12 || len(iv) > 16 {
		return "", errors.New("export requires a 32-byte key and 12–16-byte IV")
	}
	data := map[string]interface{}{}
	if codeName == "go" {
		keyPayload, err := makeSelfContainedPayload(key, key, iv)
		if err != nil {
			return "", err
		}
		defer safe.ZeroMemory(keyPayload)
		ivPayload, err := makeSelfContainedPayload(iv, key, iv)
		if err != nil {
			return "", err
		}
		defer safe.ZeroMemory(ivPayload)
		data["keyPayload"], data["ivPayload"] = keyPayload, ivPayload
	} else {
		buf, err := PackMemoryKey(key, iv)
		if err != nil {
			return "", err
		}
		defer safe.ZeroMemory(buf)
		data["buf"] = buf
	}

	t := template.New(codeName)
	t, err := t.Parse(tpl)
	if err != nil {
		return "", err
	}

	out := bytes.NewBuffer(nil)
	defer func() { safe.ZeroMemory(out.Bytes()) }()
	err = t.Execute(out, data)
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// Reject even accidental occurrences of the original key or IV in either payload.
func makeSelfContainedPayload(raw, key, iv []byte) ([]byte, error) {
	secret := safe.NewSafeBuf(raw)
	defer secret.Close()
	for range 16 {
		payload, err := safe.SealSelfContained(secret)
		if err != nil {
			return nil, err
		}
		if !bytes.Contains(payload, key) && !bytes.Contains(payload, iv) {
			return payload, nil
		}
		safe.ZeroMemory(payload)
	}
	return nil, errors.New("could not generate plaintext-free export payload")
}
