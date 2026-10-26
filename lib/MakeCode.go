package lib

import (
	"bytes"
	"errors"
	"text/template"

	"apigo.cc/go/safe"
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
	"apigo.cc/go/crypto"
	"apigo.cc/go/safe"
)

func init() {
	buf := []byte{ {{range $i, $v := .buf}}{{if $i}},{{end}}{{$v}}{{end}} }

	// 锁定内存防止交换到磁盘
	_ = safe.LockMemory(buf)
	defer safe.UnlockMemory(buf)
	defer safe.ZeroMemory(buf)

	indicator := buf[127]
	ptr1Index := 126
	if indicator%2 != 0 {
		ptr1Index = 125
	}

	offsetK := int(buf[ptr1Index])
	key := buf[offsetK : offsetK+32]

	offsetIV := int(buf[offsetK+32])
	iv := buf[offsetIV : offsetIV+int(buf[offsetK+33])]

	safeKey := safe.NewSafeBufAndErase(append([]byte(nil), key...))
	safeIv := safe.NewSafeBufAndErase(append([]byte(nil), iv...))
	defer safeKey.Close()
	defer safeIv.Close()

	pKey := safeKey.Open()
	defer pKey.Close()
	pIv := safeIv.Open()
	defer pIv.Close()

	crypto.SetDefaultAES(pKey.Data, pIv.Data)
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

// MakeCode generates application integration code containing the dynamic obfuscated buffer.
func MakeCode(codeName string, key, iv []byte) (string, error) {
	tpl := codeTemplates[codeName]
	if tpl == "" {
		return "", errors.New("tpl not exists: " + codeName)
	}

	// Re-pack into 128 byte dynamically obfuscated buffer
	buf, err := PackMemoryKey(key, iv)
	if err != nil {
		return "", err
	}

	defer safe.ZeroMemory(buf)

	data := map[string]interface{}{
		"buf": buf,
	}

	t := template.New(codeName)
	t, err = t.Parse(tpl)
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
