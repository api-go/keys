package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/api-go/encoding"
	"github.com/api-go/keys/internal/keyagent"
	"github.com/api-go/keys/lib"
	"github.com/api-go/safe"
	"golang.org/x/term"
)

func readHidden(input *os.File, prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	data, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(os.Stderr)
	return data, err
}

func unlockCipherKey(name string) (*lib.KeySet, error) {
	if name != "default" {
		client, err := keyagent.New(lib.GetKeysRootPath())
		if err == nil {
			ks, err := client.UnlockCipher(name)
			if err == nil {
				return ks, nil
			}
			if !errors.Is(err, keyagent.ErrUnavailable) && !errors.Is(err, keyagent.ErrNotKept) {
				return nil, err
			}
		} else if !errors.Is(err, keyagent.ErrUnavailable) {
			return nil, err
		}
		pwd := getMasterPassword()
		defer safe.ZeroMemory(pwd)
		return lib.LoadKeystore(name, pwd)
	}
	return lib.LoadKeystore(name, nil)
}

func handleCipherCmd(name, op string, args []string) error {
	algo, target := "aes-gcm", ""
	hasTarget := false
	for _, arg := range args {
		if isAlgorithmOption(arg) {
			algo = arg[1:]
		} else {
			target, hasTarget = arg, true
		}
	}

	terminal := term.IsTerminal(int(os.Stdin.Fd()))
	piped := !hasTarget && !terminal
	if !hasTarget && terminal && nonInteractive {
		return errors.New("非交互模式需要位置参数或标准输入")
	}
	ks, err := unlockCipherKey(name)
	if err != nil {
		return fmt.Errorf("密钥解锁失败: %w", err)
	}
	defer ks.Close()

	var data []byte
	if hasTarget {
		key, iv, err := ks.GetRaw()
		if err != nil {
			return err
		}
		defer safe.ZeroMemory(key)
		defer safe.ZeroMemory(iv)
		itemAlgo := algo
		if op == "encrypt" {
			itemAlgo = "aes-gcm"
		}
		data, err = lib.LoadPasswordStrict(name, target, key, iv, itemAlgo)
		if err == nil && op == "decrypt" {
			defer safe.ZeroMemory(data)
			return writePlaintext(data, true)
		}
		if err != nil {
			data = []byte(target)
		}
	} else if piped {
		data, err = io.ReadAll(os.Stdin)
	} else {
		prompt := "输入要加密的内容: "
		if op == "decrypt" {
			prompt = "输入密文: "
		}
		data, err = readHidden(os.Stdin, prompt)
	}
	defer safe.ZeroMemory(data)
	if err != nil && !hasTarget {
		return fmt.Errorf("读取输入失败: %w", err)
	}
	if len(data) == 0 {
		return errors.New("没有输入内容")
	}

	sym, err := ks.NewSymmetric(algo)
	if err != nil {
		return fmt.Errorf("算法初始化失败: %w", err)
	}
	defer sym.Close()
	if op == "encrypt" {
		var enc []byte
		switch algo {
		case "aes-gcm", "gcm":
			enc, err = sym.EncryptBytesAutoIV(data)
		default:
			enc, err = sym.EncryptBytes(data)
		}
		if err != nil {
			return fmt.Errorf("加密失败: %w", err)
		}
		_, err = fmt.Fprintln(os.Stdout, encoding.URLBase64(enc))
		return err
	}
	raw, err := encoding.UnURLBase64(bytes.TrimSpace(data))
	if err != nil {
		return errors.New("解密失败: 无效密文")
	}
	dec, err := sym.DecryptBytes(raw)
	defer safe.ZeroMemory(dec)
	if err != nil {
		return errors.New("解密失败: 无效密文、密钥或算法")
	}
	return writePlaintext(dec, !piped)
}

func writePlaintext(data []byte, newline bool) error {
	_, err := os.Stdout.Write(data)
	if err == nil && newline {
		_, err = os.Stdout.WriteString("\n")
	}
	return err
}
