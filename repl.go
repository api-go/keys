package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/c-bata/go-prompt"
	"golang.org/x/term"
	"apigo.cc/go/crypto"
	"apigo.cc/go/crypto-sm"
	"apigo.cc/go/encoding"
	"apigo.cc/go/keys/lib"
	"apigo.cc/go/safe"
	"apigo.cc/go/shell"
)

var masterPwd []byte

func interactiveKeystoreMode() {
	masterPwd = getMasterPassword()

	fmt.Println(shell.Cyan("Keys CLI - Keystore Mode"))
	fmt.Println(shell.White("Use Tab or Arrows for auto-completion. Type 'exit' to quit."))

	p := prompt.New(
		executorKeystore,
		completerKeystore,
		prompt.OptionPrefix("keys [keystore]> "),
		prompt.OptionTitle("Keys CLI"),
		prompt.OptionCompletionOnDown(),
	)
	p.Run()
	safe.ZeroMemory(masterPwd)
}

func executorKeystore(in string) {
	in = strings.TrimSpace(in)
	if in == "" {
		return
	}

	args := strings.Fields(in)
	cmd := args[0]

	switch cmd {
	case "exit", "quit":
		safe.ZeroMemory(masterPwd)
		os.Exit(0)
	case "list":
		handleListKeystores()
	case "create":
		if len(args) < 2 {
			fmt.Println(shell.Red("Usage: create <keyname>"))
			return
		}
		ks, err := lib.CreateKeystore(args[1], masterPwd)
		if err != nil {
			fmt.Println(shell.Red("Failed to create keystore: " + err.Error()))
			return
		}
		ks.Close()
		fmt.Println(shell.Green("Keystore created successfully."))
	case "remove":
		if len(args) < 2 {
			fmt.Println(shell.Red("Usage: remove <keyname>"))
			return
		}
		filePath := filepath.Join(lib.GetKeystorePath(), args[1])
		if err := os.Remove(filePath); err != nil {
			fmt.Println(shell.Red("Failed to remove keystore: " + err.Error()))
			return
		}
		fmt.Println(shell.Green("Keystore removed successfully."))
	case "export":
		if len(args) < 3 {
			fmt.Println(shell.Red("Usage: export <keyname> <lang>"))
			return
		}
		var pwd []byte
		if args[1] != "default" {
			pwd = masterPwd
		}
		ks, err := lib.LoadKeystore(args[1], pwd)
		if err != nil {
			fmt.Println(shell.Red("Failed to load keystore: " + err.Error()))
			return
		}
		defer ks.Close()

		key, iv, err := ks.GetRaw()
		if err != nil {
			fmt.Println(shell.Red("Failed to extract raw key/iv: " + err.Error()))
			return
		}

		code, err := lib.MakeCode(args[2], key, iv)
		if err != nil {
			fmt.Println(shell.Red("Failed to export code: " + err.Error()))
			return
		}
		fmt.Println(code)
	case "use":
		if len(args) < 2 {
			fmt.Println(shell.Red("Usage: use <keyname>"))
			return
		}
		keyName := args[1]
		var pwd []byte
		if keyName != "default" {
			pwd = masterPwd
		}
		ks, err := lib.LoadKeystore(keyName, pwd)
		if err != nil {
			fmt.Println(shell.Red("Failed to load keystore: " + err.Error()))
			return
		}
		
		key, iv, err := ks.GetRaw()
		ks.Close()
		
		if err != nil {
			fmt.Println(shell.Red("Failed to extract raw key/iv: " + err.Error()))
			return
		}

		safe.ZeroMemory(masterPwd) // Erase master password from memory
		startPasswordModeLoop(keyName, key, iv)
		os.Exit(0) // Exit when password mode finishes

	default:
		fmt.Println(shell.Red("Unknown command. Try: list, create, remove, export, use, exit"))
	}
}

func completerKeystore(d prompt.Document) []prompt.Suggest {
	text := d.TextBeforeCursor()
	args := strings.Split(text, " ")
	w := d.GetWordBeforeCursor()

	if len(args) <= 1 {
		s := []prompt.Suggest{
			{Text: "list", Description: "列出所有密钥文件"},
			{Text: "create", Description: "[密钥名] 创建新的主密钥"},
			{Text: "remove", Description: "[密钥名] 永久删除指定密钥"},
			{Text: "export", Description: "[密钥名] [语言] 导出应用集成混淆代码"},
			{Text: "use", Description: "[密钥名] 解锁并进入该密钥的密码管理模式"},
			{Text: "exit", Description: "安全退出"},
		}
		return prompt.FilterHasPrefix(s, w, true)
	}

	cmd := args[0]

	getKeystores := func() []prompt.Suggest {
		keyPath := lib.GetKeystorePath()
		files, _ := os.ReadDir(keyPath)
		var ks []prompt.Suggest
		ks = append(ks, prompt.Suggest{Text: "default", Description: "内置基础设施默认密钥 (无需密码)"})
		for _, fi := range files {
			if !fi.IsDir() && !strings.HasPrefix(fi.Name(), ".") {
				ks = append(ks, prompt.Suggest{Text: fi.Name(), Description: "密钥文件"})
			}
		}
		return ks
	}

	switch cmd {
	case "remove", "use":
		if len(args) == 2 {
			suggestions := getKeystores()
			if len(suggestions) == 0 {
				return []prompt.Suggest{{Text: "", Description: "请先创建密钥"}}
			}
			return prompt.FilterHasPrefix(suggestions, w, true)
		}
	case "create":
		if len(args) == 2 && w == "" {
			return []prompt.Suggest{{Text: "", Description: "<请输入新密钥名称>"}}
		}
	case "export":
		if len(args) == 2 {
			return prompt.FilterHasPrefix(getKeystores(), w, true)
		}
		if len(args) == 3 {
			s := []prompt.Suggest{
				{Text: "go", Description: "导出 Go 混淆代码"},
				{Text: "php", Description: "导出 PHP 混淆代码"},
				{Text: "java", Description: "导出 Java 混淆代码"},
				{Text: "python", Description: "导出 Python 混淆代码"},
				{Text: "js", Description: "导出 JavaScript 混淆代码"},
			}
			return prompt.FilterHasPrefix(s, w, true)
		}
	}

	return []prompt.Suggest{}
}

func interactivePasswordMode(keyName string) {
	var pwd []byte
	if keyName != "default" {
		pwd = getMasterPassword()
	}
	ks, err := lib.LoadKeystore(keyName, pwd)
	if err != nil {
		fmt.Println(shell.Red("Failed to load keystore: " + err.Error()))
		os.Exit(1)
	}
	key, iv, err := ks.GetRaw()
	ks.Close()
	if len(pwd) > 0 {
		safe.ZeroMemory(pwd)
	}
	
	if err != nil {
		fmt.Println(shell.Red("Failed to extract raw key/iv: " + err.Error()))
		os.Exit(1)
	}

	startPasswordModeLoop(keyName, key, iv)
}

var activeKeyName string
var activeKey []byte
var activeIV []byte

func startPasswordModeLoop(keyName string, key, iv []byte) {
	activeKeyName = keyName
	activeKey = key
	activeIV = iv

	fmt.Println(shell.Cyan("Keys CLI - Password Mode for [" + keyName + "]"))
	
	p := prompt.New(
		executorPassword,
		completerPassword,
		prompt.OptionPrefix("keys ["+keyName+"]> "),
		prompt.OptionTitle("Keys CLI - "+keyName),
		prompt.OptionCompletionOnDown(),
	)
	p.Run()

	safe.ZeroMemory(activeKey)
	safe.ZeroMemory(activeIV)
}

func executorPassword(in string) {
	in = strings.TrimSpace(in)
	if in == "" {
		return
	}

	args := strings.Fields(in)
	cmd := args[0]

	switch cmd {
	case "exit", "quit":
		safe.ZeroMemory(activeKey)
		safe.ZeroMemory(activeIV)
		os.Exit(0)
	case "list":
		pwds, err := lib.ListPasswords(activeKeyName)
		if err != nil {
			fmt.Println(shell.Red("Failed to list passwords: " + err.Error()))
			return
		}
		if len(pwds) == 0 {
			fmt.Println(shell.Yellow("No passwords found."))
			return
		}
		for _, p := range pwds {
			fmt.Println("  - " + shell.White(p))
		}
	case "create":
		if len(args) < 2 {
			fmt.Println(shell.Red("用法: create <路径> [-gcm|-cbc|-sm4|-sm4-cbc]"))
			return
		}
		pwdPath := args[1]
		algo := "aes-gcm"
		for _, a := range args[2:] {
			if strings.HasPrefix(a, "-") {
				algo = a[1:]
			}
		}
		
		fmt.Print("Enter password value: ")
		fd := int(os.Stdin.Fd())
		pwdBytes, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil || len(pwdBytes) == 0 {
			fmt.Println(shell.Red("Password value is required"))
			return
		}

		if err := lib.SavePassword(activeKeyName, pwdPath, pwdBytes, activeKey, activeIV, algo); err != nil {
			fmt.Println(shell.Red("Failed to save password: " + err.Error()))
			return
		}
		fmt.Println(shell.Green("Password saved successfully using " + algo))
	case "remove":
		if len(args) < 2 {
			fmt.Println(shell.Red("Usage: remove <pwd.path.name>"))
			return
		}
		pwdName := args[1]
		if err := lib.RemovePassword(activeKeyName, pwdName); err != nil {
			fmt.Println(shell.Red("Failed to remove password: " + err.Error()))
			return
		}
		fmt.Println(shell.Green("Password removed successfully."))
	case "encrypt":
		var rawText []byte
		algo := "aes-gcm"
		target := ""
		
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "-") {
				algo = a[1:]
			} else {
				target = a
			}
		}

		if target != "" {
			// Encrypt an existing password item
			dec, err := lib.LoadPassword(activeKeyName, target, activeKey, activeIV, "aes-gcm") // Assume stored is GCM
			if err != nil {
				fmt.Println(shell.Red("Failed to load password: " + err.Error()))
				return
			}
			rawText = dec
		} else {
			// Encrypt custom text
			fmt.Print("Enter text to encrypt: ")
			fd := int(os.Stdin.Fd())
			txtBytes, err := term.ReadPassword(fd)
			fmt.Println()
			if err != nil || len(txtBytes) == 0 {
				fmt.Println(shell.Red("Text is required"))
				return
			}
			rawText = txtBytes
		}
		
		encData, err := encryptEphemeral(activeKey, activeIV, algo, rawText)
		if err != nil {
			fmt.Println(shell.Red("Encryption failed: " + err.Error()))
			return
		}
		fmt.Println(shell.Yellow(encoding.URLBase64(encData)))

	case "decrypt":
		if len(args) < 2 {
			fmt.Println(shell.Red("用法: decrypt <路径|密文> [-算法]"))
			return
		}
		
		target := ""
		algo := "aes-gcm"
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "-") {
				algo = a[1:]
			} else {
				target = a
			}
		}

		dec, err := lib.LoadPassword(activeKeyName, target, activeKey, activeIV, algo)
		if err != nil || len(dec) == 0 {
			// Try as raw ciphertext
			rawData, err2 := encoding.UnUrlBase64FromString(target)
			if err2 == nil {
				dec2, err3 := decryptEphemeral(activeKey, activeIV, algo, rawData)
				if err3 == nil {
					dec = dec2
				} else {
					// Silent failure: return random decoy
					dec = lib.CryptoRandDecoy(12, 24)
				}
			} else {
				fmt.Println(shell.Red("Failed to decrypt: invalid path or Base64."))
				return
			}
		}
		printSecretAndErase(string(dec), 10)
	case "back":
		// Return to keystore mode
		safe.ZeroMemory(activeKey)
		safe.ZeroMemory(activeIV)
		fmt.Println(shell.Yellow("Returning to keystore mode..."))
		interactiveKeystoreMode()
		os.Exit(0)
	default:
		fmt.Println(shell.Red("Unknown command. Try: list, create, remove, encrypt, decrypt, back, exit"))
	}
}

func completerPassword(d prompt.Document) []prompt.Suggest {
	text := d.TextBeforeCursor()
	args := strings.Split(text, " ")
	w := d.GetWordBeforeCursor()
	
	if len(args) <= 1 {
		s := []prompt.Suggest{
			{Text: "list", Description: "列出该密钥下的所有密码项"},
			{Text: "create", Description: "[路径] [-算法] 创建新密码项"},
			{Text: "remove", Description: "[路径] 删除指定密码项"},
			{Text: "encrypt", Description: "[路径|空] [-算法] 加密 (不回显)"},
			{Text: "decrypt", Description: "[路径|密文] [-算法] 解密查看 (10s 阅后即焚)"},
			{Text: "back", Description: "锁定当前密钥，返回密钥管理"},
			{Text: "exit", Description: "安全退出"},
		}
		return prompt.FilterHasPrefix(s, w, true)
	}

	cmd := args[0]

	getPasswords := func() []prompt.Suggest {
		pwds, _ := lib.ListPasswords(activeKeyName)
		var ds []prompt.Suggest
		for _, p := range pwds {
			ds = append(ds, prompt.Suggest{Text: p, Description: "密码项"})
		}
		return ds
	}

	getAlgos := func() []prompt.Suggest {
		return []prompt.Suggest{
			{Text: "-gcm", Description: "AES-GCM (默认)"},
			{Text: "-cbc", Description: "AES-CBC"},
			{Text: "-sm4", Description: "SM4-GCM"},
			{Text: "-sm4-cbc", Description: "SM4-CBC"},
		}
	}

	switch cmd {
	case "remove", "decrypt", "encrypt":
		if len(args) == 2 {
			suggestions := getPasswords()
			if strings.HasPrefix(w, "-") {
				return prompt.FilterHasPrefix(getAlgos(), w, true)
			}
			return prompt.FilterHasPrefix(suggestions, w, true)
		}
		if len(args) >= 3 && strings.HasPrefix(w, "-") {
			return prompt.FilterHasPrefix(getAlgos(), w, true)
		}
	case "create":
		if len(args) == 2 {
			if strings.HasPrefix(w, "-") {
				return prompt.FilterHasPrefix(getAlgos(), w, true)
			}
			if w == "" {
				return []prompt.Suggest{{Text: "", Description: "<请输入路径，如 mail/user@apigo.cc>"}}
			}
		}
		if len(args) >= 3 && strings.HasPrefix(w, "-") {
			return prompt.FilterHasPrefix(getAlgos(), w, true)
		}
	}
	
	return []prompt.Suggest{}
}

func encryptEphemeral(key, iv []byte, algo string, data []byte) ([]byte, error) {
	var sym *crypto.Symmetric
	var err error

	k := append([]byte(nil), key...)
	v := append([]byte(nil), iv...)
	defer safe.ZeroMemory(k)
	defer safe.ZeroMemory(v)

	switch algo {
	case "aes-gcm":
		sym, err = crypto.NewAESGCMWithoutEraseKey(k, v)
	case "aes-cbc":
		sym, err = crypto.NewAESCBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	case "sm4-gcm":
		sym, err = sm.NewSM4GCMWithoutEraseKey(k, v)
	case "sm4-cbc":
		sym, err = sm.NewSM4CBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algo)
	}

	if err != nil {
		return nil, err
	}
	return sym.EncryptBytes(data)
}

func decryptEphemeral(key, iv []byte, algo string, data []byte) ([]byte, error) {
	var sym *crypto.Symmetric
	var err error

	k := append([]byte(nil), key...)
	v := append([]byte(nil), iv...)
	defer safe.ZeroMemory(k)
	defer safe.ZeroMemory(v)

	switch algo {
	case "aes-gcm":
		sym, err = crypto.NewAESGCMWithoutEraseKey(k, v)
	case "aes-cbc":
		sym, err = crypto.NewAESCBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	case "sm4-gcm":
		sym, err = sm.NewSM4GCMWithoutEraseKey(k, v)
	case "sm4-cbc":
		sym, err = sm.NewSM4CBCWithoutEraseKey(k, append(v, 0, 0, 0, 0))
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algo)
	}

	if err != nil {
		return nil, err
	}
	return sym.DecryptBytes(data)
}

func printSecretAndErase(secret string, seconds int) {
	fmt.Printf("%s: %s\n", shell.Cyan("解密结果"), shell.Yellow(secret))
	fmt.Printf("%s %s %s\n", shell.White("倒计时自动擦除，或按"), shell.Red("[ESC]"), shell.White("立即擦除"))

	cancel := make(chan struct{}, 1)
	go func() {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)

		b := make([]byte, 1)
		for {
			_, err := os.Stdin.Read(b)
			if err != nil {
				break
			}
			if b[0] == 27 { // ESC
				cancel <- struct{}{}
				break
			}
		}
	}()

loop:
	for i := seconds; i > 0; i-- {
		select {
		case <-cancel:
			break loop
		default:
			fmt.Printf("\r%s %s   ", shell.White("阅后即焚倒计时:"), shell.Red(fmt.Sprintf("%ds", i)))
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Print("\r\033[2K")      
	fmt.Print("\033[1A\033[2K") 
	fmt.Print("\r\033[1A\033[2K")
	fmt.Println(shell.Green("内容已安全擦除。"))
}
