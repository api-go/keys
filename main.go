package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"apigo.cc/go/encoding"
	"apigo.cc/go/keys/internal/keyagent"
	"apigo.cc/go/keys/lib"
	"apigo.cc/go/safe"
	"apigo.cc/go/shell"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		interactiveKeystoreMode()
		return
	}

	arg1 := os.Args[1]
	if arg1 == "__keys-agent" {
		if len(os.Args) != 3 {
			os.Exit(1)
		}
		client, err := keyagent.New(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := client.Serve(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if arg1 == "keep-key" || arg1 == "forget-key" {
		var err error
		if arg1 == "keep-key" {
			err = handleKeepKey(os.Args[2:])
		} else {
			err = handleForgetKey(os.Args[2:])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// 1. 特殊全局命令 (以 - 开头)
	if strings.HasPrefix(arg1, "-") {
		switch arg1 {
		case "-h", "--help", "-help":
			printUsage()
		case "-setpath":
			if len(os.Args) < 3 {
				fmt.Println(shell.Red("用法: keys -setpath <路径>"))
				os.Exit(1)
			}
			setPath(os.Args[2])
		case "-status":
			showStatus()
		default:
			fmt.Printf("%s: %s\n", shell.Red("未知选项"), arg1)
			printUsage()
		}
		return
	}

	// 2. 密钥管理非交互指令
	switch arg1 {
	case "list":
		handleListKeystores()
		return
	case "create":
		if len(os.Args) < 3 {
			fmt.Println(shell.Red("用法: keys create <密钥名>"))
			os.Exit(1)
		}
		handleCreateKeystore(os.Args[2])
		return
	case "remove":
		if len(os.Args) < 3 {
			fmt.Println(shell.Red("用法: keys remove <密钥名>"))
			os.Exit(1)
		}
		handleRemoveKeystore(os.Args[2])
		return
	case "export":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "用法: keys export <密钥名> <语言>")
			os.Exit(1)
		}
		if err := handleExportKeystore(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// 3. 密码管理指令 (keys <keyname> [cmd])
	keyName := arg1
	// 检查 keyName 是否存在于 keystore
	if keyName != "default" {
		ksPath := filepath.Join(lib.GetKeystorePath(), keyName)
		if _, err := os.Stat(ksPath); err != nil {
			fmt.Printf("%s: 密钥 '%s' 不存在。\n", shell.Red("错误"), keyName)
			fmt.Println("使用 'keys list' 查看可用密钥。")
			os.Exit(1)
		}
	}

	if len(os.Args) == 2 {
		// 进入该密钥的交互式密码管理模式
		interactivePasswordMode(keyName)
		return
	}

	// 非交互式密码管理
	handlePasswordCmd(keyName, os.Args[2:])
}

func setPath(newPath string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(shell.Red("无法获取用户主目录: " + err.Error()))
		os.Exit(1)
	}
	err = os.WriteFile(filepath.Join(homeDir, ".keyspath"), []byte(newPath), 0600)
	if err != nil {
		fmt.Println(shell.Red("保存 .keyspath 失败: " + err.Error()))
		os.Exit(1)
	}
	fmt.Println(shell.Green("存储路径已更新为: " + newPath))
}

func showStatus() {
	root, ksCount, pwCount := lib.GetStatus()
	fmt.Print(shell.Cyan("Keys 系统状态:\n"))
	fmt.Printf("  存储根目录: %s\n", shell.White(root))
	fmt.Printf("  密钥总数:   %d\n", ksCount)
	fmt.Printf("  密码总数:   %d\n", pwCount)
}

func handleListKeystores() {
	fmt.Println(shell.Cyan("可用密钥列表:"))
	fmt.Printf("  - %s %s\n", shell.White("default"), shell.Yellow("(内置默认)"))

	files, err := os.ReadDir(lib.GetKeystorePath())
	if err != nil {
		fmt.Printf("共 1 个密钥\n")
		return
	}
	count := 1
	for _, fi := range files {
		if !fi.IsDir() && !strings.HasPrefix(fi.Name(), ".") {
			fmt.Printf("  - %s\n", shell.White(fi.Name()))
			count++
		}
	}
	fmt.Printf("共 %d 个密钥\n", count)
}

func handleCreateKeystore(name string) {
	pwd := getMasterPassword()
	defer safe.ZeroMemory(pwd)
	ks, err := lib.CreateKeystore(name, pwd)
	if err != nil {
		fmt.Println(shell.Red("创建失败: " + err.Error()))
		os.Exit(1)
	}
	ks.Close()
	fmt.Println(shell.Green("密钥 '" + name + "' 创建成功。"))
}

func handleRemoveKeystore(name string) {
	if err := lib.RemoveKeystore(name); err != nil {
		fmt.Println(shell.Red("删除失败: " + err.Error()))
		os.Exit(1)
	}
	fmt.Println(shell.Green("密钥 '" + name + "' 已删除。"))
}

func handleExportKeystore(name, lang string) error {
	if name != "default" {
		client, err := keyagent.New(lib.GetKeysRootPath())
		if err != nil && !errors.Is(err, keyagent.ErrUnavailable) {
			return err
		}
		if err == nil {
			code, err := client.Export(name, lang)
			if err == nil {
				_, err = fmt.Fprintln(os.Stdout, code)
				return err
			}
			if !errors.Is(err, keyagent.ErrUnavailable) && !errors.Is(err, keyagent.ErrNotKept) {
				return err
			}
		}
	}
	var pwd []byte
	if name != "default" {
		pwd = getMasterPassword()
		defer safe.ZeroMemory(pwd)
	}
	ks, err := lib.LoadKeystore(name, pwd)
	if err != nil {
		return fmt.Errorf("加载失败: %w", err)
	}
	defer ks.Close()
	key, iv, err := ks.GetRaw()
	if err != nil {
		return fmt.Errorf("提取失败: %w", err)
	}
	defer safe.ZeroMemory(key)
	defer safe.ZeroMemory(iv)
	code, err := lib.MakeCode(lang, key, iv)
	if err != nil {
		return fmt.Errorf("导出失败: %w", err)
	}
	_, err = fmt.Fprintln(os.Stdout, code)
	return err
}

func handlePasswordCmd(keyName string, args []string) {
	op := args[0]

	// 下面这些操作通常需要解密 Key，所以统一获取 master password
	var pwd []byte
	if keyName != "default" {
		pwd = getMasterPassword()
		defer safe.ZeroMemory(pwd)
	}

	ks, err := lib.LoadKeystore(keyName, pwd)
	if err != nil {
		fmt.Println(shell.Red("密钥解锁失败: " + err.Error()))
		os.Exit(1)
	}
	defer ks.Close()

	key, iv, err := ks.GetRaw()
	if err != nil {
		fmt.Println(shell.Red("Key 提取失败: " + err.Error()))
		os.Exit(1)
	}

	algo := "aes-gcm"
	target := ""
	var pwdVal []byte

	// 提取参数中的算法和目标
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			algo = a[1:]
		} else {
			if target == "" {
				target = a
			} else {
				pwdVal = []byte(a)
			}
		}
	}

	switch {
	case op == "list":
		pwds, _ := lib.ListPasswords(keyName)
		fmt.Printf("%s 保护的密码项:\n", shell.Cyan("'"+keyName+"'"))
		for _, p := range pwds {
			fmt.Println("  - " + p)
		}
	case op == "create":
		if target == "" || len(pwdVal) == 0 {
			fmt.Println(shell.Red("用法: keys <密钥名> create <路径> <值> [-算法]"))
			os.Exit(1)
		}
		if err := lib.SavePassword(keyName, target, pwdVal, key, iv, algo); err != nil {
			fmt.Println(shell.Red("保存失败: " + err.Error()))
			os.Exit(1)
		}
		fmt.Printf("%s (算法: %s)。\n", shell.Green("保存成功"), algo)
	case op == "remove":
		if target == "" {
			fmt.Println(shell.Red("用法: keys <密钥名> remove <路径>"))
			os.Exit(1)
		}
		if err := lib.RemovePassword(keyName, target); err != nil {
			fmt.Println(shell.Red("删除失败: " + err.Error()))
			os.Exit(1)
		}
		fmt.Println(shell.Green("删除成功。"))
	case op == "encrypt":
		if target == "" {
			fmt.Println(shell.Red("用法: keys <密钥名> encrypt <路径|原文> [-算法]"))
			os.Exit(1)
		}

		// 尝试作为已有项加载
		data, err := lib.LoadPassword(keyName, target, key, iv, "aes-gcm")
		if err != nil || len(data) == 0 {
			data = []byte(target)
		}

		sym, err := ks.NewSymmetric(algo)
		if err != nil {
			fmt.Println(shell.Red("算法初始化失败: " + err.Error()))
			os.Exit(1)
		}
		var enc []byte
		switch algo {
		case "aes-gcm", "gcm", "":
			enc, err = sym.EncryptBytesAutoIV(data)
		default:
			enc, err = sym.EncryptBytes(data)
		}
		sym.Close()
		safe.ZeroMemory(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "加密失败: "+err.Error())
			os.Exit(1)
		}
		fmt.Println(encoding.URLBase64(enc))
	case op == "decrypt":
		if target == "" {
			fmt.Println(shell.Red("用法: keys <密钥名> decrypt <路径|密文> [-算法]"))
			os.Exit(1)
		}

		dec, err := lib.LoadPassword(keyName, target, key, iv, algo)
		if err != nil || len(dec) == 0 {
			// 尝试作为原始密文解密
			rawData, err2 := encoding.UnURLBase64(target)
			if err2 == nil {
				sym, err3 := ks.NewSymmetric(algo)
				if err3 == nil {
					dec2, err4 := sym.DecryptBytes(rawData)
					if err4 == nil {
						fmt.Println(string(dec2))
						return
					}
				}
			}
			// 🛡️ 诱饵模式: 完全失败打印随机字符
			fmt.Println(string(lib.CryptoRandDecoy(12, 24)))
			return
		}
		fmt.Println(string(dec))
	default:
		fmt.Printf("%s: %s\n", shell.Red("未知密码指令"), op)
	}
}

func getMasterPassword() []byte {
	if p := os.Getenv("MASTER_PASSWORD"); p != "" {
		return []byte(p)
	}
	fmt.Fprint(os.Stderr, "输入主密码: ")
	fd := int(os.Stdin.Fd())
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil || len(password) == 0 {
		fmt.Fprintln(os.Stderr, "必须输入密码")
		os.Exit(1)
	}
	return password
}

func printUsage() {
	fmt.Println(shell.Cyan("Keys CLI - 现代化本地 KMS 与密码管理器"))
	fmt.Println(`
用法:
  keys                      启动交互式密钥管理 (Keystore Mode)
  keys <密钥名>             启动该密钥对应的交互式密码管理 (Password Mode)

管理密钥 (非交互):
  keys list                 列出所有密钥
  keys create <名>          创建新密钥
  keys remove <名>          删除密钥
  keys export <名> <语言>   导出混淆代码 (go, php, java, python, js)
  keys keep-key <名> [--ttl 8h]  解锁并在内存中保留密钥（仅供导出）
  keys forget-key <名>          清除该密钥的内存缓存
  keys forget-key --all         清除当前密钥库的全部缓存并停止代理

管理密码 (非交互):
  keys <密钥名> list        列出该密钥下的所有密码项
  keys <密钥名> create <项> <值> [-算法]  创建/更新项 (gcm/cbc/sm4/sm4-cbc)
  keys <密钥名> remove <项> 删除密码项
  keys <密钥名> encrypt <项|原文> [-算法]   加密一段文本
  keys <密钥名> decrypt <项|密文> [-算法]   解密并显示

系统指令:
  keys -status              查看存储路径与统计状态
  keys -setpath <路径>      重定向存储根目录 (持久化到 ~/.keyspath)
  keys -h, --help           显示此帮助信息

环境变量:
  KEYSPATH                  临时指定存储路径
  MASTER_PASSWORD           自动化脚本中传递主密码`)
}

func handleKeepKey(args []string) error {
	usage := errors.New("用法: keys keep-key <密钥名> [--ttl 8h]")
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return usage
	}
	name := args[0]
	options := flag.NewFlagSet("keep-key", flag.ContinueOnError)
	options.SetOutput(os.Stderr)
	ttlText := options.String("ttl", "", "可选有效期，例如 8h")
	if err := options.Parse(args[1:]); err != nil {
		return err
	}
	if options.NArg() != 0 {
		return usage
	}
	var ttl time.Duration
	ttlProvided := false
	options.Visit(func(f *flag.Flag) {
		if f.Name == "ttl" {
			ttlProvided = true
		}
	})
	if ttlProvided {
		var err error
		ttl, err = time.ParseDuration(*ttlText)
		if err != nil || ttl <= 0 {
			return errors.New("TTL 必须是正时长，例如 8h")
		}
	}
	if name == "default" {
		return errors.New("内置 default 密钥无需保留")
	}
	pwd := getMasterPassword()
	defer safe.ZeroMemory(pwd)
	ks, err := lib.LoadKeystore(name, pwd)
	safe.ZeroMemory(pwd)
	if err != nil {
		return err
	}
	defer ks.Close()
	client, err := keyagent.New(lib.GetKeysRootPath())
	if err != nil {
		return err
	}
	if err := client.Keep(ks, ttl, client.StartProcess); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "密钥已临时保留，仅用于导出:", name)
	return nil
}
func handleForgetKey(args []string) error {
	if len(args) != 1 {
		return errors.New("用法: keys forget-key <密钥名> | --all")
	}
	all := args[0] == "--all"
	if !all && strings.HasPrefix(args[0], "-") {
		return errors.New("未知 forget-key 选项")
	}
	client, err := keyagent.New(lib.GetKeysRootPath())
	if err != nil {
		return err
	}
	if err := client.Forget(args[0], all); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "内存缓存已清除")
	return nil
}
