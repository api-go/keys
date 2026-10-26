# Keys CLI

`@go/keys` 是一款基于 `@go/crypto` 和 `@go/safe` 构建的**现代化本地 KMS (Key Management System) 与密码管理器**。旨在提供极高安全标准的密钥全生命周期管理，并支持跨语言的安全代码集成。

## 🎯 设计哲学

* **安全第一**：纯二进制存储，彻底抹除文件固定特征码；使用 `crypto/rand` 替代 `math/rand`；解密输出阅后即焚（10秒自动擦除）。
* **动态混淆 (Dynamic Obfuscation)**：内存与磁盘的数据格式均采用**奇偶指针 + 链式偏移量**的设计，使得 Key/IV/Salt 的位置完全随机且无规律。
* **双模式架构**：分离“密钥管理 (Keystore)”与“密码管理 (Password)”，提供沉浸式的交互式 REPL 体验。
* **内存安全**：基于 `@go/safe`，主密码与实际密钥在运行期常驻 `SafeBuf`，使用完毕即刻内存擦除，防范内存扫描泄露。

## 🚀 命令行指南

```text
Keys CLI - 现代化本地 KMS 与密码管理器

用法:
  keys                      启动交互式密钥管理模式 (Key Manager)
  keys <keyname>            启动交互式密码管理模式 (Password Manager)
  
  # 非交互模式 (自动化测试与脚本友好，便于 CI/CD 和自动化流)
  keys list
  keys create <keyname>
  keys remove <keyname>
  keys export <keyname> <go|php|java|python|js>
  
  keys <keyname> list
  keys <keyname> create <pwd.path.name> <value>
  keys <keyname> remove <pwd.path.name>
  keys <keyname> encrypt <pwd.path.name | raw_text>  (参数会出现在进程命令行中)
  keys <keyname> decrypt <pwd.path.name | ciphertext>

环境变量:
  KEYSPATH                  指定数据根目录 (默认依序检查 ~/.keyspath，再 fallback 到 ~/.keys)
  MASTER_PASSWORD           非交互模式下通过环境变量传递主密码

安全特性:
  - 无痕存储：纯二进制写入，动态混淆偏移量，文件无固定特征码。
  - 强随机数：全局摒弃 math/rand，核心加密全部使用 crypto/rand。
  - 防偷窥：终端解密输出明文 10 秒后自动擦除。
  - 防内存扫描：运行期 KeyBuf 在使用完毕后即刻擦除，绝不长留。
```

## 🛠 交互模式效果预览

**1. 密钥管理模式 (Keystore Mode)**
```text
$ keys
Enter Master Password: (不回显)
keys [keystore]> [Tab触发下拉提示]
  list      - 列出所有主密钥
  create    - 创建新的主密钥
  use       - 使用某密钥进入密码管理模式
  export    - 导出混淆后的应用集成代码
keys [keystore]> use db-prod
```

**2. 密码管理模式 (Password Mode)**
```text
keys [db-prod]> [Tab触发下拉提示]
  list      - 列出所有被 db-prod 保护的密码项
  create    - 添加新密码项 (如 db.mysql.root 123456)
  encrypt   - 临时加密一段文本或已有密码项 (参数会出现在进程命令行中)
  decrypt   - 解密密码项 (10秒后清屏)
  back      - 返回密钥管理模式
keys [db-prod]> decrypt db.mysql.root
> 123456 (剩余 10s...)  # 倒计时结束当前行被清除
```

## Go 应用接入

导出的 Go 文件属于 `package main`，在 `init()` 中直接调用
`crypto.SetDefaultAES`，无需声明 `setSSKey`。应用需依赖 `apigo.cc/go/crypto`
与 `apigo.cc/go/safe`。原始混淆缓冲区在退出初始化时先擦除，再解锁内存。

在包变量初始化阶段注册观察者，保证早于同包生成文件的所有 `init()`：

```go
var confAES *crypto.Symmetric

var _ = func() bool {
    crypto.OnSetDefaultAES(func(aes *crypto.Symmetric) {
        confAES = aes
    })
    return true
}()
```

`SetDefaultAES` 成功设置后关闭观察者注册，因此不要依赖跨文件 `init()` 的顺序。
被导入包的初始化早于 `main` 包，不能在其初始化时依赖本文件注入的密钥。
既有导出文件需重新导出，并移除应用中旧的 `setSSKey` 适配。

## 跨语言接入与导出约定

- Go/PHP/Java/Python/JS 均按格式中记录的实际长度恢复 12～16 字节 IV。
- PHP：先定义 `set_sskey($key, $iv)`，再包含导出文件；参数为整数数组。
- Java：将文件命名为 `SSKeyStarter.java`，提供公开 `SSKeySetter.set(byte[], byte[])`，调用 `SSKeyStarter.init()`；初始化串行执行，成功一次后跳过，失败抛异常并允许重试。
- Python：调用 `init_sskey(callback)`，参数为 `bytes`；JS：调用 `initSSKey(callback)`，参数为 `Uint8Array`。
- PHP、Python、JS 缺回调或回调抛异常时明确失败。四种语言均清理本地混淆数组；传给回调的 Key/IV 由应用管理，不在回调返回后清零，以兼容保留参数的应用。托管语言不能保证物理内存擦除。
- 非交互导出只在 stdout 输出源码；提示与错误输出到 stderr，失败退出码非零。可用 `MASTER_PASSWORD` 避免交互；没有终端且没有密码时失败。可通过下述 `keep-key` 临时授权导出；不提供密码文件。
- 错误主密码、密钥文件认证失败或结构无效均返回错误，不返回随机 KeySet。密钥创建不允许空密码或覆盖现存文件，`default` 为保留内置名称。
- 密钥名必须为非隐藏的单个文件名；密码项允许相对多层目录，不允许绝对路径、`..`、反斜杠或冒号。实际读写限制在对应存储目录内；列表遇到符号链接会报错。
- Unix 新建密钥/密码文件权限为 `0600`；密码文件更新时也收紧权限。Windows 权限取决于用户目录的 ACL，`0600` 不等于独立的 Windows ACL 策略。

## Library API (`apigo.cc/go/keys/lib`)

- 密钥：`CreateKeystore`、`LoadKeystore`、`GetDefaultKeySet`、`RemoveKeystore`、`HasMasterPassword`；`KeySet.Close/GetRaw/NewSymmetric/SourceFingerprint`。`GetRaw` 返回明文副本，调用方负责 `safe.ZeroMemory`。
- 密码项：`SavePassword`、`LoadPassword`、`RemovePassword`、`ListPasswords`；`PwdNameToPath` 仅返回输入，不执行权限验证。
- 导出/格式：`MakeCode`、`PackMemoryKey`、`UnpackMemoryKey`、`PackFileHeader`、`UnpackFileHeader`；常量 `MemoryKeySize`、`FileHeaderSize`、`DefaultKey`、`DefaultIV`。导出源码包含可恢复的密钥，按密钥材料管理。
- 路径/状态：`GetKeysRootPath`、`GetKeystorePath`、`GetPasswordBasePath`、`GetPasswordPath`、`EnsureDir`、`GetStatus`；路径构造函数本身不授权文件访问。
- 随机：`CryptoRandBytes`、`CryptoRandDecoy`。

SM4 使用主密钥前 16 字节（SM4 固定要求 128 位密钥）；AES 使用完整 32 字节主密钥。

平台验证：本轮已在 macOS 执行测试。lib 可交叉编译到 Windows；CLI 当前受 shell v1.5.8 的 Unix 系统调用平台隔离问题阻塞，尚不能标为 Windows 可用。

## 临时保留密钥，免密码导出

```sh
keys keep-key xxx                 # 验证主密码，临时保留该密钥
keys export xxx go > setKeys.go   # 另一个终端也可直接导出
keys keep-key xxx --ttl 8h        # 可选有效期，重复执行会替换缓存及期限
keys forget-key xxx                  # 立即清除指定密钥
keys forget-key --all                # 清除当前密钥库的全部缓存，并停止代理
```

- 首次 `keep-key` 自动启动当前用户的后台代理；不安装系统服务，不注册开机启动。
- 默认保留到代理退出或电脑重启；崩溃后不会从磁盘恢复授权。设置 `--ttl` 后，到期立即拒绝导出，后台清理的最大正常扫描间隔为一秒。
- 授权按密钥库的规范绝对路径及密钥名隔离。`forget-key --all` 只影响当前 `KEYSPATH`（或默认路径）对应的代理。改变存储路径后需重新授权。
- 缓存只供 `keys export` 使用；创建、删除、读取密码项及加解密命令仍使用原有主密码流程。没有缓存时，导出回退到 `MASTER_PASSWORD` 或终端输入；非交互且无凭证则失败。
- 代理保存 SafeBuf 保护的已解锁 Key/IV，不接收或保存主密码；启动时移除继承的 `MASTER_PASSWORD` 环境变量。每次导出检查原加密密钥文件的 SHA-256 指纹，文件变化或缺失即删除对应缓存；再次 `keep-key` 必须重新验证密码。
- macOS/Linux 使用临时目录中当前用户拥有的 `0700` 私有目录、`0600` Unix socket，并双向验证连接对端 UID。目录中的空 `.lock` 文件只用于内核独占锁，没有密钥或口令；进程退出/重启后锁失效，残留文件不恢复授权。
- Windows 代理通信使用命名管道，显式 DACL 限定当前登录身份，拒绝远程连接，并双向校验对端进程登录身份；不写凭证文件。代理库已完成 Windows 编译检查，但 CLI 仍受上述 shell 依赖问题阻塞，未进行 Windows 实机验证。
- `forget-key --all` 立即清理缓存；无任何缓存的代理空闲 30 秒后自动退出。缓存清除及正常退出会关闭 SafeBuf，异常进程退出由操作系统回收内存。
- 权限边界是操作系统用户/登录身份；同一身份下其他进程及管理员不属于被隔离对象。
