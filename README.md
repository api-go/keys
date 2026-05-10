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
  keys cmd keystore list
  keys cmd keystore create <keyname>
  keys cmd keystore remove <keyname>
  keys cmd keystore export <keyname> <filepath.ext>
  
  keys cmd password <keyname> list
  keys cmd password <keyname> create <pwd.path.name> <value>
  keys cmd password <keyname> remove <pwd.path.name>
  keys cmd password <keyname> encrypt <pwd.path.name | raw_text>  (不回显输入)
  keys cmd password <keyname> decrypt <pwd.path.name | ciphertext>

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
  encrypt   - 临时加密一段文本或已有密码项 (不回显输入)
  decrypt   - 解密密码项 (10秒后清屏)
  back      - 返回密钥管理模式
keys [db-prod]> decrypt db.mysql.root
> 123456 (剩余 10s...)  # 倒计时结束当前行被清除
```
