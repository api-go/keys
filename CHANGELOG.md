# Changelog: @go/keys

## v1.5.4 (2026-07-18)
- **依赖校验修复**: 重新整理模块图并补齐 checksum。

## v1.5.3 (2026-06-21)
- **依赖更新**: 升级依赖 `jsmod` 至 `v1.5.3`，`cast` 至 `v1.5.3`，`rand` 至 `v1.5.3`，`encoding` 至 `v1.5.4`，`shell` 至 `v1.5.3`，`safe` 至 `v1.5.2`，`crypto` 至 `v1.5.3`，`file` 至 `v1.5.5`，`crypto-sm` 至 `v1.5.4`。

## v1.5.2 (2026-06-11)
- **基础设施对齐**: 全面适配 `encoding` v1.5.3 的 URLBase64 语义化 API。

## v1.5.1 (2026-06-08)
- **版本对齐**: 基础设施全局对齐 v1.5.1。

## v1.0.2 (2026-06-02)

### 🛠 Improvements
- **Security & Compatibility**: 
    - 修复 AES-CBC / SM4-CBC 算法下 IV 长度处理逻辑，仅在 IV 为 12 字节时进行补零。
    - 恢复对 16 字节历史遗留 IV 的完整支持，确保与旧版工具生成的加密数据完全兼容。

## v1.0.1 (2026-05-06)

### 🚀 Features
- **Mandatory Master Password**: 全局强制主密码保护，启动时需验证或设置主密码。本地密钥库数据由 AES-GCM-256 基于主密码加密保护。
- **Password Vault (密码管理器)**: 新增简易的个人密码管理功能，支持 `vault-add`, `vault-get`, `vault-list`, `vault-del` 等指令，数据通过主密码加密安全存储于 `.vault` 文件中。
- **Semantic CLI Aliases**: CLI 指令全面支持单字母语义化简写（如 `c` 代替 `create`, `e` 代替 `encrypt`, `gcm` 代替 `aes-gcm`）。
- **Interactive UI Enhancement**: 交互模式进入时提供单行的核心支持命令高亮引导。

### 🛠 Improvements
- **Infrastructure Alignment**: 
    - 升级核心依赖 `@go/crypto`, `@go/crypto-sm`, `@go/cast`, `@go/encoding` 等基础设施至最新版。
    - 将本地 IO 操作迁移并适配到 `@go/file` 高性能基础库。
- **Code Quality**: 优化部分变量命名与错误信息提示，增强代码可读性与鲁棒性。

## v1.0.0 (2026-05-05)

### 🚀 Features
- **多语言扩展**: 新增 `-python` 和 `-js` 导出支持，覆盖主流开发语言。
- **强化混淆 (Go)**: Go 语言导出模板现采用 `safe.EncryptChaCha20` 对密钥进行二次加密。
    - 引入 1KB 随机内存池 (`pool`)。
    - 密钥与 Salt 通过算法从内存池中动态提取，极大提升反编译难度。
- **Legacy 迁移**: 完成从 `ssgo/tool/sskey` 到 `apigo.cc/go/keys` 的全面重构与迁移。
...
- **跨语言加固**: 
    - Go 语言导出模板集成 `safe.LockMemory`、`safe.DecryptChaCha20` 与 `SecretPlaintext` 生命周期管理。
    - 同步更新 PHP、Java、Python、JavaScript 的混淆生成模板。

### 🛠 Improvements
- **健壮性**: 库函数增加 `nil` 指针防御与完整的错误状态校验。
- **自动降级**: 解密过程支持从 `aes-gcm` 自动降级至 `aes-cbc` 以兼容历史数据。
- **工程化**: 建立完善的单元测试 (`keys_test.go`) 与性能基准测试 (`bench_test.go`)。

### 🔒 Security
- 密钥存储目录迁移至 `~/keys/`。
- 强制执行校验位检查，防止非法密钥加载。
- 导出代码强制执行明文即时擦除策略。
