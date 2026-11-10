## [v1.5.12] - 2026-11-10

- 迁移至 github.com/api-go/keys，同步内部模块路径与依赖。

# Changelog: @go/keys

## [v1.5.11] - 2026-10-26
- AES-GCM 密钥文件、密码文件、CLI/REPL 新写入统一使用随机 IV 前置标准格式，原解密 API 兼容旧数据。
- 保留 Key/IV 导出契约、文件头及 CBC/SM4 格式；生成 Go 集成验证覆盖新格式。
- CLI 加密错误不再忽略，完成后关闭实例并擦除明文。
- 使用已发布 crypto v1.5.9 与 crypto-sm v1.5.8，移除开发临时 replace 并复验。

## [v1.5.10] - 2026-10-26
- 补齐发布包中的 CLI 集成测试，覆盖 keep-key / forget-key、跨进程缓存导出、密码隔离与 TTL。功能代码与 v1.5.9 相同。

## [v1.5.9] - 2026-10-26
- 新增 `keep-key <名> [--ttl 时长]`、`forget-key <名>`、`forget-key --all`：按用户/密钥库隔离的临时内存代理，跨终端免密码导出；不持久化凭证或主密码。
- 导出优先使用代理缓存；TTL、指定清除、代理退出及源文件指纹变化使授权失效；密码管理命令不使用缓存。
- 新增 KeySet.SourceFingerprint，绑定实际解锁/创建的加密文件快照，避免加载与缓存之间的文件更换。
- macOS/Linux 使用私有 Unix socket、UID 校验和独占启动；Windows 代理使用受登录身份 DACL 约束的本地命名管道及对端身份检查，代理库可交叉编译，CLI 的 shell 依赖阻塞仍存在。
- 使用已发布 timer v1.5.0 进行重试/清理调度，采用兼容 Go 1.25 的 go-winio v0.6.2；新增真实多进程缓存、过期、失效、并发、崩溃和协议边界验证。
- Go 导出直接调用 crypto.SetDefaultAES，移除 setSSKey 回调。
- 初始化结束时擦除原始混淆缓冲区，再解锁内存。
- 对齐 crypto、shell、cast、jsmod 的已发布依赖，补充同包初始化接入文档与运行验证。
- 五种语言按实际 IV 长度导出；PHP/JS 缺回调明确报错，Java 初始化串行化、异常上抛并允许失败重试；清理各语言本地混淆缓冲区。
- 主密码错误和密钥认证/结构无效返回错误；不再提供随机 KeySet。
- 导出成功仅输出源码，诊断走 stderr；导出、创建、加载的临时明文按生命周期清理。
- 存储路径按目录句柄约束，校验密钥名与密码项路径；新建密钥独占创建，Unix 敏感文件权限 0600；新增 RemoveKeystore 供 CLI/REPL 共用。
- SM4 调用按算法要求传入主密钥前 16 字节，恢复存储与临时加解密可用性。
- 补充多语言真实运行、CLI 错误契约、认证/路径/并发创建测试与导出基准。

## v1.5.7 (2026-09-05)
- **依赖对齐**: 升级 `file` 至 `v1.5.8`。

## v1.5.6 (2026-09-05)
- **依赖对齐**: 升级全部 `github.com/api-go/*` 依赖至当前已发布版本。

## v1.5.5 (2026-09-04)
- **仓库清理**: 忽略本地构建生成的 `keys_tool` 可执行文件。

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
- **Legacy 迁移**: 完成从 `ssgo/tool/sskey` 到 `github.com/api-go/keys` 的全面重构与迁移。
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
