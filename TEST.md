# Test Report: @go/keys

## v1.5.9 发布验证（2026-10-26）

环境：Go 1.26.4、darwin/arm64、Apple M3 Max。
使用已发布依赖、`GOWORK=off`，无临时 replace。

| 验证 | 结果 |
| --- | --- |
| `go test -v ./...` | 通过 |
| `go test -bench=. ./...` | 通过 |
| `go test -race ./...` | 通过 |
| `go vet ./...` / `go mod verify` | 通过 |
| `GOOS=windows GOARCH=amd64 go build ./internal/keyagent ./lib` | 通过（仅编译） |
| `GOOS=linux GOARCH=amd64 go build ./internal/keyagent ./lib` | 通过（仅编译） |
| Windows CLI 交叉编译 | 未通过：已发布 shell v1.5.8/run.go 引用 Unix 专有的 Setpgid/Getpgid/Kill，未隔离到平台文件 |

覆盖场景：
- 五种语言实际生成、编译或执行，验证 12/13/14/15/16 字节 IV 和 Key 完整一致；本机 PHP/Java/Python/Node 均已执行，没有跳过。缺运行时的环境会显式跳过对应语言。
- Go 生成文件排在 main.go 前面时，包变量阶段注册仍可接收 AES；验证加解密及完整 IV 派生结果。
- PHP/Python/JS 无回调、回调异常；Java 回调失败后重试及多线程只成功初始化一次。
- CLI 成功 stdout 仅含源码；错误密码、无终端且无密码、未知语言、多余参数均为非零退出码、stderr 诊断、空 stdout。
- 错误/空主密码、密钥认证失败；非法导出参数。
- 密钥名/密码项的目录穿越、符号链接逃逸；合法嵌套项。
- 并发同名密钥创建只有一个成功；Unix 文件权限 0600。
- AES-GCM/AES-CBC/SM4-GCM/SM4-CBC 存储、更新、读取、删除及 KeySet 加解密往返。
- 代理使用真实独立子进程：多客户端共享、指定/全部清除、TTL 到期、重复保留替换期限、并发启动、不同密钥库隔离、源文件变化及加载后更换文件、崩溃重启不恢复旧授权。
- Unix socket/目录/锁文件权限及空锁文件检查；畸形/超长请求不影响后续合法导出；不安全目录下拒绝操作，无法连接时不误报清除成功。
- CLI 真实进程完成 keep-key→无密码导出→forget-key 流程；密码管理命令不借用缓存；错误密码的 keep-key 不替换有效缓存；非法/空/负 TTL 拒绝执行。
- 代理拒绝继承非空 MASTER_PASSWORD；命令启动时移除该变量。
- API 核对采用 `GOWORK=off go doc ./lib` 与导出源码交叉核对（替代 getExports）；新增 RemoveKeystore 和 KeySet.SourceFingerprint，MakeCode 签名不变。

导出基准（包含模板解析与渲染；并行进行其他验证时测量，仅作本机参考）：

| 语言 | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Go | 21876 | 10694 | 208 |
| PHP | 21506 | 8991 | 207 |
| Java | 23545 | 16605 | 211 |
| Python | 21364 | 8821 | 207 |
| JS | 21646 | 9215 | 207 |
| 代理缓存 Go 导出（含本地 IPC） | 95815 | 4264 | 25 |

代理缓存导出的 B/op 与 allocs/op 仅统计客户端进程；延迟包含独立代理的处理时间，不含 CLI 进程启动。代理测试子进程在正常关闭后等待退出，并检查 race detector 的退出状态。

## v1.5.7 验证
- 独立模块解析、全量测试与基准测试均通过。

## 测试环境
- **操作系统**: darwin (macOS)
- **架构**: amd64
- **Go 版本**: go 1.25.0+
- **CPU**: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz

## 单元测试结果
运行时间: 2026-06-21
运行命令: `go test -v ./lib`

| 测试用例 | 状态 | 描述 |
| :--- | :--- | :--- |
| `TestKeyLifecycle` | PASS | 验证密钥创建、加载及全算法加解密闭环 |
| `TestKeyErrors` | PASS | 验证文件缺失、格式损坏、校验位错误及非法算法处理 |
| `TestEmptyData` | PASS | 验证零长度数据的加解密处理 |
| `TestMakeCode` | PASS | 验证 Go/PHP/Java 三种语言的集成代码生成 |

## 性能基准测试 (Benchmark)
数据规模: 1KB 负载

### 加密性能 (Encryption)
| 算法 | 性能 (ns/op) |
| :--- | :--- |
| AES-GCM (默认) | 5365 |
| AES-CBC | 5949 |
| SM4-GCM | 6795 |
| SM4-CBC | 14249 |

### 解密性能 (Decryption)
| 算法 | 性能 (ns/op) |
| :--- | :--- |
| AES-GCM (默认) | 4801 |
| AES-CBC | 5381 |
| SM4-GCM | 7087 |
| SM4-CBC | 5751 |

## 安全性验证
- [x] **内存锁定**: 导出代码集成 `safe.LockMemory`。
- [x] **自动擦除**: 敏感明文在使用后立即调用 `Close()` 擦除。
- [x] **交换分区防护**: 通过 `mlock` 防止密钥泄露至磁盘。
# v1.5.5 验证

- `go test -v ./...`
- `go test -bench=. ./...`
