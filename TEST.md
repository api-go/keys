## CLI 自动化验证（2026-11-14，v1.5.13 未发布）

- 全部密钥、密码和系统命令的 -h/--help 在不存在的密钥及空 MASTER_PASSWORD 下成功，帮助不触发认证。
- --non-interactive 禁止无命令或仅密钥名进入 REPL，缺密码不提示直接失败；验证创建密钥、密码项读写、导出及删除的完整自动化流程。
- 未知命令、未知全局选项及无效密文返回非零；损坏的存储密码项解密失败，stdout 为空、stderr 有错误，不返回诱饵。
- GOWORK=off 全量测试、基准与定向 race 通过；go doc ./lib 核对 LoadPasswordStrict。

## v1.5.13 自包含 Go 导出验证

环境：2026-11-14，Go 1.26.4，darwin/arm64，Apple M3 Max。

验证命令：`GOWORK=off go test -v ./...`、`GOWORK=off go test -bench=. ./...`，均通过。`ai/tools/getExports` 不存在，使用 `GOWORK=off go doc` 与导出源码交叉核对新增 API。性能为本机单次测量，非 SLA。

开发依赖：safe v1.5.6、crypto v1.5.11 显式 replace 到 `/Users/star/Case2/go/safe`、`/Users/star/Case2/go/crypto`（本轮v1.5.6 / v1.5.11）；timer 使用已发布 v1.5.2。发布前按依赖顺序移除替换并采用正式版本。

覆盖：
- AST 提取生成代码的两个载荷，检查均不含完整连续原始 key/IV，认证恢复并逐项比较；同输入多次导出不同。
- 生成 Go 程序实际运行，12–16 字节 IV 全长度保留，观察者初始化及默认 AES 解密。
- 单独编译不带预期明文常量的生成程序，在可执行文件中检查原始 key/IV 连续字节缺失；该检查只证明本次样本，不承诺任意程序二进制。
- 损坏载荷使生成程序启动失败；未知语言、错误 key/IV 长度返回错误。
- CLI 解密固定 `-` 前缀 URL-base64 密文、新旧 GCM 格式、代理授权、其他四种语言导出及 keystore 全量测试。
- 定向 race：`-run 'TestGo(SelfContainedPayloads|ExportBinaryAndCorruption|ExportInitialization)|TestAutoIVCLI' ./...` 通过。

| 基准 | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| MakeCode/go | 50344 | 15990 | 404 |
| KeptExport | 132958 | 5227 | 25 |

API：GOWORK=off go doc ./lib 与源码核对；MakeCode 签名不变，中英文 README 已说明 Go 导出所需新依赖和其他语言兼容边界。

# Test Report: @go/keys

## v1.5.11 开发验证（已由下方正式依赖验证替代）（2026-10-26）

Go 1.26.4 / darwin arm64 / Apple M3 Max。使用 GOWORK=off 与显式临时 replace：
`github.com/api-go/crypto => /Users/star/Case2/go/crypto`，其余依赖为已发布版本。
`go test -v ./...`、`go test -bench=. ./...`、`go test -race ./...`、`go vet ./...` 均通过。
通过 `go doc ./lib` 与源码核对导出 API，替代 getExports。

新增覆盖：
- 独立标准库 GCM 验证密钥文件、密码文件和 CLI 的 nonce/ciphertext/tag 布局。
- 使用原格式生成真实旧密钥文件、密码文件和 CLI 密文，验证兼容读取；旧密码项更新输出新格式。
- CLI 连续加密 nonce 不同、加解密往返；生成 Go 文件注入默认 AES 后读取新格式。
- 原 CBC/SM4 存储回归、五语言实际执行/编译、代理/导出和认证/路径测试全部通过，无跳过。

MakeCode 基准（µs/op）：Go 21.780 / PHP 21.188 / Java 24.813 / Python 21.880 / JS 21.166。
加密路径与旧格式回退成本见 crypto/TEST.md 的 64 B、4 KiB、1 MiB 基准。


## v1.5.10 发布验证（2026-10-26）

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

## v1.5.11 发布验证（2026-10-26）

GOWORK=off，正式依赖 crypto v1.5.9，无 replace。`go test -v ./...`、`go test -bench=. ./...`、`go vet ./...`、`go mod verify` 通过。使用 `go doc` 与源码交叉核对 API，替代 getExports。现有回归覆盖本模块业务；新旧 GCM 格式、认证失败和性能基准见 crypto v1.5.9。

本次功能测试无跳过。

基准结果：
```text
BenchmarkKeptExport-16    	   13753	     87630 ns/op	    4264 B/op	      25 allocs/op
BenchmarkMakeCode/go-16 	   54261	     22299 ns/op	   10695 B/op	     208 allocs/op
BenchmarkMakeCode/php-16         	   54534	     21967 ns/op	    8991 B/op	     207 allocs/op
BenchmarkMakeCode/java-16        	   49914	     23947 ns/op	   16605 B/op	     211 allocs/op
BenchmarkMakeCode/python-16      	   53372	     21963 ns/op	    8821 B/op	     207 allocs/op
BenchmarkMakeCode/js-16          	   54847	     21985 ns/op	    9215 B/op	     207 allocs/op
```

## GitHub migration validation (pending release)

Module paths and internal dependency versions are migrated. Development verification uses GOWORK=off and explicit sibling replacements; remove these replacements before release. See migration validation logs for actual results. Existing unrelated working changes are preserved and require separate review.

API inventory verification: `GOWORK=off go doc` succeeded; output retained in the migration validation directory. Source exports were preserved by the path migration.

## GitHub release verification

GOWORK=off go test -v ./... and go test -bench=. ./... passed using published GitHub dependencies, without local replacements. go mod verify passed.

## 最终依赖图验证（2026-11-14，未发布）

显式本地 replace 覆盖本轮待发布依赖链；GOWORK=off go mod tidy、go test -v ./...、go test -bench=. -benchtime=1x ./...。基准按固定 1 次采样，避免排除计时的昂贵准备阶段反复校准。本轮结果：[('tidy', '0'), ('test', '0'), ('bench', '0')]。0 为通过，其他结果待定位。

固定一次采样的基准摘要（非稳定性能测量）：

```text
BenchmarkKeptExport-16    	       1	    198250 ns/op	    5296 B/op	      25 allocs/op
BenchmarkMakeCode/go-16 	       1	     94833 ns/op	   18528 B/op	     408 allocs/op
BenchmarkMakeCode/php-16         	       1	     53292 ns/op	   11528 B/op	     211 allocs/op
```

## v1.5.13 正式发布验证（2026-11-14）

GOWORK=off；移除全部 replace，使用已发布依赖。go mod tidy、go test -v ./...、go test -bench=. ./...、go mod verify 均通过。API 工具不可用，使用 go doc 与源码核对。

```text
BenchmarkKeptExport-16    	    8492	    128847 ns/op	    5230 B/op	      25 allocs/op
BenchmarkMakeCode/go-16 	   24097	     49627 ns/op	   15990 B/op	     404 allocs/op
BenchmarkMakeCode/php-16         	   55174	     21786 ns/op	    8991 B/op	     207 allocs/op
```
