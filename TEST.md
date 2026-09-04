# Test Report: @go/keys

## v1.5.4 验证
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
