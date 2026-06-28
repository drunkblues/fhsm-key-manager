# fhsm-key-manager 设计文档

- **日期**: 2026-06-27
- **状态**: 已批准（设计阶段）
- **作者**: brainstorming 会话产出

## 1. 概述

`fhsm-key-manager` 是一个命令行工具，用于管理 PBOC1/PBOC2 对称密钥与 RSA/SM2/ECC 非对称密钥。

**核心定位**: 与 `fhsm-cpp` 的密钥文件**二进制完全兼容**——本工具直接读写 fhsm-cpp 的真实密钥文件（`pboc1.key`/`pboc2.key` 二进制 DB，以及 `rsa/`、`sm2/`、`ecc/` 目录下的明文密钥文件），字节布局完全一致。

**运行时机**: 离线操作。仅在 fhsm-cpp 停机或针对一份拷贝目录操作，只读写文件，不同步共享内存（shm）。fhsm-cpp 下次启动时从文件重新加载。

**设计目标**:
- 二进制完全兼容 fhsm-cpp 密钥文件
- LSK 通过参数传入，不依赖硬件存储（默认全 0）
- 方便其他进程调用，数据交换使用 JSON 格式
- 工程范式对齐 `fhsm-key-tool` 与 `fhsm-card`（纯 Go、cobra、JSON stdout）

## 2. 技术栈

| 方面 | 选择 | 理由 |
|---|---|---|
| 语言 | Go（CGO_ENABLED=0）| 对齐 siblings，跨平台 |
| CLI 框架 | `github.com/spf13/cobra` | 与 fhsm-card/fhsm-key-tool 一致 |
| 外部依赖 | **无**（纯标准库）| 见下"关键发现" |
| I/O 约定 | stdout 恒为 JSON；stderr 仅 `--verbose` 输出；退出码 0/1 | 对齐 siblings 标准化契约 |
| 构建 v1 | `go build -buildmode=pie -ldflags="-s -w"` | 纯 Go，PIE + 符号剥离 |
| 构建 v2（后续）| 补 `build.zig` 对齐 siblings checksec 画像 | 非 v1 阻塞项 |

### 关键发现：零外部依赖

SM2 密钥生成只需"随机私钥 d → 公钥 P = d·G"（sm2p256v1 曲线标量乘法），**不需要 SM3/签名**。因此可用 `math/big` 自实现（约 150 行，仿 `fhsm-key-tool` 的 `pkg/crypto/sm4` 自包含风格）。配合 `crypto/des`（2TDEA）、`crypto/rsa`（RSA 生成），整个项目**纯标准库、零外部依赖、零 CGO**。

## 3. 项目骨架

```
fhsm-key-manager/
  main.go              # 入口、全局 flag(--path/--lsk/--verbose)、子命令路由
  cmd/                 # 每个动词一个文件：get/get-all/list/put/delete/gen/version
  internal/
    storage/           # 二进制格式层：pboc1.go pboc2.go rsa.go sm2.go ecc.go
    crypto/            # tdea.go(2TDEA-ECB) sm2gen.go(纯 Go keygen)
    keymodel/          # JSON 数据模型 + 校验
  testdata/            # fhsm-cpp mock 产出的真实 fixture
  go.mod
  docs/superpowers/specs/
```

## 4. 命令面（按密钥类型分组）

全局 flag（cobra persistent flags）：
- `--path`（默认 `.`）—— 密钥根目录
- `--lsk`（hex，默认 32 个 `0` = 全 0 的 16 字节）—— 3DES 加密密钥
- `--verbose` —— stderr 输出进度

命令树：

```
fhsm-key-manager
  ├─ pboc1  {get|get-all|list|put|delete}
  ├─ pboc2  {get|get-all|list|put|delete}
  ├─ rsa    {get|list|put|delete|gen}
  ├─ sm2    {get|list|put|delete|gen}
  ├─ ecc    {get|list|put|delete}        # 无 gen（专有曲线）
  └─ version
```

目录布局（`--path` 指向一个根，镜像 fhsm-cpp 的 `/usr/rsakey/`）：

```
<path>/
  pboc1.key  pboc2.key       # 二进制 DB（3DES/LSK 加密）
  rsa/0001.RSA  sm2/0001.SM2 ecc/0001.ECC   # 明文，按需自动建子目录
```

## 5. 二进制格式与加密（二进制兼容的命门）

### 5.1 加密：2TDEA-ECB / LSK（无填充）

- **LSK** = 16 字节，`--lsk` 传入 hex（默认 32 个 `0`）；PBOC1/PBOC2 **共用同一 LSK**（fhsm-cpp 均用 slot 0）
- **2TDEA 构造**：`E(K1) → D(K2) → E(K1)`，K1 = LSK[0:8]、K2 = LSK[8:16]、第三轮复用 K1（对应 `fhsm-cpp/src/common/GeneralArith.cpp:306` 的 `_3DesEnc8`）
- **ECB、无填充**，逐 8 字节块独立；明文长度恒为 8/16/24，天然块对齐
- **Go 复刻**：`key24 = K1 ‖ K2 ‖ K1`（24 字节）→ `des.NewTripleDESCipher(key24)` → 手写 ECB 逐 8 字节块加解密（Go 标准库无 ECB 原语，块循环即可）
- 确定性算法 → get 后 put 回去密文不变，**往返稳定**

### 5.2 pboc1.key（33792 字节 = 1024 × 33B）

| 偏移 | 字段 | 说明 |
|---|---|---|
| [0] | flag | 0=空, 1=占用 |
| [1] | block | 区号 |
| [2] | type | 密钥类型 |
| [3] | version | 版本 |
| [4] | index | 索引 |
| [5] | alg | 算法标识 |
| [6] | div | 分散级别 |
| [7] | exp | 导出属性 |
| [8] | keylen | 8/16/24 |
| [9..32] | enc key | 密文，占 keylen 字节，**槽固定 24B**，余下补 0 |

磁盘上 [1..4] 就是 block/type/version/index 四个独立字节（btvi 整数仅用于内存二分查找，不上盘）。

### 5.3 pboc2.key（32768 字节 = 1024 × 32B）

| 偏移 | 字段 | 说明 |
|---|---|---|
| [0] | flag | 0/1 |
| [1] | type | 类型 |
| [2] | index | 索引 |
| [3] | subtype | 子类型 |
| [4..6] | reserved | **恒 0**（fhsm-cpp 从不写，必须保持 0 才兼容）|
| [7] | keylen | 8/16/24 |
| [8..31] | enc key | 密文，槽固定 24B |

### 5.4 非对称密钥（明文，NNNN = 4 位十进制索引，如 `0001`）

| 文件 | 内容 | 字节数 |
|---|---|---|
| `rsa/NNNN.RSA` | DER RSA 私钥（**PKCS#1**，因 fhsm-cpp 用 `d2i_RSAPrivateKey` 读回）| 变长 |
| `sm2/NNNN.SM2` | priv(32) ‖ pubX(32) ‖ pubY(32) | 96 |
| `ecc/NNNN.ECC` | pri(48) ‖ pub1(48) ‖ pub2(48)（nMod=2 专有曲线）| 144 |

### 5.5 写回语义（保证 byte-exact）

- **新增**: 找首个 flag=0 槽，写 flag=1 + 各字段；密钥槽不足 24B 的尾部补 0
- **更新**: 命中同选择子的槽，原地覆写（保留 flag=1）
- **删除**: 整槽 `memset(0)`（33B / 32B）；非对称则整文件删除
- **SM2/ECC 读取时校验文件长度**（96 / 144），不符报错

## 6. JSON 契约与命令 I/O

### 6.1 输出约定

- **stdout 恒为 JSON**：成功 = 结果对象/数组；失败 = 错误信封 `{ "error": "<message>", "code": "<CODE>" }`
- **stderr**: 仅 `--verbose` 时输出进度
- **退出码**: 成功 0，失败 1
- **编码**: 对称密钥/SM2 用 **hex**（短、对齐 fhsm-card 习惯）；RSA/ECC 二进制用 **base64**

### 6.2 各密钥数据模型

```
pboc1: { block, type, version, index, alg, div, exp, length, key(hex) }
pboc2: { type, index, subtype, length, key(hex) }
rsa:   { index, modulusLen?, exponent?, privDer(b64), pubDer?(b64) }   // pub 由 priv 派生
sm2:   { index, priv(hex32), pubX(hex32), pubY(hex32) }
ecc:   { index, pri(b64), pub1(b64), pub2(b64) }                       // 不透明存取
```

### 6.3 命令 I/O 表

| 组 | 命令 | 入参 | stdout |
|---|---|---|---|
| pboc1 | `get` | `--block --type --version --index` | 单个 key 对象 |
| | `get-all` | — | `[{…所有 key…}]`（含明文 key，即"读多个"）|
| | `list` | — | `[{block,type,version,index,alg,div,exp,length}, …]`（仅元信息）|
| | `put` | **stdin JSON**（单个对象 **或数组**，支持批量）| `{ "written": n }` |
| | `delete` | `--block --type --version --index` | `{ "deleted": bool }` |
| pboc2 | `get`/`get-all`/`list`/`put`/`delete` | 选择子 = `--type --index --subtype` | 同 pboc1 结构 |
| rsa | `get` | `--index` | `{index, privDer, pubDer}`（pub 派生）|
| | `list` | — | `[{index, modulusLen}, …]`（bits 从 DER 解析）|
| | `put` | stdin `{index, privDer}` | `{ "written": 1 }` |
| | `delete` | `--index` | `{ "deleted": bool }` |
| | `gen` | `--index --modlen 2048 --exponent 65537` | `{index, privDer, pubDer}`（priv 落盘）|
| sm2 | `get`/`list`/`put`/`delete` | `--index` | 同 rsa 结构（priv/pubX/pubY）|
| | `gen` | `--index`（固定 sm2p256v1）| `{index, priv, pubX, pubY}` |
| ecc | `get`/`list`/`put`/`delete` | `--index` | 无 `gen` |

### 6.4 关键约定

- **读**（get/get-all）：工具用 LSK **解密**后返回**明文** key
- **写**（put）：调用方给**明文** key（hex/b64），工具**加密**后落盘；put 接受**数组**实现批量写
- **gen**：rsa/sm2 生成后私钥写文件、响应里同时返回公私钥（便于调用方留存公钥）
- `modulusLen`/`exponent` 在 `rsa gen` 时必填；`get`/`list` 时从 DER 反解

## 7. 错误处理

### 7.1 错误信封

stdout：`{ "error": "<message>", "code": "<CODE>" }` + exit 1

### 7.2 错误码

| code | 含义 |
|---|---|
| `FILE_NOT_FOUND` | 密钥文件不存在 |
| `PATH_INVALID` | `--path` 路径无效 |
| `SELECTOR_MISSING` | 选择子 flag 缺失 |
| `KEY_NOT_FOUND` | get 时找不到指定密钥 |
| `KEYLEN_INVALID` | 密钥长度非 8/16/24 |
| `LSK_INVALID` | LSK 非 16 字节 / 32 hex |
| `SIZE_MISMATCH` | SM2 文件≠96B、ECC 文件≠144B |
| `DER_INVALID` | RSA DER 解析失败 |
| `DB_FULL` | 1024 槽已满，无空槽 |
| `GEN_FAILED` | 密钥生成失败 |

### 7.3 敏感数据清零

明文 key 用完即 `defer` 显式 memset 清零（仿 `fhsm-key-tool` 的零化）；`--lsk` 值不回显到日志。

## 8. 测试策略

二进制兼容是最高风险，重点投入。

### 8.1 金标准：用 fhsm-cpp mock 构建产出真实 fixture

fhsm-cpp 的 mock 构建（macOS 可跑、纯软件、LSK 经 `input_key_test` 明文文件可控）→ 用**已知 LSK** 生成 `pboc1.key`/`pboc2.key`/`.RSA`/`.SM2`/`.ECC`，提交进 `testdata/`。我们的测试读取这些**真实文件**，比对解出的明文 → 字节兼容的最强证明。

### 8.2 分层测试

1. **加密单元**：2TDEA-ECB 对照已知向量（含 NIST 2TDEA，K1‖K2‖K1 构造）；验证 E→D→E 链与确定性往返
2. **格式单元**：内存构造 pboc1/pboc2 item → 序列化 → 逐字节比对预期
3. **往返稳定**：get（解密）→ put（同明文+同 LSK 加密）→ 文件字节不变
4. **gen 测试**：RSA DER 用 `crypto/x509` 回解析；SM2 验证点在曲线上 + 往返一致；gen→文件→get→匹配
5. **JSON I/O**：put stdin → get stdout 全链路比对

## 9. 范围边界（YAGNI）

**v1 范围内**:
- 五类密钥（pboc1/pboc2/rsa/sm2/ecc）的 get/get-all/list/put/delete
- rsa/sm2 的 gen
- LSK 参数化（默认全 0）
- `--path` 指定密钥根目录

**v1 范围外**（明确不做）:
- ECC gen（专有 gx 曲线，纯 Go 无法复刻）
- shm 共享内存同步
- PBOC 密钥派生生成（cmd10/cmd11）
- 备份/恢复到 IC 卡
- 与运行中 fhsm-cpp 的 live 协调

## 10. 参考来源

所有二进制格式与加密细节均经 fhsm-cpp 源码核对：
- `include/basetype.h:81-89,156-158` — 文件路径定义
- `src/common/pboc1keymanager.cpp` — pboc1.key 格式与 3DES 加解密
- `src/common/pboc2keymanager.cpp` — pboc2.key 格式与 3DES 加解密（`PBOC2KEYITEMLEN=32`）
- `src/common/GeneralArith.cpp:306-340` — `_3DesEnc8`/`_3DesEnc8X` 的 2TDEA-ECB 实现
- `src/manager-msg/MngProcess.cpp:3303-3413` — RSA/SM2 文件生成与格式
- `src/biz/extfilter.cpp:2403-2469` — ECC 文件格式（48+48+48）
