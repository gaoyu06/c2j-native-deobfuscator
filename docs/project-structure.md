# 项目顶层结构

> 定义模块边界、目录布局、各阶段产物 schema、CLI 入口。**未开工**。

## 1. 目标 / 非目标

**目标**
- 把"被转译为 JNI native 的 jar + .dll/.so"还原回**可反编译的 jar**
- 多语言混合：每个模块用最自然的语言
- 模块可独立使用（每个模块自带 CLI）；存在一个顶层 orchestrator 提供"一键还原"
- 主流程不依赖 native-obfuscator 内部实现（见 [`static-reverse-approach.md`](./static-reverse-approach.md) §10.1）

**非目标**
- 不还原源码级信息（局部变量名、参数名、源文件行号——除非原 jar 带 debug info）
- 不试图绕过反检测/反调试代码
- 不还原**已被编译器物理消除**的信息（如常量折叠掉的中间步骤）

---

## 2. 模块拆分

按职责拆 8 个模块。每个模块**独立可用**，模块间通过 **JSON 文件**通信，schema 版本化。

| # | 模块 | 语言 | 输入 | 输出 | 阶段 |
|---|---|---|---|---|---|
| 1 | `jar-parser` | Java/Kotlin + ASM | input.jar | classes.json | Phase 1 |
| 2 | `binary-introspect` | Python + LIEF | input.dll/.so | binary.json | Phase 1+2 |
| 3 | `manifest-merge` | Python | classes.json + binary.json | manifest.json | Phase 1+2 |
| 4 | `dynamic-trace` | C/C++ JVMTI agent | jar + 运行参数 | trace.jsonl | Phase 3a |
| 5 | `trace-to-bytecode` | Java/Kotlin + ASM | manifest + trace.jsonl | recovered/*.json | Phase 3a |
| 6 | `static-reverse` | GhidraScript + Python + tree-sitter | input.dll/.so + manifest | recovered/*.json | Phase 3b |
| 7 | `class-rebuilder` | Java/Kotlin + ASM | input.jar + recovered/*.json | output.jar | Phase 4 |
| 8 | `cli` | Python (typer) | — | — | 编排 |

**可选附加模块**：
- `snippet-importer`（Python）：可选 feature，单向依赖 `static-reverse` 的 rule 接口（见 static-reverse-approach.md §10）。**主流程完全不感知**。

**模块依赖图**（实线=必需，虚线=可选）：

```
                    ┌──────────────────────────┐
                    │           cli            │
                    └──┬───────┬────────┬──────┘
                       │       │        │
            ┌──────────▼─┐ ┌───▼────┐ ┌─▼──────────────┐
            │ jar-parser │ │binary- │ │ manifest-merge │
            │            │ │introsp.│ │                │
            └──────┬─────┘ └───┬────┘ └────────┬───────┘
                   │           │               │
                   └───────────┼───────────────┘
                               ▼
                       (manifest.json)
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
        ┌──────────────────┐      ┌──────────────────┐
        │  dynamic-trace   │      │  static-reverse  │   ◀┄┄┄┄ snippet-importer
        │       ↓          │      │                  │       (可选)
        │ trace-to-bytecode│      │                  │
        └────────┬─────────┘      └────────┬─────────┘
                 │                         │
                 └──────────┬──────────────┘
                            ▼
                  ┌──────────────────┐
                  │ class-rebuilder  │
                  └────────┬─────────┘
                           ▼
                       output.jar
```

---

## 3. 目录布局

按**语言**分组（每种语言一个构建系统），而非按模块——避免每个模块都要装配自己的工具链。

```
j2c-dumper/
├── README.md
├── docs/                          # 设计文档
│   ├── static-reverse-approach.md
│   ├── project-structure.md       # 本文档
│   └── schemas/                   # JSON Schema 形式化定义（draft-07）
│
├── jvm/                           # 所有 JVM 模块（Gradle multi-project）
│   ├── settings.gradle.kts
│   ├── build.gradle.kts           # 公共配置
│   ├── jar-parser/
│   ├── trace-to-bytecode/
│   ├── class-rebuilder/
│   ├── common/                    # 共享工具：jar I/O、ASM helper、schema POJO
│   └── dynamic-trace-agent-java/  # JVMTI agent 的 Java 侧 stub
│
├── py/                            # 所有 Python 模块（单 workspace）
│   ├── pyproject.toml             # uv 管理；用 workspaces 拆子包
│   ├── j2c_dumper_cli/            # 顶层 CLI（typer）
│   ├── binary_introspect/
│   ├── manifest_merge/
│   ├── ast_matcher/               # static-reverse 的 Python 侧
│   └── snippet_importer/          # 可选 feature
│
├── native/                        # C/C++ JVMTI agent
│   ├── CMakeLists.txt
│   ├── src/
│   └── include/
│
├── ghidra/                        # GhidraScript（不参与构建系统，直接 drop-in）
│   ├── scripts/
│   └── data-types/                # type archive (.gdt) 或生成脚本
│
├── schemas/                       # JSON Schema 形式化定义（与 docs/schemas/ 同源；
│                                  # 实际放这里以便代码引用）
│
├── tests/
│   ├── e2e/                       # 端到端集成测试
│   ├── fixtures/                  # 小型示例 jar + dll
│   └── unit/                      # 各模块自带的单元测试就近放，这里只放跨模块的
│
└── tools/                         # 开发/构建辅助脚本
    ├── build.py                   # 一键构建所有模块
    └── ci/
```

**为什么按语言分组而不是按模块**：
- 一个 Gradle multi-project 就能编译所有 JVM 模块（共享依赖、版本统一）
- 一个 uv workspace 就能管所有 Python 模块（共享 lockfile）
- 调试时跨模块引用更方便（同语言模块直接 import）
- 顶层 `j2c-dumper/` 看起来不乱

---

## 4. 语言选择理由

| 模块 | 语言 | 不选其它语言的理由 |
|---|---|---|
| `jar-parser` / `trace-to-bytecode` / `class-rebuilder` | Kotlin（运行在 JVM 上，可直接用 Java 库） | ASM 是 Java 库，Python/Rust 没有同质量替代品 |
| `binary-introspect` | Python | LIEF 的 Python 绑定最成熟；解析 PE/ELF 字符串池/重定位表 ~200 行就能搞定 |
| `dynamic-trace` agent | C++（JVMTI 必须） | JVMTI 是 C API；agent 必须是 native shared library |
| `dynamic-trace` Java stub | Kotlin | 在 JVM 内辅助 hook（如 ClassFileTransformer），需要在 JVM 里跑 |
| `static-reverse` GhidraScript | Java（Ghidra 内置脚本环境） | 不引入 Ghidrathon，少一层依赖 |
| `static-reverse` AST 匹配 | Python | tree-sitter 绑定成熟，规则用 Python DSL 描述最自然 |
| `snippet-importer` | Python | 解析 properties 文件 + 生成规则；不需要重型工具 |
| `cli` | Python（typer） | 跨语言编排最常见的 glue 语言；用 `subprocess` 调 JVM/Ghidra 干净 |

---

## 5. 各阶段产物 schema（草案）

正式 JSON Schema 放 `schemas/`。这里列字段骨架，让你评审字段是否够用。

### 5.1 `classes.json`（jar-parser 输出）

```json
{
  "schemaVersion": 1,
  "input": { "jarPath": "in.jar", "sha256": "..." },
  "loaderClass": "native0/Loader",
  "nativeDir": "native0",
  "classes": [
    {
      "name": "com/example/Foo",
      "superName": "java/lang/Object",
      "interfaces": ["java/lang/Runnable"],
      "version": 52,
      "access": 33,
      "signature": null,
      "sourceFile": "Foo.java",
      "fields": [
        { "name": "x", "desc": "I", "access": 2, "signature": null, "value": null }
      ],
      "methods": [
        {
          "name": "bar",
          "desc": "(I)I",
          "access": 257,
          "signature": null,
          "isNative": true,
          "isObfuscatedNative": true,
          "tryCatchBlocks": [],
          "maxStack": -1,
          "maxLocals": -1,
          "originalBody": null
        },
        {
          "name": "<init>",
          "desc": "()V",
          "access": 1,
          "isNative": false,
          "isObfuscatedNative": false,
          "originalBody": "<base64-bytecode>"
        }
      ]
    }
  ]
}
```

`isObfuscatedNative=true` 标记的方法是**等待还原**的目标；`<init>` 这种没被处理的方法 `originalBody` 保留原字节码。

### 5.2 `binary.json`（binary-introspect 输出）

```json
{
  "schemaVersion": 1,
  "input": { "libPath": "x64-windows.dll", "format": "PE", "arch": "x86_64", "sha256": "..." },
  "stringPool": {
    "base": "0x180012000",
    "totalBytes": 65536,
    "strings": ["com/example/Foo", "bar", "(I)I", "..." ]
  },
  "nativeRegistry": [
    {
      "classId": 0,
      "className": "com/example/Foo",
      "registerFunction": { "addr": "0x180001000", "symbol": "__ngen_register_0" },
      "methods": [
        { "name": "bar", "desc": "(I)I", "fnAddr": "0x180001234", "fnSymbol": "__ngen_com_example_Foo_bar" }
      ]
    }
  ],
  "perClassLookups": [
    {
      "classId": 0,
      "cstrings": { "addr": "0x180020000", "entries": [{"index":0,"poolIndex":12}] },
      "cclasses": { "addr": "0x180020100", "entries": [{"index":0,"name":"com/example/Foo"}] },
      "cmethods": { "addr": "0x180020200", "entries": [{"index":0,"owner":"java/io/PrintStream","name":"println","desc":"(Ljava/lang/String;)V"}] },
      "cfields":  { "addr": "0x180020300", "entries": [] }
    }
  ],
  "hiddenClasses": [
    { "embeddedAt": "0x180030000", "size": 412, "classData": "<base64>" }
  ]
}
```

`hiddenClasses` 是 native-obfuscator 用 `DefineClass` 动态加载的隐藏类，从 .rdata 直接 dump 出来的 .class 字节序列。

### 5.3 `manifest.json`（merge 后的规范元数据）

由 `manifest-merge` 把 `classes.json` 和 `binary.json` 合并；为每个 `isObfuscatedNative=true` 的方法关联到其 native 函数地址 + 该类的 lookup 表。下游模块都只需要读 manifest，不需要再单独读前两份。

### 5.4 `trace.jsonl`（dynamic-trace agent 输出）

JSONL，每行一个事件。事件类型：
- `enter` / `exit`：进入/退出 __ngen_* 函数
- `jni`：JNI 调用（包括 vtable 槽名、args、返回值）
- `cstack` / `clocal`：（可选高频）jvalue 槽位读写

```jsonl
{"ts":1234567890123456,"thr":1,"ev":"enter","fn":"__ngen_com_example_Foo_bar","args":[42]}
{"ts":1234567890123500,"thr":1,"ev":"jni","call":"GetIntField","obj":"0x7fa...","fid":"0x7f8...","ret":7}
{"ts":1234567890123600,"thr":1,"ev":"exit","fn":"__ngen_com_example_Foo_bar","ret":49}
```

### 5.5 `recovered/<class>/<method>.json`（trace-to-bytecode 或 static-reverse 输出）

```json
{
  "schemaVersion": 1,
  "owner": "com/example/Foo",
  "name": "bar",
  "desc": "(I)I",
  "source": "dynamic|static|merged",
  "confidence": "high|medium|low",
  "instructions": [
    { "op": "ILOAD", "var": 0 },
    { "op": "ICONST_3" },
    { "op": "IADD" },
    { "op": "IRETURN" }
  ],
  "tryCatchBlocks": [],
  "localVariables": [],
  "lineNumbers": []
}
```

`source` 让 `class-rebuilder` 知道是来自哪条路径；`merged` 表示动态+静态结果一致并合并；`confidence` 用于报告不确定的部分。

---

## 6. CLI 形态

### 6.1 顶层 CLI（一键还原）

```
j2c-dumper recover <input.jar> [--lib <lib.dll>] [-o <output.jar>]
                   [--no-dynamic] [--no-static]
                   [--run-cmd "java -jar in.jar"]   # 给 dynamic 用
                   [--ghidra-home <path>]
```

行为：
1. 调 `jar-parser` → classes.json
2. 自动从 jar 内解出 native lib（或读 `--lib`），调 `binary-introspect` → binary.json
3. 调 `manifest-merge` → manifest.json
4. （除非 `--no-dynamic`）启动 `dynamic-trace` + 执行 `--run-cmd` → trace.jsonl → `trace-to-bytecode`
5. （除非 `--no-static`）调 `static-reverse` 跑 Ghidra + AST 匹配
6. `class-rebuilder` 把 recovered 字节码写回 .class，输出 output.jar

### 6.2 子命令（模块独立调用）

```
j2c-dumper parse-jar <input.jar> -o classes.json
j2c-dumper inspect-binary <lib.dll> -o binary.json
j2c-dumper merge-manifest classes.json binary.json -o manifest.json
j2c-dumper dynamic-trace --manifest manifest.json --run "java -jar in.jar" -o trace.jsonl
j2c-dumper trace-to-bc trace.jsonl --manifest manifest.json -o recovered/
j2c-dumper static-reverse <lib.dll> --manifest manifest.json -o recovered/
j2c-dumper rebuild --input in.jar --recovered recovered/ -o out.jar
```

每个子命令对应一个模块；用户可任意拼接 / 替换。

### 6.3 native-obfuscator 强绑定子命令（可选 feature）

```
j2c-dumper no-dump-string-pool <lib.dll> -o pool.txt
j2c-dumper no-dump-lookups <lib.dll> -o per-class.json
j2c-dumper no-import-snippets <native-obf-repo-path> -o snippet-rules.json
```

`no-` 前缀表示"native-obfuscator-specific"，用户清楚这些只对该工具的产物有意义。

---

## 7. 构建 / 开发工作流

| 操作 | 命令 |
|---|---|
| 一键构建所有模块 | `python tools/build.py` |
| 只构建 JVM 模块 | `cd jvm && ./gradlew assemble` |
| 只构建 Python | `cd py && uv sync` |
| 只构建 native agent | `cd native && cmake -B build && cmake --build build` |
| 安装 CLI（开发模式） | `cd py && uv pip install -e ./j2c_dumper_cli` |
| 运行端到端测试 | `python tools/build.py test-e2e` |

CI（GitHub Actions）：每个 PR 跑 lint + 各模块的单元测试 + 至少一个端到端 fixture。

---

## 8. 测试策略

- **单元测试**：每个模块各自独立，就近放（`jvm/jar-parser/src/test/`、`py/binary_introspect/tests/` 等）
- **集成测试**：模块间用 JSON 文件契约通信，集成测试就是"喂一份 manifest，期望某个 recovered/*.json"
- **端到端测试**：`tests/e2e/` 下放小型 fixture——一个用 native-obfuscator 处理过的小 jar，运行整条管线，比对输出 .jar 反编译结果是否包含期望的方法签名/字节码

Fixture 生成：在 CI 上**实时调用** native-obfuscator（项目同目录有现成的）处理 `tests/fixtures/source/*.jar`，生成 `tests/fixtures/processed/`。

---

## 9. 模块独立性 + Schema 演进

- 每个 schema 顶层有 `schemaVersion: int`
- 下游模块读 schema 时检查版本，不兼容直接报错
- 升级时**优先 additive**（加字段而非改字段）；breaking change 时 bump major 版本，所有下游同步更新
- 跨语言用 JSON 而不是 protobuf / msgpack —— 调试可读、版本兼容简单、不引入 codegen 依赖

---

## 10. 待你拍板

1. **目录布局按语言分组 vs 按模块分组** —— 我已选"按语言分组"，理由见 §3 末尾。是否同意？
2. **Python 包管理用 uv** —— 比 pip/poetry 快；锁文件 `uv.lock` 跨平台一致。是否同意？
3. **JVM 端语言**：Kotlin 还是 Java？我倾向 Kotlin（ASM API 用起来更简洁，且能调用 100% Java 库）。
4. **CLI 实现**：Python typer 还是 Go cobra？Python 更贴近其它 Python 模块（无 IPC 开销），Go 编译成单文件分发更方便。我倾向 Python——分发不是 MVP 阶段的重点。
5. **dynamic-trace 的 trace 粒度**：默认只记 `enter/exit/jni` 三类事件（最实用）；是否需要 `cstack/clocal` 槽位级 trace（数据量大但还原精度更高）？我倾向默认关闭，留 `--detailed-trace` 选项。

定稿后开 Phase 1（jar-parser）实现。
