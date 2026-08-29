# 架构与功能一览

[English](overview.md) | [中文](overview.zh-CN.md)

本页是 `c2j-native-deobfuscator` 的当前地图：各层怎么拼、每条表面做什么、
哪些**不是**默认路径或未随仓库发布。描述的是 #2–#14 收尾之后的 `main`。
本文不改变任何运行时默认值。

配套文档：[ARCHITECTURE.md](ARCHITECTURE.md)（模块契约）、
[options-and-status.md](options-and-status.md)（决策与晋升门槛）、
[getting-started.zh-CN.md](getting-started.zh-CN.md)（10 分钟默认路径）。

用语保持中性：JNI-native 转译 JAR 恢复、JVMTI、进程检查、库插桩、插件 ABI、
特权观察器。

---

## 这是什么

核心产品是一套 **CLI 恢复工具**，面向把 Java 方法转译成 C/C++、再经 JNI
回调的 JAR（[`native-obfuscator`](https://github.com/radioegor146/native-obfuscator)
家族及其衍生，如 j2cc）。

`scripts/j2c` 是自动化契约。可选的 Swing 查看器只展示产物，不替代 CLI。
相邻的用户态观察模块在 JAR 管线**之外**，删掉也不影响恢复。

仓库基线是 **JDK 17** 与 **Python 3.11+**。只有桌面模块需要 **JDK 21**。
native JVMTI agent 面向 **x86-64** 构建。

---

## 分层架构

```
  ┌──────────────────────────────────────────────────────────────────┐
  │ 表面                                                             │
  │   CLI  scripts/j2c （doctor、recover、attach、各阶段）            │
  │   桌面查看器  scripts/gui.sh  （可选，以只读展示为主）            │
  └───────────────────────────────┬──────────────────────────────────┘
                                  │ schemas/ 下的版本化 JSON
  ┌───────────────────────────────┼──────────────────────────────────┐
  │ 发现                          │  恢复引擎                        │
  │   jar-parser → classes.json   │   动态 JVMTI     （默认）        │
  │   binary-introspect           │   活动附加       （预览）        │
  │     → binary.json             │   轻量静态 stub  （draft-dev）   │
  │   manifest-merge              │   模拟           （可选）        │
  │     → manifest.json           │   Ghidra 方法体  （可选）        │
  └───────────────────────────────┼──────────────────────────────────┘
                                  │ recovered/*.json
                                  ▼
                     class-rebuilder → out.jar

  相邻、不在 JAR 路径上（可安全删除）：
    native-x86/              用户态 metadata 观察，插件 ABI 0.2
    privileged-observer/     用户态 /proc maps 插件；默认关闭
```

每个恢复阶段只读写**版本化 JSON**。跨模块只走 `schemas/`。编排器
（`py/j2c_dumper_cli`）只负责把阶段串起来。

两棵相邻树产出的是进程镜像记录，不是字节码：

- [`native-x86/`](../native-x86/) — 用户态 host + 插件；公开 ABI 不含 Java 类型。
- [`privileged-observer/`](../privileged-observer/) — 可选用户态 maps 后端；
  **没有**内核镜像或内核源码。

---

## 恢复管线（默认与备选）

### 默认：动态 `recover`

JAR 能跑时，`scripts/j2c recover … --run-cmd "…"` 依次执行：

1. `parse-jar` → `classes.json`
2. `inspect-binary` → `binary.json`（从 JAR 抽出 blob）
3. `merge-manifest` → `manifest.json`
4. `dynamic-trace` — 用 `-agentpath` 启动目标 → `trace.jsonl`
5. `trace-to-bc` → `recovered/*.json`
6. `rebuild` → 剥离 loader 的 `out.jar`

覆盖率只含**实际执行到的分支**。未观察到的方法可能仍是桩。这仍是默认发布路径。

### 离线发现与轻量静态（不运行、不要 Ghidra）

`parse-jar` + `inspect-binary` + `merge-manifest`（或一条 `static-lite`）
按 JNI 规范事实（`Java_*` 导出、`RegisterNatives` vtable 索引 215）生成可审计
方法 manifest 与可通过校验的 stub。这是 **draft-dev**，不是默认 `recover`，
也不声称已经还原方法体。

诚实缺口是一等公民：仅按数量匹配的歧义表记为
`ambiguous-count-only-table`；表结构可见但名称/descriptor 字节是垃圾时记为
`unreadable-table`（不静默跳过，也不编造名字）。详见
[generic-recovery.md](generic-recovery.md)。

### 可选静态方法体（Ghidra）

发现之后，可用 Ghidra Headless 把每个 `fnAddr` 反编译成 pseudo-C，再由
`ast_matcher` 抬升到 `recovered/*.json`。**发现阶段不需要 Ghidra**。

### 可选模拟

`scripts/j2c emulate` / `py/native_emulate` 在 Unicorn + mock JNI 下跑 blob：
列出注册、dump 解密常量、把方法当纯函数 oracle。不会自动产出字节码。

### 活动附加（预览）

`scripts/j2c attach --pid <pid> --i-own-this-process` 把同一个 agent 装进
**已经在跑、且属于同一用户**的 JVM。启动期 `-agentpath` 仍然看得更多。
不少 JDK（已在 OpenJDK 21 上实测）附加后只有 bind。没有 stealth，也没有绕过。
详见 [jvm-attach.md](jvm-attach.md)。

---

## 功能目录

| 表面 | 做什么 | 状态 | 是否恢复默认？ |
|---|---|---|---|
| `scripts/setup.sh` / `setup.ps1` | 构建 JVM 模块、Python 工作区、x86-64 agent | 已落地 | 仅安装 |
| `scripts/j2c doctor` | 版本 + 产物；缺失项给出下一条命令 | 已落地 | 仅检查 |
| `scripts/j2c recover` | 一键动态恢复 | 已落地 | **是** |
| 分阶段 CLI（`parse-jar`、`inspect-binary`、`merge-manifest`、`dynamic-trace`、`trace-to-bc`、`static-reverse`、`rebuild`、`synth-stubs`、`static-lite`、`emulate`） | 隔离的 JSON 阶段 | 已落地 | 否（除非被 `recover` 串起来） |
| 通用 JNI 发现 | PE/ELF/Mach-O；x86-64、AArch64、ARM、i386 ELF；`j2cc` PE 探测器；共享 dispatch 采集 | draft-dev | **否** |
| 诚实绑定缺口 | `bindingGaps` + `analysis.unreadableTables` | draft-dev | 仅报告 |
| Ghidra `DumpFromManifest` + `ast_matcher` | 可选 pseudo-C 方法体抬升 | 可选插件 | **否** |
| 模拟（`unicorn`） | 注册 / 字符串 / oracle | 可选 | **否** |
| `scripts/j2c attach` | 可选活动 JVMTI 附加 | 预览 | **否** |
| `scripts/gui.sh` | Swing + FlatLaf 产物 / 附加查看器 | 可选桌面 | **否** |
| `native-x86/` | 用户态 metadata 观察，ABI 0.2 | 预览 | **否**（不在 JAR 路径上） |
| `privileged-observer/` | 用户态 Linux maps 插件 | 预览，默认**关** | **否** |
| `.claude/skills/j2c-deobfuscate` | 智能体手册 | 可选 | 仅便利 |

---

## 各表面再展开一点

### CLI

一律通过 `scripts/j2c`（Windows 上 `scripts\j2c.ps1`）运行，以使用
`py/.venv` 里的工作区解释器。`doctor` 不会启动 JVM 模块或加载 agent，
只检查版本和产物。

### 桌面查看器

[`jvm/desktop-ui/`](../jvm/desktop-ui/) 是以只读展示为主的 Swing + FlatLaf
客户端。用 `scripts/gui.sh [会话目录]` 启动。它列出方法、恢复后的方法体、
管线状态、绑定缺口，并能跟踪 `trace.jsonl`。**Attach / Listen** 是同一条
`attach` CLI 的前端（所有权勾选、拒绝横幅，没有第二套协议）。真正的恢复
步骤仍走 CLI。该模块用 JDK 21；仓库其余部分仍是 JDK 17。详见
[desktop-gui.md](desktop-gui.md)。

### native-x86（预览）

用户态 host + 插件：模块、导出，以及在 Linux 上对具名导出做 metadata-only
的进入/返回观察（`SSL_*` / `RSA_*` / `AES_*` / `EVP_*`、`Java_*`、Windows
CNG `BCrypt*` 按名字）。Windows 只读（模块/导出）。Linux 活动观察仅限单线程
（ptrace / INT3）。**仅 metadata**：不拦截 TLS、不采集缓冲区或密钥、不做
stealth、没有内核组件。需要同一用户 + `--i-own-this-process`。详见
[native-x86-module.md](native-x86-module.md) 与 [plugin-abi.md](plugin-abi.md)。

### 特权观察器（用户态，默认关闭）

[`privileged-observer/`](../privileged-observer/) 加载带版本号的用户态插件。
随仓库提供的 Linux 后端读取 `/proc/<pid>/maps`，输出模块路径与地址。必须同时
给出 `--i-enable-privileged-observer` 与 `--i-own-this-process`。本仓库
**不发布内核镜像或内核源码**。详见
[privileged-observer.md](privileged-observer.md)。

---

## 仓库地图

```
├── scripts/                    j2c、j2c.ps1、setup、gui.sh / gui.ps1
├── jvm/                        Kotlin/ASM（Gradle；除 desktop-ui 外为 JDK 17）
│   ├── jar-parser/             jar → classes.json
│   ├── trace-to-bytecode/      trace.jsonl → recovered/*.json
│   ├── class-rebuilder/        recovered/ → output.jar
│   ├── common/                 公共 schema 类型
│   └── desktop-ui/             Swing + FlatLaf 查看器（JDK 21）
├── native/                     C++ JVMTI agent（OnLoad + OnAttach）
├── native-x86/                 用户态观察 host + 插件
├── privileged-observer/        用户态 maps host + Linux 插件
├── ghidra/scripts/             可选 Headless 方法体 dump
├── py/                         uv workspace
│   ├── binary_introspect/      blob → binary.json
│   ├── manifest_merge/         classes + binary → manifest.json
│   ├── ast_matcher/            pseudo-C → 字节码
│   ├── j2c_dumper_cli/         CLI 编排器
│   └── native_emulate/         Unicorn + mock JNI
├── schemas/                    版本化 JSON Schema
└── docs/                       本页及下列指南
```

---

## 已经冻结的决策

见 [options-and-status.md](options-and-status.md) 与
[decisions.md](decisions.md)：

| 议题 | 选择 |
|---|---|
| 「已还原」的含义 | 覆盖率 + 行为校验都通过才叫 restored；较弱结果必须单独标注 |
| 部分输出 | 能跑则默认 hybrid JAR；否则 inspection-only |
| 桌面工具包 | Swing + FlatLaf；没有 Web UI |
| 附加策略 | 同一用户 + `--i-own-this-process` |
| 密码学观察 | 仅 metadata |
| 特权观察器 | 默认 **否**；仅用户态预览 |
| 通用发现 | 不是默认 `recover` 路径 |

---

## 仍然不成立的事

- 通用发现**不是**默认发布路径。
- 记下 `unreadable-table` 缺口**并不**解密表内容。
- 活动附加**不等于**启动期 `-agentpath`。
- GUI **不**替代 CLI。
- native-x86 **不是** JAR 恢复的一部分，也**不是**产品级 ABI。
- 特权观察器**不是**内核功能，且默认**不**开启。
- **没有** stealth、TLS 内容采集，也没有随仓库发布的内核驱动。

---

## 接下来看哪里

| 如果你想… | 阅读 |
|---|---|
| 10 分钟恢复一个能跑的 JAR | [getting-started.zh-CN.md](getting-started.zh-CN.md) |
| 了解阶段契约 | [ARCHITECTURE.md](ARCHITECTURE.md) |
| 不靠 Ghidra 发现方法 | [generic-recovery.md](generic-recovery.md) |
| 附加到活动 JVM | [jvm-attach.md](jvm-attach.md) |
| 打开桌面查看器 | [desktop-gui.md](desktop-gui.md) |
| 模拟一个 blob | [emulation-recovery.md](emulation-recovery.md) |
| 手工编辑恢复 JSON | [manual-restoration.md](manual-restoration.md) |
| 检查进程镜像 | [native-x86-module.md](native-x86-module.md) |
| 打开用户态观察器 | [privileged-observer.md](privileged-observer.md) |
| 看决策与合并状态 | [options-and-status.md](options-and-status.md) |
