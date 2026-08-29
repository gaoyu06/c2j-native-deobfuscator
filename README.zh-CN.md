[English](README.md) | **中文**

# c2j-native-deobfuscator

把被 **JNI native 混淆器** 处理过的 JAR 还原回可读的 Java 字节码。
目标对象是 [`native-obfuscator`](https://github.com/radioegor146/native-obfuscator)
及其衍生工具（如 j2cc）—— 凡是把 JVM 字节码翻成 C++、再通过 JNI 从打包进
JAR 的 `.dll` / `.so` 回调 Java 的混淆方案，都在覆盖范围内。

提供四条互补的恢复路径（只有**动态**是默认的 `recover` 流程）：

| 路径 | 输入 | 思路 |
|---|---|---|
| **动态** | 混淆后的 JAR + 一条可运行的命令 | 启动时加载 JVMTI agent，观察 JNI 调用流，把它重新拼回 JVM 字节码 |
| **轻量静态** | 转译后的 JAR + native blob | 无需 Ghidra，发现 JNI 方法表、生成 manifest 和字节码还原 stub |
| **静态方法体** | 离线 manifest + 可选 Ghidra | 发现之后，可选地反编译各函数并把 pseudo-C 抬升回 JVM 字节码 |
| **模拟** | 混淆后的 blob（不需运行、不需 Ghidra） | 用 CPU 模拟器 + mock JNI 直接跑 native 代码：恢复方法表、dump 解密后的常量、把方法当纯函数来调用 |

离线发现是各路径共用的第一步，**不需要 Ghidra**：`parse-jar` 读取 JAR 声明，
`inspect-binary` 按 JNI 规范检查入口（直接导出的 `Java_*` 符号和
`RegisterNatives` 动态注册），`merge-manifest` 再合并这些证据。实现位于
[`py/binary_introspect`](py/binary_introspect)，详见
[`docs/generic-recovery.md`](docs/generic-recovery.md)。只有当 JAR 无法运行、
而你又希望从 pseudo-C 恢复静态方法体时，才需要在后续可选地使用 Ghidra。

动态路径和可选的方法体插件可以输出 `out.jar`。覆盖度按方法计：未观察到或
未能抬升的方法可能仍是桩。轻量静态路径先生成可审计的方法 manifest 与可通过
校验的 stub；模拟路径还能补充运行时注册信息、解密常量和纯函数 oracle。

协议：**GPLv3**。

[可选观察器契约](docs/privileged-observer.md)默认关闭，本项目不为其签名。
JAR 还原不需要它；仓库不发布内核镜像或内核源码。

当前架构、全部表面、默认 vs 预览状态见
**[docs/overview.zh-CN.md](docs/overview.zh-CN.md)**
（[English](docs/overview.md)）。

---

## 架构速览

```
  CLI（scripts/j2c）  ·  可选桌面查看器（scripts/gui.sh）
                         │  版本化 JSON（schemas/）
          发现 ──────────┼───── 恢复引擎 ───── 重建
   parse-jar / inspect-  │   动态 JVMTI（默认）    class-rebuilder
   binary / merge-       │   attach（预览）         → out.jar
   manifest              │   轻量静态（draft-dev）
                         │   模拟 / Ghidra 方法体（可选）

  相邻、不在 JAR 路径上：
    native-x86/                 用户态 metadata 观察
    privileged-observer/        用户态 maps；默认关闭
```

| 表面 | 作用 | 是否默认？ |
|---|---|---|
| `scripts/j2c recover` | 启动期 `-agentpath` 动态恢复 | **是** |
| `parse-jar` / `inspect-binary` / `merge-manifest` / `static-lite` | 无 Ghidra 的方法发现 + stub | 否（draft-dev） |
| `emulate` | Unicorn + mock JNI（表 / 字符串 / oracle） | 否 |
| Ghidra + `static-reverse` | 可选 pseudo-C 方法体 | 否 |
| `scripts/j2c attach` | 活动、同一用户的 JVMTI 附加 | 否（预览） |
| `scripts/gui.sh` | Swing + FlatLaf 产物 / 附加查看器 | 否（可选） |
| `native-x86/` | 进程镜像 metadata，插件 ABI 0.2 | 否（预览；不在 JAR 路径上） |
| `privileged-observer/` | 用户态 `/proc` maps | 否（默认**关**） |

---

## 自己动手运行

默认的恢复路径完全可以手动跑起来，不需要任何编码智能体：

```bash
git clone <本仓库> && cd c2j-native-deobfuscator
bash scripts/setup.sh                      # 构建 JVM + Python（x86-64 上再构建 native agent）
scripts/j2c doctor                         # 检查版本 + 构建产物
scripts/j2c recover in.jar -o out.jar --run-cmd "java -jar in.jar"
```

> **请通过 `scripts/j2c` 运行 CLI**（Windows 上为 `scripts\j2c.ps1`）。setup 会用
> `uv` 把 Python 工作区装进 `py/.venv`，所以直接用*系统* `python3 -m j2c_dumper_cli`
> 找不到这些包。该启动器会挑选真正装了这些包的解释器。

详见下方的 [Quick start](#quick-start)、
[10 分钟上手指南](docs/getting-started.zh-CN.md)
（[English](docs/getting-started.md)），以及
[架构与功能一览](docs/overview.zh-CN.md)。

**什么时候需要人工过一遍。** 本项目提供的是对整个"把 Java 转译成 C/C++
再通过 JNI 回调"混淆器家族的**通用思路**，所以难度较大的目标仍可能需要针对
具体方法做适配（读反编译、补每个方法依赖的状态、扩展 harness、加 profile）。
遇到这种情况，恢复出的 `*.json` 中间产物本就是给你手工编辑的 —— 参见
[`docs/manual-restoration.md`](docs/manual-restoration.md)。

**可选：** 编码智能体很擅长做这类适配。如果你用它，可以加载随仓库附带的 skill
（[`.claude/skills/j2c-deobfuscate`](.claude/skills/j2c-deobfuscate/SKILL.md)）
再把目标交给它。这只是锦上添花，并非必需 —— CLI 本身即可独立运行。

---

## 效果展示

基于 `e2e-test/snake/` 真实端到端 fixture 自动生成 —— 每张图都是用 HTML + Prism.js 渲染实际还原产物、再 Chrome headless 截下来的，没有任何手工编辑。
> （此前的"占位项"已替换为下方实际截图。）
> 完整目录见 [`screenshots/README.md`](screenshots/README.md)。

**静态路径 — Snake.java 完整对比**

![](screenshots/showcase/snake-static-overview.png)

原始源码 vs Vineflower 解出来的静态路径产物。capstone 抽到的 cache-table 把每个 cclasses/cfields/cmethods slot 都对回 `(owner, name, desc)`；lifter 把 JNI `param_2` 预绑到 JVM 局部槽 0，receiver 全部正确显示为 `this`。

**动态路径 — Snake.java 完整对比**

![](screenshots/showcase/snake-dynamic-overview.png)

同样输入，走 JVMTI agent：被混淆的 native 代码每一次 JNI 调用都被记录下来再抬升回 JVM 字节码。被实际执行到的分支，输出和 javac 字节码几乎一致。

**静态路径迭代过程**

![](screenshots/showcase/snake-static-progression.png)

同一输入，静态路径三个阶段：stub 兜底 → tier 2 unverified 写入 → cache-table + receiver 绑定。每一步多救回一层语义信息。

**JVMTI 动态路径的中间产物**

![](screenshots/showcase/dynamic-intermediates.png)

动态路径如何把运行时的 JNI 调用流转成 JVM 字节码：agent 写的 `trace.jsonl`（每条 JNI 调用一条 JSON）、抬升后的 `recovered/*.json`、以及把它们串起来的流水线。

**同输入两条路径：Board.java**

![](screenshots/showcase/board-static-vs-dynamic.png)

静态路径离线快但覆盖率受限于每种混淆器的模式识别；动态路径要求目标能跑起来，但对运行时实际触达的分支几乎能产出 javac 等价的字节码。

**动态路径手动还原**

![](screenshots/showcase/manual-restoration-dynamic.png)

熟手 10-15 分钟过一遍能做到的事：删 SSA 槽位 `Object varN = null;` 声明、inline 单用临时变量、把 trace 烧进去的具体常量换回符号表达式、补回 trace 没走到的分支。完整流程见 [`docs/manual-restoration.md`](docs/manual-restoration.md)。

**静态路径手动还原**

![](screenshots/showcase/manual-restoration-static.png)

需要更多人工推理，但中间产物保证不靠猜：`recovered/*.json` 记录了 lifter 抽到的 opcode 序列，`manifest.json.cacheTable` 把每个 `?.?` 都对回真实的 `(owner, name, desc)` —— 即便反编译器没把它们渲染出来。

---

## 技术栈

### 动态路径

- **JVMTI agent**（`native/`，C++）。默认通过 `-agentpath:` 在启动时加载；
  也可作为预览，用 `Agent_OnAttach` 附加到已经在跑、且属于同一用户的 JVM
  （见 [`docs/jvm-attach.md`](docs/jvm-attach.md)）。启动时订阅
  `NativeMethodBind`、`MethodEntry`、`MethodExit`、`Exception`、
  `ExceptionCatch`；活动附加只订阅 JDK 仍授予的事件（在 OpenJDK 21 上常常
  只有 `NativeMethodBind`）。
- **JNI 函数表替换**。在 `VMInit` 和每个 `ThreadStart` 时，把
  `JNIEnv->functions` 指针整体换成一份代理表。代理表里约 80 个槽位都被
  重定向到记录调用日志的 wrapper，wrapper 在转发到原函数前把这次调用
  写成一行 JSON 进 `trace.jsonl`。`Call*Method` 这类变参形式按
  jmethodID 缓存的 descriptor 解析 `va_list`。
- **符号传播**（`jvm/trace-to-bytecode/`）。抬升器逐条扫描 trace，根据
  每个 jobject 的来源给它打类型标签（`FindClass` → jclass，
  `GetMethodID` → jmethodID，等等），再按完整的 owner / name / desc 信息
  发射对应的 JVM opcode。
- **SSA 风格的合成 local**。被多次复用的 jobject 会分配一个合成槽位，
  在产生它的 JNI 调用后追加 `DUP + ASTORE <slot>`，每个复用点改用
  `ALOAD <slot>`。这样还原出的字节码保留了真实的引用同一性，不必重复
  推导。
- **操作数栈平衡器**。跟踪当前栈状态，在必要位置插入 `POP` / `CHECKCAST`
  / `ACONST_NULL`，让最终的字节码可以通过 ASM 的
  `COMPUTE_FRAMES` 校验。

### 离线发现（无需 Ghidra）

- **基于 JNI 规范的方法表发现**（`jar-parser`、`py/binary_introspect/`、
  `manifest-merge`、`capstone`）。`parse-jar`、`inspect-binary`、
  `merge-manifest` 从 JAR 声明以及 JNI 规范定义的机制构建 `manifest.json`：
  直接导出的 `Java_*` 符号和 `RegisterNatives`（vtable 索引 215，按 ABI
  核对方法表与长度参数）。支持 PE/Microsoft x64、ELF/Mach-O System V、
  AArch64、ARM 和 i386 ELF。静态 `JNINativeMethod[]`、栈上构造的表、共享
  调用点和 `Java_*` 导出可互相补充。这个阶段既不需要活 JVM，也不需要 Ghidra。
- **轻量静态编排**无需反编译器即可生成 `binary.json`、`manifest.json`
  以及可通过校验的 stub；可选的注册模拟还能补全运行时名称和 descriptor。

### 静态方法体恢复（可选 Ghidra 步骤）

- **可选 Ghidra 插件**（`ghidra/scripts/DumpFromManifest.java`，Ghidra
  Headless）。当 JAR 无法运行、而你又需要静态方法体时，才在后续使用它。
  它读取 `manifest.json` 中的 `(class, method, fnAddr)`，对每个地址跑一次
  p-code 反编译，结果汇总到 `ghidra-dump.json`，每个方法对应一段 pseudo-C。
- **tree-sitter-c AST 解析**（`py/ast_matcher/`，`tree-sitter-c`）。把
  Ghidra 输出的 pseudo-C 解析成 AST，再由按 feature flag 控制的 driver
  识别 `env->FnName(args)` 形式的 JNI 调用（这是从 Ghidra 的
  `(**(code **)(*reg + 0xN))(...)` 形式改写来的）、JNI helper 模式以及
  异常检查守卫。
- **可选异常文案推断**。部分变体会在每次潜在 Java 调用前生成
  `"Cannot invoke X.Y.Z(args)"` 字符串以备运行时抛异常用。当符号跟踪
  穿不过混淆器自己的 helper 时，抬升器把这些字符串解析成 invoke hint
  做兜底的 `(owner, name, args-desc)` 来源。
- **Profile 自动探测**。匹配变体的采集策略（每类一张表
  vs 共享 dispatch）、异常文案正则、if-guard 跳过规则等都来自一个
  `Profile`，由二进制扫描出来的探测器选定；这些启发式在 `generic` 下关闭。

### 模拟路径

- **整 blob 模拟**（`py/native_emulate/`，`unicorn`）。把 native blob（PE 或
  ELF）映射进 CPU 模拟器，在一套 **mock JNI 环境**（伪造的
  `JNIEnv`/`JavaVM`，其 vtable 槽位回陷进 Python）下直接执行被混淆的函数。
  因为它是真"跑"代码，所以能看到 JNI tracing 看不到的东西：被内联的比较
  （那个从不调用 `String.equals` 的校验）、解密后的 `<clinit>` 字符串表，
  以及藏在控制流平坦化 / MBA 后面的逻辑（模拟器只管跑字节，不去结构化它）。
- **`recover`** — 模拟注册函数（或读 `Java_*` 导出 / `JNI_OnLoad`）并捕获
  `RegisterNatives`，列出每个 native 方法的 `(name, sig, fnPtr)`。对
  native-obfuscator 全自动；j2cc 需要 regc 地址（来自 `binary.json`）。
- **`strings`** — 模拟一个方法并 dump 出它解密后的字符串常量（字母表、
  密文、提示语）——也就是另外两条路只能留成下标访问的那张字符串表。
- **`call`** — oracle：把恢复出的 native 方法当纯函数调用，喂输入、抓输出。
  把"读一万行平坦化 MBA"变成"输入→输出"地探测。
- **JNI ABI 由 JVM 规范钉死**（`GetArrayLength`=vtable index 171，
  `RegisterNatives`=215，`ExceptionCheck`=228…），所以同一套引擎对整个家族
  通用。后端：x86-64 PE/Win64 与 ELF/System-V。详见
  [`docs/emulation-recovery.md`](docs/emulation-recovery.md)。

### 可选桌面查看器

- **Swing + FlatLaf**（`jvm/desktop-ui/`，**仅此模块**需要 JDK 21）。
  `scripts/gui.sh [会话目录]` 打开会话文件夹，展示方法、恢复后的方法体、
  管线状态、绑定缺口，以及实时 `trace.jsonl`。**Attach / Listen** 是
  `scripts/j2c attach` 的前端，不会另起一套协议。恢复步骤仍走 CLI。
  详见 [docs/desktop-gui.md](docs/desktop-gui.md)。

### 共用部分

- **JSON 管线**。每个阶段的输入和输出都是 `schemas/` 下带版本号的 JSON
  artifact。
- **ASM**（`org.objectweb.asm`）负责所有 class 文件发射。
  `ClassWriter.COMPUTE_FRAMES` 是验证关；栈不平衡而未通过的方法会被替换
  成 sentinel stub，JAR 仍然可以产出。

---

## 适用对象

两条路径输入相同，但在覆盖率和准确性上取舍不同：

| | 动态 | 静态 | 模拟 |
|---|---|---|---|
| **适合的场景** | JAR 能运行并触达相关类。 | 支持的二进制中能看到标准 JNI 导出或 `RegisterNatives`。 | 逻辑被改写成纯 C、注册表在运行时构造，或需要解密后的常量。 |
| **要求** | 一条能触达转译类的运行命令。 | JAR + native blob；方法清单、manifest 和 stub 不需要 Ghidra。可选 Ghidra 仅用于静态方法体。 | native blob + 可选 `unicorn`；不需要 JVM 或 Ghidra。 |
| **覆盖率** | 只覆盖实际执行到的分支。 | 覆盖通过结构校验的导出/方法表；方法体恢复是独立步骤。 | 覆盖模拟能触达的方法与常量；方法行为通过 oracle 探测。 |
| **准确性** | 对已观察到的 JNI 调用准确度高。 | 命名表/导出的元数据可精确绑定；栈构造表按地址顺序兜底。 | 执行真实 native 代码，但不会自动产出字节码。 |
| **耗时** | 受目标运行时长与 agent 开销限制。 | 反汇编和表解码通常很快。 | 相关入口可触达时通常很快。 |

---

## 局限性

- **静态路径不保证准确性。** 抬升器是在 Ghidra 的 pseudo-C 上做模式
  匹配；Ghidra 没能干净结构化的控制流会产出栈不平衡的字节码，被
  `class-rebuilder` 静默降级成 stub。整个类的其他方法仍然能正常输出。
- **动态路径只能看到运行时实际触达的分支。** 一个 if/else，运行时只走
  if 的话，恢复出来的字节码里 else 就不存在；循环体只能看到一次迭代
  的痕迹；除非 agent 把某个值标记为动态值，否则它会被烧成 LDC 常量。
- **纯 native 控制流 / 算术运算对两条路径都不可见。** 当混淆器把一段
  完全不需要 JVM 协作的运算（字符数组操作、整型计算等）整体翻成 C++
  时，没有任何 JNI 调用发生，动态采不到，静态匹配 JNI 模式也匹配不到，
  这一段的方法体最终会是空或 stub。
- **AOT 转译过的逻辑无法恢复。** 一些高级混淆器会识别出"不依赖 JVM"
  的 Java 代码（例如对称加密、字节数组变换、走 POSIX / Win32 的文件
  操作），直接发射成纯 native 代码而不是 JNI-callback 形式的 C++。
  这种输出里完全没有 JNI 签名 —— 两条路径都只能给一个 stub，唯一的
  办法是人工读汇编。
- **`<clinit>` 解密的字符串表暂未还原。** 混淆器普遍会把每个类的字符串
  常量包成一张 XOR / 移位表，在类加载时解码。抬升器目前原样保留
  `Foo.a(0, 17)` 这样的下标访问，不替换具体值；规划中的做法是用清理后
  的 JAR 跑一次 `<clinit>` 把表 dump 出来再回填（详见 `docs/ROADMAP.md`）。

---

## Quick start

前置条件：**JDK 17+**（并设置 `JAVA_HOME`）与 **Python 3.11+**。在 Windows 上
构建 native agent 还需要 **Git Bash**（随 Git for Windows 提供）；WSL 会构建出
Linux 的 `.so`，而不是这里 JVM 加载的 Windows `.dll`。
第一次上手？请按
[10 分钟上手指南](docs/getting-started.zh-CN.md)（[English](docs/getting-started.md)）操作。

### 1. 安装（一次性构建全部）

```bash
# 幂等脚本：构建 JVM 模块、同步 Python 工作区，并在 x86-64 主机上检测到 JDK + zig
# 时构建 native agent。可以放心重复执行。
bash scripts/setup.sh            # Linux / macOS
# Windows（PowerShell）：
#   pwsh scripts/setup.ps1
```

`scripts/setup.sh` 在可用时用 [`uv`](https://docs.astral.sh/uv/) 同步 Python
工作区，否则回退到 `pip install -e`。native agent 这一步需要 JDK 和 `zig`；
缺任意一个时会带清晰提示跳过（只有动态路径需要它）。`native/build.sh` 面向
x86-64，因此在 ARM（或其他 CPU）上 setup 会跳过 native agent，并且不会报告动态
路径就绪 —— 那里请改用模拟兜底。

### 2. 检查工具链

```bash
scripts/j2c doctor       # Windows：scripts\j2c.ps1 doctor
```

`doctor` 会报告 Java/JDK、Python、Python 恢复阶段是否可 import（`capstone` +
`lief`）、已构建的 JVM 模块与本机匹配的 native agent，以及可选工具（Ghidra、
unicorn、zig），并为每个缺失项打印下一步命令。它只校验工具版本与产物是否存在，
不会启动 JVM 模块或加载 agent。只有当某个必需项**缺失**时它才以非零码退出；
`WARN`（例如 `JAVA_HOME` 未设）只是提醒，不是阻塞。agent 必须在文件名和 CPU 架构
两方面都与本机匹配：在非 x86-64 主机上，`native/build.sh` 无法产出可加载的 agent，
因此它始终被报告为 missing，动态路径不算就绪。

### 3. 恢复（默认路径 —— 动态）

**当目标在你环境里能跑起来时用这条。** 它把 JVMTI agent 挂到一次真实运行上，
观察 JNI 调用流，再抬升回字节码：

```bash
scripts/j2c recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

依次执行：

1. `parse-jar`         → `classes.json`
2. `inspect-binary`    （从 JAR 自动抽出 native blob）
3. `merge-manifest`    → `manifest.json`
4. `dynamic-trace`     带 JVMTI agent 跑目标 → `trace.jsonl`
5. `trace-to-bc`       抬升到 `recovered/*.json`
6. `rebuild`           输出 loader 已剥离的最终 JAR

输出包含的是**针对本次运行中观察到的行为、尽力恢复出的方法体**。动态 trace 只
覆盖实际执行到的路径，因此未观察到的方法可能仍是桩或只有部分方法体；请检查结果，
难度较大的目标要预期需要人工补全（见上文的"人工过一遍"说明）。

> **只用一个解释器。** `scripts/j2c ...` 会用 setup 安装这些包的解释器来运行 CLI
> （`py/.venv` 下的 `uv` venv，或 `pip` 兜底所用的解释器），你不必自己挑。少数
> CLI 没有包装的用法（下面的模拟 harness、抬升器的 feature flag）也走同一个解释器，
> 本文写作 `py/.venv/bin/python`（Windows 上为 `py\.venv\Scripts\python`）。如果
> setup 走的是 `pip` 兜底，就换成它安装到的那个解释器。

### 进程附加（预览 —— 可选、仅限同一用户）

如果目标 JVM 是你自己的、且已经在运行、无法重启，可以把同一个 JVMTI agent
附加到活动进程上，而不必用 `-agentpath`：

```bash
scripts/j2c attach --pid <pid> --i-own-this-process -o trace.jsonl
```

这是**预览**级诊断路径，**不是**默认路径 —— `recover` 仍走启动期 `-agentpath`
注入（观测更完整）。进程附加只能看到附加之后发生的行为，且能获得多少覆盖取决于
JDK 在附加*之后*还允许申请哪些 JVMTI 能力。在不少 JDK 上（**已在 OpenJDK 21
上实测**），活动附加只能拿到 native-method-bind，因此 trace 只有 `bind` 事件，
方法进入/退出、局部变量、异常等事件**不会**被捕获；agent 的 `capability` /
`gap` 记录会如实说明实际获得了什么。要完整恢复方法体请改用启动期路径。
进程附加必须显式提供 `--pid` 和 `--i-own-this-process` 确认标志，并且拒绝跨用户
目标。详见 [`docs/jvm-attach.md`](docs/jvm-attach.md)。

### 可选桌面查看器

恢复**不需要**这个 Swing 查看器。在 `recover --workdir`（或任何含 JSON
产物的会话目录）之后：

```bash
scripts/gui.sh ./work          # Windows：scripts\gui.ps1 .\work
```

它展示方法、恢复后的方法体、管线状态，并能运行或只监听 `attach`。
该模块需要 **JDK 21**；仓库其余部分仍是 JDK 17。详见
[`docs/desktop-gui.md`](docs/desktop-gui.md)。

### 离线发现与轻量静态（无需运行、无需 Ghidra）

当 JAR 无法运行时先从这里开始。下面的通用发现步骤会检查标准 JNI 导出符号和
`RegisterNatives` 注册证据；它们**不需要 Ghidra**：

```bash
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json

# 或一条命令：binary.json + manifest.json + recovered/*.json stub
scripts/j2c static-lite in.jar --lib natives.bin --profile generic -o static-lite/
```

详见 [`docs/generic-recovery.md`](docs/generic-recovery.md)。`inspect-binary`
会在 stderr 打印 `format/arch/profile=` 与 `unreadableTables=`；
`merge-manifest` 会打印 `bindingGaps=<n> kinds=…`。`bindingGaps` 不会写入
`binary.json`。可见但不可读的 `JNINativeMethod[]` 会记成 `unreadable-table`
缺口，而不是编造绑定。
如需可选的 pseudo-C 方法体抬升，可在轻量静态步骤后运行 Ghidra。

### 模拟恢复（无需 JVM、无需 Ghidra）

```bash
# 把 unicorn 装进工作区解释器（走 pip 兜底时，`scripts/j2c doctor` 会打印确切命令）
(cd py && uv pip install unicorn)

# 列出 native 方法（入口自动发现）
scripts/j2c emulate natives.bin --operation recover --binary-json binary.json

# dump 某个函数解密后的字符串常量（字母表、密文、提示语）
scripts/j2c emulate natives.bin --operation strings --fn 0x<addr>

# 把 native 方法当纯函数调用（oracle）
scripts/j2c emulate natives.bin --operation call --fn 0x<addr> \
    --arg-bytes "input" --static "v=@alphabet.txt"
```

完整步骤见 [`docs/emulation-recovery.md`](docs/emulation-recovery.md)；命令参考
与实测矩阵见 [`py/native_emulate/README.md`](py/native_emulate/README.md)。

### 分阶段执行

每个阶段都有独立的子命令，详见
`scripts/j2c --help`。

---

## 进阶：静态恢复（离线，需要 Ghidra）

这是上面无 Ghidra 发现之后的**可选后续步骤**。只有当 JAR 无法运行、而你又需要
模拟兜底不会自动产出的静态方法体 pseudo-C 时才使用它；这一步需要
**Ghidra 11.x**：

```bash
# 1. 通用 JNI 发现（不需要 --run-cmd，也不需要 Ghidra）
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json

# 2. 可选：通过 Ghidra Headless 抬升静态方法体
<GHIDRA>/support/analyzeHeadless.bat <project-dir> proj \
    -import natives.bin \
    -scriptPath <repo>/ghidra/scripts \
    -postScript DumpFromManifest.java manifest.json ghidra-dump.json

# 3. pseudo-C 抬升到字节码 + 重建 JAR
scripts/j2c static-reverse ghidra-dump.json --manifest manifest.json -o recovered/
scripts/j2c rebuild --input in.jar --recovered recovered/ \
    --manifest manifest.json -o out.jar
```

---

## 通用性

`generic` 是默认兜底，只依赖 JNI 规范中的结构事实：

- `RegisterNatives` 的 vtable 索引 215；
- Microsoft x64、System V x86-64、AArch64 AAPCS64（方法表用 `x2`，
  `nMethods` 用 `w3`/`x3`）、32 位 ARM AAPCS32（方法表用 `r2`，
  `nMethods` 用 `r3`）与 32 位 x86/i386 System V cdecl（参数走栈：
  `push $nMethods` / `push methods`）的参数传递方式；
- 合法的 `JNINativeMethod` 名称/descriptor 与可执行函数指针；
- 规范定义的 `Java_*` 导出；
- 可选的二进制模拟注册捕获。

它不会开启异常文案正则、反编译器输出重写、缓存表命名假设或异常/缓存
guard 跳过。匹配的变体 Profile 可以按需开启这些能力。Ghidra 脚本是可选的
方法体插件，不参与通用方法发现。

通用发现已由提交入库的 fixture 证明：覆盖三种 x86-64 目标格式（ELF、PE、
Mach-O）、**两种不同的注册族**——按类的单表注册器（`RegisterNatives` 静态表
或 `Java_*` 导出名）与共享 `initClass()` 式分发器（一个调用点为两个类注册、
`nMethods` 各不相同，两张栈表都被恢复而非折叠成一次绑定），并包含
符号剥离 ELF、**AArch64** ELF（`adrp`/`add` 取表地址，JNI 分发经 `x16`
中转寄存器）、**Mach-O arm64** dylib（报告 `format=MachO`/`arch=aarch64` 与
`_Java_*` 导出；当宿主 Capstone 能反汇编 AArch64 时，静态表还会经紧凑的单条
`adr` 取表地址方式解出）、**32 位 ARM** ELF（报告 `format=ELF`/`arch=arm` 与
`Java_*` 导出；当宿主 Capstone 能反汇编 ARM 时，静态表还会经字面量池 +
`add r2, pc, r2` 取表地址与 `ip` 中转寄存器解出）、**32 位 x86/i386** ELF
（报告 `format=ELF`/`arch=x86`，cdecl 走栈传参、经 GOT 基址 `lea` 取表地址，
是真正的 `EM_386` 镜像而非改名的 64 位 `.so`），以及**删除节头表**
（section header table）后仅靠 `PT_LOAD` 程序头兜底恢复的 ELF。完整
“已证明/未证明”对照见
[`docs/generic-recovery.md`](docs/generic-recovery.md)。该路径仍是开发中能力：
未提升为默认 `recover` 流程，也不声称还原方法字节码。

通用能力有明确边界：不支持的 ABI、模拟无法触达的非标准或加密注册流程、
自定义方法体布局仍需扩展 Profile 或 backend。详见
[`docs/generic-recovery.md`](docs/generic-recovery.md) 与
[`docs/adding-obfuscator-profile.md`](docs/adding-obfuscator-profile.md)。

可选 lifter 启发式仍可逐项关闭：

这些 flag 没有暴露在 `scripts/j2c static-reverse` 上，因此用工作区解释器直接跑抬升器：

```bash
py/.venv/bin/python -m ast_matcher.cli ghidra-dump.json -o recovered/ \
    --disable use_throw_reason_invoke_hints \
    --disable skip_native_exception_guards
py/.venv/bin/python -m ast_matcher.cli --list-flags
```

---

## 预览：`native-x86/`（不在 JAR 路径上）

[`native-x86/`](native-x86/) 是**实验性 / 预览**的用户态 host + 插件，
用于进程镜像 metadata。公开 ABI（v0.2）**不含 Java 类型**。动态、静态、
模拟路径都不依赖它；整个目录删掉也不影响它们。

目前能做的：

- Linux：同一用户 + `--i-own-this-process`；只读模块/导出，或**单线程**
  活动观察（ptrace / INT3），只记录具名导出的进入/返回 metadata。
- Windows：只读模块/导出快照（没有活动断点）。
- 示例插件按名字观察 OpenSSL `SSL_*` / `RSA_*` / `AES_*` / `EVP_*`、
  JNI 约定的 `Java_*`、以及 Windows CNG `BCrypt*` 导出。

明确不做的事：TLS 拦截、缓冲区/密钥/内容采集、stealth、任何内核组件。
详见 [`docs/native-x86-module.md`](docs/native-x86-module.md) 与
[`docs/plugin-abi.md`](docs/plugin-abi.md)。

## 预览：特权观察器（用户态，默认关闭）

[`privileged-observer/`](privileged-observer/) 是另一套用户态插件 host。
随仓库提供的 Linux 后端读取 `/proc/<pid>/maps`，输出模块路径与地址。
必须同时给出 `--i-enable-privileged-observer` 与 `--i-own-this-process`。
本仓库**不发布内核镜像或内核源码**。详见
[`docs/privileged-observer.md`](docs/privileged-observer.md)。

---

## 仓库结构

```
├── scripts/                    j2c / j2c.ps1、setup、gui.sh / gui.ps1
├── jvm/                        Kotlin/ASM 模块（Gradle；除 desktop-ui 外为 JDK 17）
│   ├── jar-parser/             input.jar  → classes.json
│   ├── trace-to-bytecode/      manifest + trace.jsonl → recovered/*.json
│   ├── class-rebuilder/        input.jar + recovered/ → output.jar
│   ├── common/                 公共 schema 类型
│   └── desktop-ui/             Swing + FlatLaf 查看器（JDK 21）
├── native/                     C++ JVMTI agent（OnLoad + OnAttach；zig c++）
├── native-x86/                 预览级用户态观察 host + 插件
│                               （任何恢复路径都不依赖它）
├── privileged-observer/        用户态 maps host；默认关闭；无内核镜像
├── ghidra/scripts/             Ghidra Headless 脚本（Java）
├── py/                         Python 模块（uv workspace）
│   ├── binary_introspect/      .dll / .so / natives.bin  → binary.json
│   │   ├── arch/               按架构 / ABI 的实现
│   │   ├── jni_tables.py       RegisterNatives 表发现
│   │   ├── profile.py          混淆器变体 Profile
│   │   └── stub_recovery.py    未恢复方法的 stub 合成
│   ├── manifest_merge/         classes.json + binary.json → manifest.json
│   ├── ast_matcher/            pseudo-C → JVM 字节码
│   │   └── lifter/             driver + 各 feature 子模块
│   ├── j2c_dumper_cli/         顶层 CLI 编排器
│   ├── native_emulate/         模拟路径：j2c_emu.py（Unicorn + mock JNI）
│   └── snippet_importer/       （可选）native-obfuscator cppsnippets 导入器
├── .claude/skills/             j2c-deobfuscate skill（智能体使用手册）
├── docs/                       overview、ARCHITECTURE、ROADMAP …
├── schemas/                    每种 artifact 的 JSON Schema
└── tests/                      端到端 fixture 与管线测试
```

---

## 文档

- [overview.zh-CN.md](docs/overview.zh-CN.md) — **架构与全部功能从这里开始**
  （[English](docs/overview.md)）
- [getting-started.zh-CN.md](docs/getting-started.zh-CN.md) — 10 分钟默认路径
  上手、常见故障、JSON 产物在哪
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — 模块边界、管线、artifact schema、扩展点
- [desktop-gui.md](docs/desktop-gui.md) — 可选 Swing 查看器
  （[模块 README](jvm/desktop-ui/README.md)）
- [jvm-attach.md](docs/jvm-attach.md) — 可选活动 JVMTI 附加（预览）
- [emulation-recovery.md](docs/emulation-recovery.md) — 模拟路径使用指南
  （命令参考见 [`py/native_emulate/README.md`](py/native_emulate/README.md)）
- [generic-recovery.md](docs/generic-recovery.md) — 无 Ghidra 的方法发现、
  manifest、stub、诚实缺口与可选模拟
- [manual-restoration.md](docs/manual-restoration.md) — 手工清理恢复产物
- [options-and-status.md](docs/options-and-status.md) — 决策、合并状态、晋升门槛
- [ROADMAP.md](docs/ROADMAP.md) — 已知限制和计划工作
- [adding-obfuscator-profile.md](docs/adding-obfuscator-profile.md) — 如何注册新混淆器变体
- [static-reverse-approach.md](docs/static-reverse-approach.md) — 基于 Ghidra 的静态路径设计笔记
- [native-x86-module.md](docs/native-x86-module.md) — 预览级用户态观察
  （[插件 ABI](docs/plugin-abi.md)、
  [密码学插件](docs/plugins/crypto-libraries.md)、
  [特权观察器](docs/privileged-observer.md)）
- [`.claude/skills/j2c-deobfuscate`](.claude/skills/j2c-deobfuscate/SKILL.md) —
  智能体使用手册（加载到你的编码智能体里）

---

## License

以 **GPL v3** 发布。详见 [LICENSE](LICENSE)。
