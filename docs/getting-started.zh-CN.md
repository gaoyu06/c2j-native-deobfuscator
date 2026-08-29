[English](getting-started.md) | [中文](getting-started.zh-CN.md)

# 10 分钟上手

这是从全新 clone 到产出恢复后 jar 的最短路径，走的是**默认（动态）路径** ——
不需要 Ghidra，也不需要编码智能体。

动态路径的前提是你能在自己的环境里**跑起来**这个混淆 jar。如果跑不起来，请直接
看[目标跑不起来时怎么办](#目标跑不起来时怎么办)。

---

## 0. 前置条件

- **JDK 17+**，并把 `JAVA_HOME` 指向它（`java -version` 应显示 17 及以上）。
- **Python 3.11+**。
- 仅构建 native agent 时需要：**[zig](https://ziglang.org/) 0.16.x**。
  可选；装不上就跳过它，改用模拟兜底。
- 在 **Windows** 上构建 native agent 还需要 **Git Bash**（随
  [Git for Windows](https://git-scm.com/download/win) 提供），这样才能运行
  `native/build.sh` 并产出 Windows DLL。WSL **不等价**：它会构建 Linux 的
  `.so`，而不是这里 JVM 加载的 Windows `.dll`。

其余依赖（`uv`、ASM、`capstone`、`lief`……）都由 setup 脚本自动拉取。默认恢复
路径会 import `capstone`，因此它是 `binary-introspect` 的必需依赖，并非可选。

> **请通过 `scripts/j2c` 运行 CLI**（Windows 上为 `scripts\j2c.ps1`）。setup 会用
> `uv` 把 Python 工作区装进 `py/.venv`，所以直接用*系统* `python3 -m j2c_dumper_cli`
> 是找不到这些包的。该启动器会运行真正装了这些包的解释器（`uv` 的 venv，或 `pip`
> 兜底所用的解释器）。

---

## 1. 安装（一次性构建全部）—— 约 3–5 分钟

```bash
git clone <本仓库> && cd c2j-native-deobfuscator
bash scripts/setup.sh            # Linux / macOS
# Windows（PowerShell）：pwsh scripts/setup.ps1
```

`scripts/setup.sh` 是幂等的（可以放心重复执行）。它会：

1. 构建 JVM 模块（`jvm/*/build/install/...`）；
2. 同步 Python 工作区（`uv sync`，否则回退到 `pip install -e`）；
3. 当 JDK **且** `zig` 都存在、**且主机是 x86-64** 时构建 native JVMTI agent ——
   否则打印清晰提示并继续（只有动态路径需要它）。`native/build.sh` 面向 x86-64；
   在 ARM（或其他 CPU）上 setup 会跳过 native agent，并且*不会*报告动态路径就绪。

## 2. 检查工具链 —— 约 10 秒

```bash
scripts/j2c doctor       # Windows：scripts\j2c.ps1 doctor
```

它会打印一张表，并为每个缺失项给出确切的下一步命令。一台尚未就绪的机器示例：

```
JVM modules (installDist)   MISSING   not built: jar-parser, ...
Native JVMTI agent          MISSING   no j2c_agent.so under native/build/lib
...
Not ready. Missing: ... Run scripts/setup.sh (or scripts/setup.ps1) to fix.
```

`doctor` 检查工具版本，以及默认路径所需的构建产物是否存在（它不会启动 JVM 模块，
也不会加载 agent）。只有当某个必需项**缺失**时它才以非零码退出，因此可以用它给
脚本做前置门槛。`WARN`（例如 Java 版本够新但 `JAVA_HOME` 未设）只是提醒，不算失败，
也不会翻转就绪标志。可选工具（Ghidra、unicorn、zig）永远不会导致阻塞。在本机上
`doctor` 只接受它真正能加载的 agent 文件名（Linux 上是 `j2c_agent.so`，macOS 上是
`.dylib`，Windows 上是 `.dll`），并且文件头必须表明它是为本机 CPU 构建的；为其他
操作系统遗留、为其他 CPU 架构构建、或格式无法识别的产物都会被报告为 missing。由于
`native/build.sh` 只面向 x86-64，非 x86-64 主机（例如 ARM）无论 `native/build/lib`
里放着什么，agent 都会被报告为 missing —— 动态路径在那里不可用，请改用模拟兜底或
静态路径，两者都不需要 agent。

## 3. 恢复 —— 约 1–2 分钟

```bash
scripts/j2c recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

`--run-cmd` 是一条能真正**运行**该混淆 jar 的命令，好让 JVMTI agent 观察它。
记得触达你关心的类（一个只打印 help 的 CLI 不会 trace 到有意思的代码路径）。

跑完你会得到 `path/to/clean.jar`：原先的 native 方法桩会被替换为**针对已观察到的
行为、尽力恢复出的方法体**，loader / native blob 资源条目也被剥离。动态 trace 只
覆盖 `--run-cmd` 实际执行到的路径；未观察到的方法可能仍是桩或只有部分方法体，因此
请检查输出，难度较大的目标要预期需要人工补全。

---

## JSON 中间产物在哪里

`recover` 会把中间产物写到一个工作目录。默认是首行打印的一个新临时目录
（`workdir: /tmp/j2c-XXXX`）。用 `--workdir ./work` 可以自己指定。目录里包含：

| 文件 | 由谁产出 | 内容 |
|---|---|---|
| `classes.json`   | `parse-jar`      | 类骨架 + native 方法注册表 |
| `binary.json`    | `inspect-binary` | 来自 blob 的字符串池 + 隐藏类 |
| `manifest.json`  | `merge-manifest` | 前两者合并，含 `cacheTable` |
| `trace.jsonl`    | `dynamic-trace`  | 每条观察到的 JNI 调用一行 JSON |
| `recovered/*.json` | `trace-to-bc`  | 抬升后的字节码，每个 native 方法一个文件 |
| 你的 `-o` jar    | `rebuild`        | 最终 loader 已剥离的输出 |

`recovered/*.json` 就是当难度较大的目标需要人工过一遍时，你要手工编辑的产物 ——
见 [`manual-restoration.md`](manual-restoration.md)。

---

## 常见故障

**`recover cannot start: required build artifacts are missing`**
JVM 模块或 native agent 没构建。先跑 `scripts/setup.sh`（或 `scripts/setup.ps1`），
再 `scripts/j2c doctor`。

**`doctor` 显示 `Java / JDK 17+  WARN` —— JAVA_HOME 未设置**
Java 版本够新，但 `JAVA_HOME` 没设；native agent 构建需要它。这是提醒，不是阻塞：
如果 agent 已经构建好，动态路径仍可运行。等下次需要构建 agent 时，把 `JAVA_HOME`
指向你的 JDK 目录再重跑 `scripts/setup.sh`。

**`doctor` 显示 `Native JVMTI agent  MISSING` 且 setup 跳过了它**
没找到 `zig`（或 JDK 头文件）—— 或者存在的是为其他操作系统遗留的 agent。安装
[zig](https://ziglang.org/) 0.16.x（或把 `ZIG` 设为它的路径）、设置 `JAVA_HOME`，
再 `bash scripts/setup.sh --force`。装不了 `zig` 就用下面的模拟兜底。

**Gradle 找不到匹配的 Java toolchain**
安装 JDK 17+ 并设置 `JAVA_HOME` 后重跑。`doctor` 会显示它找到的是哪个 Java。

**`recover` 跑完了，但 `trace.jsonl` 里没有 `enter` 事件**
你的 `--run-cmd` 没触达混淆类。换一条能真正运行到它们的命令；动态路径只能恢复
实际执行到的分支。

---

## 目标跑不起来时怎么办

先运行通用、无需 Ghidra 的发现管线。它把 JAR 中的 native 声明与 JNI 标准入口证据
合并起来：直接导出的 `Java_*` 符号和 `RegisterNatives` 动态注册。

```bash
scripts/j2c parse-jar      in.jar      -o classes.json
scripts/j2c inspect-binary natives.bin -o binary.json
scripts/j2c merge-manifest classes.json binary.json -o manifest.json
```

这三步既不需要真实运行，也不需要 Ghidra；它们产出的是方法发现 manifest，而不是
恢复后的方法体。通用发现实现位于
[`py/binary_introspect`](../py/binary_introspect)；更完整的 generic-first 覆盖正在
[PR #4](https://github.com/gaoyu06/c2j-native-deobfuscator/pull/4) 中完成。

如果要获得可执行行为和纯 C 常量，再使用**模拟兜底**。它同样无需 JVM、无需 Ghidra：
在 CPU 模拟器 + mock JNI 下直接执行 native 代码，因此能列出 native 方法、dump
解密后的常量，并把方法当纯函数 oracle 来调用。

把 `unicorn` 装进 setup 所用的那个解释器，并用它来跑 harness（启动器只包装 CLI 子命令）：

```bash
(cd py && uv pip install unicorn)    # 没有 uv？`scripts/j2c doctor` 会打印确切命令
py/.venv/bin/python py/native_emulate/j2c_emu.py recover natives.bin --binary-json binary.json
```

完整步骤见 [`emulation-recovery.md`](emulation-recovery.md)。

当 JAR 无法运行、而你又希望得到可抬升为静态方法体的 pseudo-C 时，Ghidra Headless
才是一个**可选的后续步骤**；见
[README](../README.zh-CN.md) 里的"进阶：静态恢复"一节。
