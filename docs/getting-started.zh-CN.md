[English](getting-started.md) | [中文](getting-started.zh-CN.md)

# 10 分钟上手

这是从全新 clone 到产出恢复后 jar 的最短路径，走的是**默认（动态）路径** ——
不需要 Ghidra，也不需要编码智能体。

动态路径的前提是你能在自己的环境里**跑起来**这个混淆 jar。如果跑不起来，请直接
看[目标跑不起来时怎么办](#目标跑不起来时怎么办)。

---

## 0. 前置条件

- **JDK 21+**，并把 `JAVA_HOME` 指向它（`java -version` 应显示 21 及以上）。
- **Python 3.11+**。
- 仅构建 native agent 时需要：**[zig](https://ziglang.org/) 0.16.x**。
  可选；装不上就跳过它，改用模拟兜底。

其余依赖（`uv`、ASM、capstone……）都由 setup 脚本自动拉取。

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
3. 当 JDK **且** `zig` 都存在时构建 native JVMTI agent —— 否则打印清晰提示并
   继续（只有动态路径需要它）。

## 2. 检查工具链 —— 约 10 秒

```bash
python -m j2c_dumper_cli doctor
```

它会打印一张表，并为每个缺失项给出确切的下一步命令。一台尚未就绪的机器示例：

```
JVM modules (installDist)   MISSING   not built: jar-parser, ...
Native JVMTI agent          MISSING   no j2c_agent.(so|dll|dylib) under native/build/lib
...
Not ready. Missing: ... Run scripts/setup.sh (or scripts/setup.ps1) to fix.
```

默认路径未就绪时 `doctor` 会以非零码退出，因此可以用它给脚本做前置门槛。可选
工具（Ghidra、unicorn、zig）永远不会导致阻塞。

## 3. 恢复 —— 约 1–2 分钟

```bash
python -m j2c_dumper_cli recover \
    path/to/obfuscated.jar \
    -o path/to/clean.jar \
    --run-cmd "java -jar path/to/obfuscated.jar"
```

`--run-cmd` 是一条能真正**运行**该混淆 jar 的命令，好让 JVMTI agent 观察它。
记得触达你关心的类（一个只打印 help 的 CLI 不会 trace 到有意思的代码路径）。

跑完你会得到 `path/to/clean.jar`：原先的 native 方法现在拥有真实字节码方法体，
loader / native blob 资源条目也被剥离。

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
再 `python -m j2c_dumper_cli doctor`。

**`doctor` 显示 `Java / JDK 21+  WARN` —— JAVA_HOME 未设置**
Java 版本够新，但 `JAVA_HOME` 没设；native agent 构建需要它。把 `JAVA_HOME`
指向你的 JDK 目录后重跑 `scripts/setup.sh`。

**`doctor` 显示 `Native JVMTI agent  MISSING` 且 setup 跳过了它**
没找到 `zig`（或 JDK 头文件）。安装 [zig](https://ziglang.org/) 0.16.x（或把 `ZIG`
设为它的路径）、设置 `JAVA_HOME`，再 `bash scripts/setup.sh --force`。装不了 `zig`
就用下面的模拟兜底。

**Gradle 找不到匹配的 Java toolchain**
安装 JDK 21+ 并设置 `JAVA_HOME` 后重跑。`doctor` 会显示它找到的是哪个 Java。

**`recover` 跑完了，但 `trace.jsonl` 里没有 `enter` 事件**
你的 `--run-cmd` 没触达混淆类。换一条能真正运行到它们的命令；动态路径只能恢复
实际执行到的分支。

---

## 目标跑不起来时怎么办

改用**模拟兜底** —— 无需 JVM、无需 Ghidra。它在 CPU 模拟器 + mock JNI 下直接执行
native 代码，因此能列出 native 方法、dump 解密后的常量，并把方法当纯函数 oracle
来调用：

```bash
pip install unicorn
python py/native_emulate/j2c_emu.py recover natives.bin --binary-json binary.json
```

完整步骤见 [`emulation-recovery.md`](emulation-recovery.md)。

**静态路径**（Ghidra）是用于离线逐方法覆盖的**进阶、可选**路线；见
[README](../README.zh-CN.md) 里的"进阶：静态恢复"一节。
