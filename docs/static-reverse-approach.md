# 静态反编译方案（Ghidra Headless + tree-sitter-c AST 匹配）

> **未开工**。本文档为 Phase 3b 的设计参考。

## 0. 锁定决策

| 决策点 | 选择 |
|---|---|
| 总体路线 | **方案 B**：Ghidra Headless 反编译 → 伪 C → AST 匹配。无 fallback，单技术栈 |
| 反编译器调用 | **GhidraScript**（不用 Ghidrathon），输出 JSON 给下游 |
| AST 解析 | **tree-sitter-c**（出问题再考虑 pycparser） |
| 阶段优先级 | **Phase 3a（JVMTI 动态）先做**；Phase 3b（本文档静态）后做，并用动态结果交叉验证 |
| 备选方案 A/C | **不实现**。下面 §3 仅作为方案 B 的对照说明保留 |
| `cppsnippets.properties` 模板生成 | **不进主流程**。作为独立可选 feature 提供（见 §10） |

---

## 1. 目标 & 输入

- **输入**：被 native-obfuscator（或其变体）处理过的 .dll / .so / .dylib，以及配套的 .jar
- **输出**：每个 `__ngen_<class>_<method>` 函数 → 对应的 JVM 字节码指令流（InsnList 级别），最终可被 ASM 写回 .class
- **静态路径的定位**：它是 JVMTI/JNI hook 路径（Phase 3 核心）之外的另一条独立路径。两条路径互补：
  - 静态：覆盖所有方法（包括从未被执行到的分支），但对 -O2 优化和编译器差异敏感
  - 动态：精度高、抗优化，但只能恢复执行过的路径，且需要能跑 .dll
- 本方案聚焦**T3（方法体还原）**，建立在 T1/T2（元数据 + 类骨架）已经完成的基础上：换言之，能假设我们已经知道每个函数的入口地址、对应的原 Java 方法名/desc、以及 `cstrings`/`cclasses`/`cmethods`/`cfields` 这四张表的内容。

---

## 2. 为什么静态可行 —— 不变量清单

转译产物有几个**即便经过 -O2 也大概率保留**的结构特征，这些是模式匹配的锚点：

| 不变量 | 解释 | 抗优化程度 |
|---|---|---|
| **`JNIEnv*` 调用通过 vtable 间接调用** | `env->CallIntMethod(...)` 编译为 `call qword ptr [rax+OFFSET]`，OFFSET 是 `JNINativeInterface_` 结构里函数指针的固定偏移 | 极高（vtable 偏移由 JNI ABI 写死，编译器无法消除） |
| **`cmethods[N]` / `cfields[N]` / `cstrings[N]` / `cclasses[N]` 是文件级 static 数组** | 索引 N 编译为 `[base+N*sizeof(ptr)]` 形式的 RIP 相对寻址（PE/ELF 都一样） | 极高（数组地址固定，索引可静态恢复） |
| **`cstack[i]` / `clocal[i]` 是栈上 jvalue 数组** | 在函数入口处一次性 zero-init，编译后是栈帧内固定偏移 | 中等（O2 下部分槽位会被提升到寄存器；但**写入大型联合体的不同字段**`.i/.j/.f/.d/.l` 难以全部消除） |
| **每个槽位是 `jvalue` 联合体（16 字节）** | 访问 `.i`(int) 是 `[off]`、`.j`(long) 是 `[off]`、`.l`(jobject) 是 `[off]`——同槽位不同字段共享起点 | 高（联合体 layout 由 JNI 定义） |
| **try-catch 的 handler 通过 C++ label + `goto` 实现** | 编译后是无条件跳转到固定 basic block | 高 |
| **每个 transpiled 函数有固定 prologue** | `get_class_from_object` → `get_classloader_from_class` → `find_class_wo_static` → 一串 `cclasses` 懒加载 + mutex lock/unlock | 极高（函数符号在 .rdata 字符串里可见，调用关系稳定） |

**关键结论**：恢复每条 JVM 指令时，**不需要识别完整的机器码序列**——只需要识别"这条 asm 触发了 JNI 的哪个 vtable 槽 + 操作数指向 cstack/clocal/c\*tables 的哪个索引"。这两个东西**都不被优化器破坏**。

---

## 3. 方案对比（保留作为决策依据；只实现 B）

### 方案 A：Capstone + 手写指令流匹配 *（不实现）*

最朴素：用 capstone-py / capstone-rs 把函数体反汇编成 Instruction 流，自己写状态机扫一遍。

**流程**
1. 用 LIEF / pefile 拿到 PE/ELF 节区，定位 `__ngen_*` 入口地址（来自 Phase 1 的注册表）
2. 反汇编函数直到 `ret`/`jmp` 到 epilogue
3. 维护一个轻量的"槽位映射"：记录每个寄存器/栈位置当前持有的抽象值（"cstack[3].i"、"cmethods[7]"、"jclass cclasses[5]"……）
4. 遇到 `call [reg + KNOWN_OFFSET]` → 查 JNIEnv vtable 偏移表，识别这是哪个 JNI 调用 → 反查对应 JVM opcode

**优点**
- 实现最快，纯 Python 几百行
- 无外部重型依赖（不需要 Ghidra）
- 适合做 PoC 和处理简单函数

**缺点**
- **对 -O2 优化敏感**：register allocation、instruction reordering、inlining 都会让"按 instruction 顺序匹配模板"失败
- 跨架构（x64 / arm64）和跨编译器（MSVC vs gcc vs clang）的方言差异需要单独写模板集
- 常量折叠会把 `ICONST_3 ICONST_5 IADD` 合并成 `cstack[0].i = 8`，**永久丢失原指令序列**

**不实现的理由**：在 -O2 默认设置下抗优化能力不足，且工程上的"省事"优势在跨架构+跨编译器后被吃掉。

---

### 方案 B：Ghidra Headless + decompiler 输出 AST 匹配 *（采用）*

利用 Ghidra 的 SLEIGH-based decompiler 把机器码还原成接近 C 的伪代码，然后在 C AST 层做模式匹配。

**流程**
1. Ghidra Headless 自动加载 .dll，应用一份预设的 data-type archive：
   - 声明 `JNINativeInterface_` 结构（带所有函数指针的名字+签名）
   - 声明 `jvalue` 联合体
   - 给 `cstrings`、`cclasses`、`cmethods`、`cfields` 这几个全局数组打类型标注
   - 把 Phase 1 已知的 `__ngen_*` 函数命名好，给它们正确的 JNI 签名
2. 跑 decompiler，把每个目标函数的 C 输出 dump 成文本
3. 用 tree-sitter-c（或 pycparser）把伪代码解析成 AST
4. 对 AST 做模式匹配：每条 C 语句 → 对应一条 JVM 指令

**为什么伪代码层更稳**：Ghidra 的 decompiler 已经做了 SSA 化、寄存器→局部变量映射、callsite arg 识别。-O2 下被打散的指令被它合并回 high-level 表达式后**反而比 asm 层更接近源码**。

举例：原 C++
```cpp
cstack0.i = (cstack0.i + cstack1.i);
cstack0.l = env->CallObjectMethod(cstack0.l, cmethods[3]);
```
Ghidra 反编译输出**会非常接近这个**（即便 -O2 把中间过程优化了一通）。AST 上抓 `assignment(member_access(cstackN, "i"), binop("+", ...))` → IADD；抓 `call(member_access(env, "CallObjectMethod"), args)` → INVOKEVIRTUAL with desc from args。

**优点**
- 抗优化能力**显著**强于方案 A
- 跨架构自动支持（Ghidra 内置 x64/arm64/x86/arm32 SLEIGH）
- 类型注解让 Ghidra 主动识别 `cstack[].i` / `cstack[].l` 等不同 union 访问

**缺点**
- 需要 Ghidra 运行环境（JDK 17+），headless 启动一次要几秒
- 单函数 decompile 在大 jar（几百方法）上耗时，需要并行 / 缓存
- AST 匹配规则的实现复杂度高于方案 A 的指令流匹配
- 调试不便（Ghidra 内部不易插桩）

**采用作为唯一路径**。

---

### 方案 C：Capstone + 自写小型符号执行器 *（不实现）*

不依赖 Ghidra，但比方案 A 重：自己写一个迷你抽象解释器，逐指令前向传播抽象值。

**核心思想**：建一个"槽位寄存器"模型——
- 每个 GPR、每个栈位置都映射到一个抽象值（`Symbolic`/`Concrete`/`SlotRef("cstack", 3, ".i")`/`TableRef("cmethods", 7)`……）
- `mov`、`add`、`load`、`store` 等指令更新这个模型
- `call [vtable+OFFSET]` 时，根据当前的抽象参数+被调函数 → emit JVM 指令

**优点**
- 不依赖 Ghidra
- 能处理一些 Ghidra 也搞不定的"奇异"优化（罕见，但理论上更强）
- 实现过程中天然得到 cstack/clocal 的"生命周期"分析

**缺点**
- **实现量大**：要写一个针对性的 x64+arm64 抽象解释器（哪怕只覆盖 ~30 种常见指令模式）
- 还是要给跨编译器的方言差异写 case 分支
- 工程上"花同样力气，方案 B 用 Ghidra 现成能力，得到的更多"

**不实现的理由**：工程量太大，"花同样的力气在 Ghidra type archive 上"投入产出比更高。如果未来 Ghidra 真的吃不下某些 .dll，再回头考虑。

---

## 4. 模板匹配的具体形态（按 JVM 指令分类）

不管选哪个方案，"识别一条 JVM 指令"的本质都是匹配下面这几类**形状**。这里以方案 B（在 Ghidra 反编译伪 C 上做 AST 匹配）的视角举例。

### 4.1 常量加载 / 算术（纯 cstack 操作）

```c
// 伪 C (Ghidra 输出，已应用类型注解)
cstack[0].i = 3;                                  // ICONST_3
cstack[1].i = 5;                                  // ICONST_5
cstack[0].i = cstack[0].i + cstack[1].i;          // IADD
cstack[0].j = (long)cstack[0].i;                  // I2L
```

**AST 规则**
- `assign(cstack[N].i, IntLiteral(v))` → 若 v∈[-1..5] → ICONST_v，否则 BIPUSH/SIPUSH/LDC
- `assign(cstack[N].i, binop(+, cstack[N].i, cstack[N+1].i))` → IADD
- `assign(cstack[N].j, cast(long, cstack[N].i))` → I2L

**风险**：常量折叠。如果原 Java 是 `int x = 3 + 5;`，编译器会把它合并成 `cstack[0].i = 8;`——还原结果会是 `BIPUSH 8`，**不等同但语义无损**。可以接受。

### 4.2 局部变量 ↔ 栈

```c
clocal[2].i = cstack[0].i;          // ISTORE 2
cstack[0].i = clocal[2].i;          // ILOAD 2
```

**AST 规则**：`assign(clocal[V].T, cstack[N].T)` → TSTORE V；反向 → TLOAD V。其中 T ∈ {.i, .j, .f, .d, .l}，决定指令 prefix。

### 4.3 字段访问

```c
// GETFIELD <C.f:I>
cstack[0].i = (*env)->GetIntField(env, cstack[0].l, cfields[7]);

// PUTFIELD <C.f:I>
(*env)->SetIntField(env, cstack[0].l, cfields[7], cstack[1].i);
```

**AST 规则**：识别 `call(member(env, "GetIntField"), args)` → GETFIELD；从 `cfields[7]` 反查 Phase 2 的 fields 表得到 `{owner, name, desc}`。
`GetXxxField` 系列函数有 9 个变体（boolean/byte/char/short/int/long/float/double/object），对应不同 JVM type prefix。

### 4.4 方法调用

```c
// INVOKEVIRTUAL <C.bar:(I)I>
cstack[0].i = (*env)->CallIntMethod(env, cstack[0].l, cmethods[3], cstack[1].i);

// INVOKESTATIC <C.qux:()V>
(*env)->CallStaticVoidMethod(env, cclasses[2], cmethods[5]);

// INVOKESPECIAL: 走 NonvirtualXxxMethod 系
```

**AST 规则**：根据 `CallXxx` 函数名前缀决定 INVOKE 类型；从 `cmethods[N]` 反查 Phase 2 表拿 owner/name/desc。

**注意**：调用参数顺序在 JVM 字节码里是先 receiver 再 args；在 C 里是 `(env, receiver, methodID, arg1, arg2, ...)`。从 args 倒数往 cstack 上一一对应即可。

### 4.5 数组访问

```c
// IALOAD: int[]
{ jint tmp; (*env)->GetIntArrayRegion(env, (jintArray)cstack[0].l, cstack[1].i, 1, &tmp); cstack[0].i = tmp; }

// AASTORE: Object[]
(*env)->SetObjectArrayElement(env, (jobjectArray)cstack[0].l, cstack[1].i, cstack[2].l);
```

**AST 规则**：识别 `GetXxxArrayRegion` / `SetXxxArrayRegion` / `GetObjectArrayElement` / `SetObjectArrayElement` → 对应 xALOAD / xASTORE。NPE 检查（`if (cstack[N].l == nullptr) throw_re(...)`) 会在每条数组访问前出现，模式固定。

### 4.6 跳转

```c
if (cstack[0].i == cstack[1].i) goto L_42;        // IF_ICMPEQ → label "L_42"
```

**AST 规则**：识别 `if (binop(cmp, cstack[N], cstack[M])) goto L` → IF_ICMPxx；label 名→跳转目标偏移（保留 labelPool 用过的命名约定可直接反向 hash）。

### 4.7 类型操作

```c
// CHECKCAST
{ if (cstack[0].l && !(*env)->IsInstanceOf(env, cstack[0].l, cclasses[N])) throw_re(env, "java/lang/ClassCastException", ...); }

// INSTANCEOF
cstack[0].i = cstack[0].l ? (*env)->IsInstanceOf(env, cstack[0].l, cclasses[N]) : 0;
```

### 4.8 异常 / try-catch

转译后每个 try block 体后接 catch handler label。模式：
```c
L_catch_handler:
  cstack[0].l = (*env)->ExceptionOccurred(env);
  (*env)->ExceptionClear(env);
  if ((*env)->IsInstanceOf(env, cstack[0].l, cclasses[N])) goto L_user_handler;
  (*env)->Throw(env, cstack[0].l); return 0;
```

→ 可以重建 `tryCatchBlocks` 表 + ATHROW 指令。

---

## 5. 抗优化策略

| 优化 | 影响 | 应对 |
|---|---|---|
| **寄存器分配**（cstack 槽位被 promote 到 GPR） | 短生命期 cstack 不出现在栈上 | Ghidra 已处理；方案 A/C 需要自己做 mem2reg |
| **常量折叠** | `3+5` 变 `8`，源指令序列丢失 | **接受**：emit 语义等价的字节码（BIPUSH 8） |
| **CSE / 公共子表达式消除** | 多次 `cmethods[3]` 访问被合并为一次 | 不影响指令识别（每次 callsite 仍单独出现） |
| **DCE / 死代码消除** | 完全不会发生（每条 JVM 指令都有 side effect: cstack 写） | 不需要应对 |
| **Inlining** | `throw_re` 等 helper 被内联 | 给这些 helper 在 Ghidra 里手动反内联，或在模板里把内联展开后的形状也加进去 |
| **Loop unrolling / vectorization** | 理论可能但实测概率很低（cstack 写不是连续内存访问） | 暂不考虑 |
| **指令重排** | 不相邻的两条 JVM 指令的 asm 被交错 | Ghidra 的 SSA + reorder 会把它"复原"为顺序伪 C；方案 A/C 需要在 SSA 后再匹配 |

**重要**：native-obfuscator 默认 CMake 模板用的是 `-O2`（GCC）/ `/O2`（MSVC）。如果用户自己换成 `-O0`/`/Od`，还原**会容易得多**。我们的还原器需要兼容两者，但应该把 `-O2` 当默认假设来设计。

---

## 6. 推荐技术栈

| 模块 | 语言 | 库 | 理由 |
|---|---|---|---|
| .jar 解析 / 类骨架 dump | Java/Kotlin | ASM | 与 native-obfuscator 同源，无 impedance mismatch |
| PE/ELF 解析、节区抽取、字符串池 dump | Python | LIEF | API 干净、跨格式统一 |
| **静态反编译** | GhidraScript（Java/Jython 2.7，Ghidra 内置） | Ghidra | 锁定方案 |
| AST 匹配 | Python 3 | tree-sitter-c | 锁定方案 |
| 重建 .class | Java/Kotlin | ASM | 直接 emit InsnList |
| JVMTI/JNI hook（Phase 3） | C/C++ + Java agent | JVMTI native + jvmti-tools | hook 路径必须 C/C++ |
| 编排 / CLI | Python（或 Go） | typer/click | 工程上最低成本 |

---

## 7. 实现规模估算（仅方案 B 主路径）

| 子任务 | 估算 |
|---|---|
| Ghidra data type archive（声明 JNINativeInterface_、jvalue、cstack/clocal/c*tables 等） | 200~400 行 GhidraScript |
| Headless 编排 + 每函数 decompile | 100~200 行 Python |
| tree-sitter-c AST 匹配规则（覆盖 ~150 条 JVM 指令） | 500~1000 行 Python |
| InsnList 重建（ASM emit） | 300~500 行 Java |
| 集成 + 一键 jar 还原 | 200 行胶水代码 |
| **总计** | ~1500~2500 行 |

不算小，但对于"还原级"工具是合理的。

---

## 8. 与项目其他模块的关系

```
┌────────────────────────────────────────────────────────────────┐
│              jar / dll 输入                                     │
└──────────┬─────────────────────────┬───────────────────────────┘
           ▼                         ▼
   ┌──────────────┐         ┌─────────────────┐
   │  Phase 1     │         │  Phase 2        │
   │  jar metadata│         │  string pool +  │
   │  & native    │         │  lookup tables  │
   │  registry    │         │  (per-class)    │
   └──────┬───────┘         └────────┬────────┘
          │                          │
          └──────────┬───────────────┘
                     ▼
        ┌────────────────────────────────┐
        │  Phase 3a  动态 (JVMTI+hook)   │   ← 默认主路径，已规划
        │  Phase 3b  静态 (本文档方案)   │   ← 互补路径，本文档讨论
        └────────────────┬───────────────┘
                         ▼
              ┌──────────────────────┐
              │  Phase 4             │
              │  ASM 写回 .class →   │
              │  可反编译的 .jar     │
              └──────────────────────┘
```

**静态是"对照组"**：动态跑过的方法用 JVMTI 结果；动态未覆盖到的方法、或者交叉验证用静态。两者在 Phase 4 之前 merge。

---

## 9. 通用化（不与 native-obfuscator 强绑定）

本方案的核心**「识别 JNI vtable 调用 + 解析 jvalue 数组访问」**对所有"把 JVM 字节码转译成 JNI C++"的工具都通用。差异在于：

| 工具 | cstack/clocal 形状 | 字符串池 | 方法注册方式 |
|---|---|---|---|
| native-obfuscator | jvalue[] 栈数组 | 单个大 char[] | JNI_OnLoad → RegisterNatives |
| 其它变体 | 可能是 union union/struct mix | 可能加密 / 分段 | 可能用 DefineClass + hidden class |

抽象层设计：
1. **`HostBackend` 接口**：识别函数入口、注册表、字符串池——native-obfuscator 是一个实现，其它变体可以新增实现
2. **`StackModel` 接口**：定义"如何从伪 C 里识别出栈/局部变量槽位"——默认实现匹配 jvalue 数组，其它变体可换
3. **`JniDecoder` 共享层**：JNI 函数表 vtable 偏移 + 函数名 → JVM 指令的映射，这是**强通用**的，所有变体共用

也就是说，AST 匹配规则可以分两层：
- **JNI 层**（通用）：`env->CallIntMethod(env, recv, mid, args...)` → INVOKEVIRTUAL with int return
- **栈模型层**（按 backend 替换）：识别"哪个内存访问是 cstack[3].l"——native-obfuscator 一种实现，其它变体另一种

---

## 10. 决策汇总 & 模块边界

所有问题已定（见 §0）。

**主流程的 AST 匹配规则**：手写，覆盖所有通用 JNI 调用模式 + jvalue 数组访问模式。**不依赖** native-obfuscator 的内部细节。

**`cppsnippets.properties` 模板生成**：作为 **独立可选 feature**，单独的子模块（暂定名 `snippet-importer`）：
- 读 native-obfuscator 仓库内的 `cppsnippets.properties`
- 机械生成一份"补充规则集"，可加载到主匹配器作为附加 hint
- 仅在用户主动启用时介入；不开启时主流程完全不感知它的存在
- 用途：(a) 对**确认是 native-obfuscator 原版**的产物提升匹配精度；(b) 升级 native-obfuscator 时自动跟随

模块依赖方向：`snippet-importer` → 主匹配器（单向依赖）；主匹配器无反向依赖。

### 10.1 无 `cppsnippets.properties` 时的能力保证（硬约束）

> 任何主流程功能都必须在 **完全不存在 `cppsnippets.properties`** 的前提下可用。`snippet-importer` 只能提升精度/覆盖率，**不能成为主流程的功能开关**。

主匹配器需要内置的规则覆盖范围（手写规则集，独立完成）：

| 类别 | 覆盖完整度 | 说明 |
|---|---|---|
| 常量 / 算术 / 位运算 (ICONST_x, IADD, IXOR, ISHL, I2L, INEG …) | **100%** | 纯 cstack 上的算术/位运算，无 JNI 依赖；模式由 jvalue 字段访问唯一确定 |
| 局部变量 ↔ 栈 (xLOAD / xSTORE / DUP / POP / SWAP) | **100%** | 完全靠 jvalue 槽位 move 模式识别，与 snippet 无关 |
| 字段访问 (GETFIELD / PUTFIELD / GETSTATIC / PUTSTATIC) | **100%** | JNI vtable 偏移（`Get*Field` / `Set*Field`）+ cfields 索引，与 snippet 无关 |
| 方法调用 (INVOKEVIRTUAL / STATIC / SPECIAL / INTERFACE) | **100%** | JNI vtable 偏移（`Call*Method` / `CallStatic*` / `CallNonvirtual*` / `CallInterface*`）+ cmethods 索引 |
| 数组访问 (xALOAD / xASTORE / ARRAYLENGTH / NEWARRAY / ANEWARRAY) | **100%** | JNI `Get*ArrayRegion` / `Set*ArrayElement` / `GetArrayLength` / `NewObjectArray` 系列 |
| 类型操作 (CHECKCAST / INSTANCEOF / NEW / ATHROW / MONITORENTER/EXIT) | **100%** | `IsInstanceOf` / `AllocObject` / `NewObject` / `Throw` / `MonitorEnter/Exit` |
| 跳转 (IFxx / IF_ICMPxx / IF_ACMPxx / GOTO / TABLESWITCH / LOOKUPSWITCH) | **100%** | 控制流由 CFG + cstack 比较模式恢复，独立于 snippet |
| try-catch 表 + ATHROW 路径 | **100%** | 固定的 `ExceptionOccurred` + `ExceptionClear` + `IsInstanceOf` + `goto handler` 模式 |
| LDC（字符串 / class / int / long / float / double） | **100%** | 字符串走 cstrings 索引、class 走 cclasses 索引、立即数直接出现在伪 C 中 |
| INVOKEDYNAMIC | **部分** | native-obfuscator 通过 IndyPreprocessor 改写为 bootstrap 调用 + 普通调用，**还原结果是语义等价的非-indy 序列**——这不是缺失，是设计权衡 |
| 函数 prologue / classloader 引导段 | **100%** | 固定模式（`get_class_from_object` → `get_classloader_from_class` → `find_class_wo_static` → cclasses 懒加载），与 snippet 无关 |

**主流程不依赖 snippet 的根本原因**：上述所有模式的"匹配锚点"都是 **JNI ABI 不变量**（vtable 偏移、jvalue layout、JNI 函数签名）或 **C 语言层的语义结构**（赋值、binop、call、goto），而 `cppsnippets.properties` 只是 native-obfuscator 把每条 JVM 指令翻译成 C++ 的**具体文本**——这层文本经过编译器之后早已不可见，可识别的只剩 ABI 和语义结构。所以**没有 snippet 文件，主流程依然完整**。

**snippet-importer 真正补什么**：
- 对**编译器优化激进合并**的情况（例如 `ICONST_3 ICONST_5 IADD` 被常量折叠成 `BIPUSH 8`），snippet-importer 不能恢复——这是物理信息丢失，谁都救不回来
- 对 native-obfuscator **未来新增的特殊指令处理**（比如新加的 IndyPreprocessor 变体），snippet-importer 可以自动跟随升级，主流程不用同步改代码
- 对**长尾的 helper 调用模式**（如 `utils::throw_re`、`utils::create_multidim_array_value`），snippet-importer 提供更精确的模式权重

也就是说：**snippet-importer 影响精度的尾部，不影响主流程的覆盖率**。

下一步交付：**GhidraScript 接口设计 + AST 匹配 DSL 草案**（数据流：函数列表 → headless 输入 → JSON → tree-sitter → InsnList）。
