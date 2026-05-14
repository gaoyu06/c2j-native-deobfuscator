# 推迟实现的功能 / 设计偏离记录

> 按 `goal` 要求：开发中难以实现或与设计偏离的功能在此记录，并说明替代/后续路径。

## 1. binary-introspect：函数入口表静态恢复

### 设计原 plan
项目结构文档把 binary-introspect 的输出定义为 `nativeRegistry[]`，每条记录包含每个 native 方法的入口 VA、JNI 名/描述符。

### 实际情况
native-obfuscator 生成的 C++ 代码中：
- 每类的 `JNINativeMethod __ngen_methods[]` 数组是**栈上局部变量**，运行时由 `__ngen_register_methods` 函数构造后调用 `env->RegisterNatives`
- 跨类的函数指针表 `reg_methods[]` 是 BSS/DATA 段中的**零初始化数组**，由 `prepare_lib` 在 `JNI_OnLoad` 中运行时填充

因此函数入口与 JNI 名/描述符的映射**不存在于静态文件**中，无法通过 LIEF 简单读 sections 拿到。要静态恢复必须反汇编 `prepare_lib` 和每个 `__ngen_register_methods`，识别 `lea` 指令的目标地址。

### 当前实现的范围（~70% of 设计目标）
binary-introspect v1 实现：
- ✅ 格式 / 架构识别（PE/ELF/MachO × x86_64/aarch64/x86）
- ✅ String pool 完整 dump（按 .rdata 等只读段扫 null-terminated UTF-8）
- ✅ Hidden class 字节抽取（按 CAFEBABE 魔字 + class file 结构解析确定大小）
- ✅ Export table 抽取（PE: `JNI_OnLoad`；ELF/Mach-O: 全部）
- ⚠️ `nativeRegistry[]`：只输出**候选类名**（从 string pool 过滤出合法 Java 内部名），不含 fn 地址
- ❌ `perClassLookups[]` 全部为空（同样需要反汇编 `__ngen_register_methods` 才能填）

### 替代路径
1. **动态路径（Phase 3a）**：JVMTI agent hook `RegisterNatives`，运行时拿到完整的 `{name, desc, fn}` 映射。**这是项目主路径**，所以静态侧的函数表缺失并不阻塞 end-to-end 还原。
2. **静态路径（Phase 3b）**：Ghidra 反编译时本来就要解析这些函数；Ghidra 端会输出一份 `fn_table.json` 喂回 manifest-merge。
3. **若坚持纯 binary-introspect 路径**：需引入 capstone-based 反汇编 pass，约 +300 行 Python，实现 `prepare_lib` 和 `__ngen_register_methods` 的 lea/mov pattern 识别。**当前阶段不做**，原因是与 static-reverse 工作重复。

### manifest-merge 的应对
manifest-merge 在 fn 地址缺失时不会报错。下游 dynamic-trace 会**通过 hook** 在运行时填充地址；static-reverse 通过 Ghidra 自己定位。manifest 的 `fnAddr` 字段允许为 null。

---

## 2. 候选类名误报率高

string pool 里夹杂 C++ 标准库类名（`std::basic_string`、`itanium_demangle::*`）、Windows API 名（`VirtualProtect`、`Sleep`）、寄存器名（`rax`、`rbp`）等，简单的 "合法 Java 标识符 / 分隔" 过滤无法剔除它们。

### 当前处理
binary-introspect 输出的 `nativeRegistry[].classNameCandidate` 是**未过滤**的候选集。下游 manifest-merge 用 jar-parser 输出的真实类名做交集，丢弃所有不在 jar 里的候选。这样 noise 被自然去除。

### 影响
零——下游交集运算解决问题。仅在用户**只有 .dll 没有 .jar** 的场景下噪音会暴露给用户。在那种场景应当走 Ghidra 路径。

---

## 3. trace-to-bytecode：JNI 变参解码缺失导致 jclass 绑定不全

### 设计原 plan
JVMTI agent 抓到的 JNI 调用轨迹，逐条翻译为 JVM 字节码：GETSTATIC/INVOKEVIRTUAL 等。

### 实际情况
native-obfuscator 不直接走 `env->FindClass(name)`——它把所有 jclass 通过 **classloader.loadClass(String)** 拿到：
```cpp
jclass = (jclass) env->CallObjectMethod(classloader, load_class_method, name_jstring);
```
我们的 JNI hook 现在只记录调用的**位置参数**（receiver、methodID），**不解码 C 语言层的 vararg `...`**——也就是 `name_jstring` 这个串没出现在 trace 里。结果是 trace 里所有 jclass 都"没有源"，无法绑定到具体 Java 类名。

### 后果
对 e2e Hello 案例：
- `Get*FieldID(<unknown jclass>, "out", "Ljava/io/PrintStream;")` 翻译时不知道 owner，跳过
- `CallObjectMethod(<unknown obj>, <unknown methodID>)` 同上
- 最终 `Hello.main` 的 recovered 只有 `RETURN`

trace-to-bytecode 当前**结构正确，覆盖率受限于上游 hook 的精度**。已识别的模式包括：
- `GetStaticFieldID` + `GetStaticObjectField(class, fid)` → GETSTATIC（**需要 class 已经在符号表里**）
- `GetMethodID` + `Call*Method(recv, mid)` → INVOKEVIRTUAL/INVOKESTATIC（同上）
- `NewObject(class, ctor)` → NEW + DUP + INVOKESPECIAL
- `GetObjectField` + `GetIntField` 等 → GETFIELD
- `Throw`/`ThrowNew` → ATHROW

### 替代/后续路径
1. **JNI vararg 解码**（首选）：在 agent 端扩展 `Call*MethodV` 包装器，用已知 jmethodID 的描述符解析 va_list。需要在 hook 端维护 mid → desc 的索引（由我们的 `GetMethodID` 包装器构建）。约 100 行 C++ 增量。
2. **手动符号注入**：CLI 提供 `--hint` 文件把已知 jobject → 含义映射喂给 translator。低成本但靠用户。
3. **静态路径补全**（最长远）：Phase 3b 的 Ghidra 静态反编译看 cclasses[] 表初始化代码，能直接把 jclass 索引映射到 class 名字。dynamic + static 合并后**完全恢复**。

### 当前完成度
- 模块架构：100%
- 模式识别覆盖：~50%（缺 vararg-依赖的部分）
- 简单情况（GETSTATIC、GETFIELD、INVOKE 当 jclass 已知）：100%

trace-to-bytecode 在 manifest 中**预填类引用**（jar-parser 已经知道哪些类被引用了）的场景下覆盖率会高很多。完整解决方案要走路径 1（agent vararg 解码），列为下个迭代任务。

---

## 4. static-reverse：未在真实 Ghidra 输出上做端到端验证

### 设计原 plan
GhidraScript 把 j2c 转译产物反编译为伪 C JSON → Python tree-sitter AST 匹配 → 还原字节码。

### 实际情况
本机环境**未安装 Ghidra**。GhidraScript（`ghidra/scripts/`）已按文档接口写好，但只能在用户的 Ghidra 环境里跑。AST 匹配器（`py/ast_matcher/`）用**手工构造的伪 C** 验证通过 4 个核心模式：
- 常量赋值 / 算术（IADD/ISUB/.../IXOR）→ 100%
- 局部变量 ↔ 栈（xLOAD/xSTORE）→ 100%
- GETFIELD/GETSTATIC（`env->GetXxxField(...)` + cfields/cstrings 表查找）→ 100%
- INVOKEVIRTUAL/INVOKESTATIC（`env->Call*Method(...)` + cmethods 表查找）→ 100%

未覆盖的模式（结构上可添加，但本阶段未做）：
- NEW + DUP + INVOKESPECIAL（new + 构造调用）
- NEWARRAY / ANEWARRAY / MULTIANEWARRAY / ARRAYLENGTH
- xALOAD / xASTORE（数组元素访问）
- CHECKCAST / INSTANCEOF
- TABLESWITCH / LOOKUPSWITCH
- try-catch label → tryCatchBlocks 表
- INVOKEDYNAMIC（按 design 同样语义等价，不强求 indy 还原）

### 替代/后续路径
- **真实 Ghidra 验证**：用户在装好 Ghidra 后跑 `analyzeHeadless` + 我们的 GhidraScript，把生成的 JSON 喂给 ast-matcher 即可。文档列了完整调用方式。
- **方法描述符回填**：当前 AST matcher 从 `__ngen_<class>_<method>` 符号 split 出 owner/name，但 desc 取不到。需要 ast-matcher 在 dump 阶段也读 manifest.json，按 fnAddr 反查 method desc。约 30 行 Python 增量。
- **补全 AST 模式**：剩 ~10 类模式按现有 framework 增加 ~150 行规则即可。

### 当前完成度
- GhidraScript（dump + type-archive）：80%（未真机验证）
- AST matcher framework：100%
- AST 规则覆盖：~50%（核心模式齐，长尾未做）
- 端到端（Ghidra→AST→recovered）：架构联通，缺真实 Ghidra 输出验证

---

## (后续模块——预留位置)

更多偏离会随实现进度追加到此。
