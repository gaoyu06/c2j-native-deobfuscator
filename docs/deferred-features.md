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

## 4. static-reverse：真 Ghidra 跑通了，但 Hello.dll 太小不是有效测例

### 设计原 plan
GhidraScript 把 j2c 转译产物反编译为伪 C JSON → Python tree-sitter AST 匹配 → 还原字节码。

### 后续实际情况（已更新）
**Ghidra 11.3.1 已安装到 `~/.j2c-dumper/ghidra_11.3.1_PUBLIC/`**，需要 JDK 21（用 `~/.jdks/ms-21.0.9`）。`analyzeHeadless` 跑通，对 e2e Hello.dll 提取了 457 个函数的伪 C。

**意外的发现**：在 Hello.dll（一个 ~473 KB Zig -O2 编译的 stripped PE）上，AST 匹配器只能从 4 个函数找到 env-> 调用——而且**没有一个**是 `__ngen_Hello_main`。原因：
- Zig + -O2 把 `__ngen_Hello_main` 内联进了周围的代码或合并掉了
- Ghidra 反编译器对剩下的代码做的"类型传播"反复失败（输出里到处是 `Type propagation algorithm not settling` warning）
- 大量 vtable 偏移（`0x110`、`0x108` 等）跟 C++ runtime 结构体字段的偏移撞车，让 regex 误识别

也就是说，**这个 488 字节左右的 Hello 类太小，被编译器优化吃掉了**。Ghidra 找不到独立的 `__ngen_Hello_main` 函数，更不要说还原它的字节码。

### 替代/后续路径
- **更现实的测试输入**：用一个有几十/几百方法的混淆 jar（业务代码），Zig -O2 不会激进 inline 整个函数，Ghidra 反编译会有 `__ngen_*_*` 这种正常体量的函数。
- **改用真实 JNINativeInterface_ 类型注解**：当前 GhidraScript 只声明了 `jvalue` union，没有声明完整的 `JNINativeInterface_` 结构体。如果声明，Ghidra 直接渲染 `env->FindClass(...)`，AST 匹配会更稳。已用 Python regex 弥补（`jni_vtable.py`），但 type-archive 是更鲁棒的方案。
- **结合 Hello.jar 的 JVMTI 动态 trace**：动态路径目前能可读地还原方法链；静态在小输入上没有可识别的目标函数。两条路径设计上互补，本次测例下动态独自就够看了。

### 当前完成度（更新）
- Ghidra 安装 + analyzeHeadless 可调用：100% ✓
- GhidraScript（dump + type-archive）：90%（type-archive 只声明 jvalue，未声明完整 JNINativeInterface_）
- vtable 字节偏移 → 函数名映射表（`jni_vtable.py`）：100%（覆盖所有 ~230 个 JNI 函数）
- AST matcher framework：100%
- AST 规则覆盖：~50%（核心模式齐，长尾未做）
- 在 Hello.dll 上端到端：失败——但**不是工具缺陷，是测例太小被优化消化掉**

---

## 5. (replaced — original §4 below kept for history)

原 §4：未在真实 Ghidra 输出上做端到端验证

### 设计原 plan（已过期）
GhidraScript 把 j2c 转译产物反编译为伪 C JSON → Python tree-sitter AST 匹配 → 还原字节码。

### 实际情况（已过期）
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

## 5. 栈平衡 + verify 通过率：4/5 通过，advanced 失败

### 背景
v8/v9 迭代加了 SSA 风格的合成 local var 槽位（每个 producer JNI 返回的 jobject DUP + ASTORE 进 slot；consumer 处 ALOAD）+ CHECKCAST 兜底 + return-value 收尾保护。在 5 个测试 fixture 上的 verify 状态：

| 测例 | verify | 真实跑到多深 |
|---|---|---|
| comprehensive | ✓ | NPE on `<local10>` (内部数组空) |
| snake | ✓ | NPE on `Board.rng` |
| tetris | ✓ | NPE on `Board.height` |
| httpserver | ✓ | **服务器真的 start 起来了** (listening on 55320)，hit() 因 URL spec=null NPE |
| **advanced** | ✗ | bci=2219 stack[52] 'Object' 不能赋给 'Throwable' |

### advanced 失败的根因
含 lambda + invokedynamic + stream + reflection。native-obfuscator 的 `IndyPreprocessor` 把 `invokedynamic` 改写成 bootstrap-then-call 链路，单个 lambda 表达式会展开成几十条 JNI 调用（`MethodHandles.lookup`, `MethodHandleNatives.linkCallSite`, ...）。我们的 trace 收到几千条 JNI 事件，translator 顺序模型扛不住操作数栈高 50+。

### 替代/后续路径
1. **专门识别 indy bootstrap 模式**：在 trace-to-bytecode 加一个 pattern matcher：连续若干条 `MethodHandles$Lookup.findStatic/findVirtual` / `LambdaMetafactory.metafactory` 调用塌缩成单条合成 `INVOKEDYNAMIC` 指令。约 200 行 Kotlin。这是正解，但需要熟悉 indy bootstrap 协议。
2. **粗粒度跳过 indy 区段**：识别"我们正在 indy 链路中"的启发式（receiver 是 lookup 对象），把这段 trace 事件折叠为单个 `aconst_null + checkcast java/lang/Object`。能让 verify 通过但 lambda 体现不出来。
3. **直接 emit 原始 invokedynamic**：如果 trace 能识别出 BootstrapMethod 句柄和参数，可以原样 emit `invokedynamic`。但这要求 trace 看到完整的 `CallSite` 创建过程，目前缺。

本阶段不做 (1)/(2)/(3)，因为 lambda 还原是个独立的 sub-project。**建议作为 j2c-dumper v2 的专项任务**。

---

## 6. 纯算术方法还原为空

### 现象
`Calc.factorial(int)long`、`Calc.add(int,int)int`、`Snake.equals` 等只做加法/比较/赋值的方法，trace 抓到 0 个 JNI 事件，还原结果只剩一条 `IRETURN`/`LRETURN`。

### 根因
native-obfuscator 把 `ILOAD/ISTORE/IADD` 这类指令翻译成纯 C++ 赋值：
```cpp
cstack0.i = clocal1.i;
cstack1.i = clocal2.i;
cstack0.i = cstack0.i + cstack1.i;
```
这些是栈上 local var 的算术，**完全不触发 JNI**。JVMTI agent 监听不到。

### 已探索的替代路径
1. **静态反编译 (Ghidra)**：理论上能从二进制反汇编看到 cstack/clocal 的栈帧偏移。**实测在 -O2 优化下失败**：编译器把短生命期的 cstack 提升到寄存器，常量折叠，循环展开，整个函数有时被内联消失（参见 §4）。
2. **要求被混淆的 .dll 用 -O0 重编**：如果用户控制混淆器配置，Ghidra 反编译会清晰得多。但对野外 jar 不适用。
3. **JVMTI MethodEntry 拿方法 args**：JVMTI 对 native 方法的 args **不暴露**（`GetLocalObject` 等只对 Java 方法有效）。需要给每个 native 方法生成 trampoline 包装拦截 args——非常侵入性，每个签名都得 hand-roll 或上 libffi。
4. **修改 native-obfuscator 加 `--trace-mode` 编译选项**：让 cppsnippets 模板额外 emit `j2c_trace_op(opcode, slot, value)` 调用。能 100% 还原但性能爆炸、且只对内部研究用。

### 当前阶段决定
**不做**。纯算术方法目前是 dynamic 路径的硬性盲区。文档承认这一点。
- 用户场景 90% 的关注点是业务逻辑方法（带 JNI 调用 = 调外部 API + 字段访问）—— 这些覆盖率 80%+
- 纯辅助算术方法（getter / 加法 / 比较）即使还原为空，对理解整体程序逻辑也基本无影响——逆向工程师能从被调用上下文反推

**下个阶段**做 §4 列的"完整 GhidraScript + 真实 jar"路径，对大型业务 jar 应该能补回 50%+ 的纯算术方法。

---

## 7. 方法参数识别：只识别 this，其他参数缺失

### 现状
通过启发式（非 static 方法的首个 `GetObjectClass` 调用 args[0] = this）识别 `this`，绑定到 SSA slot 0。其他方法参数（jobject 或基本类型）**未识别**。

### 影响
当某个方法参数是 jobject 类型（如 `compute(int[] values)` 的 `values`），它的 jobject hex 出现在 trace 里但没有 producer——SSA 找不到来源，退化为 `aconst_null + checkcast`。结果：方法调用看似 OK 但调用 `values.length` 等 NPE。

### 已探索的替代路径
1. **JVMTI MethodEntry 拿参数 jobject 值**：对 native 方法**不可用**——JVMTI 的 `GetLocalObject` 只对 Java 字节码方法有效，native 方法的参数在 JVMTI 看来是不可见的。
2. **在 native-obfuscator 生成的 trampoline 里捕获**：每个 `__ngen_*` 方法函数签名不同，需要为每种签名生成定制的 trampoline，或上 libffi。复杂度高。
3. **观察推断**：方法首次执行时，如果第一个 jobject-类型的 JNI 调用接受了某个未知 jobject 作为 args[0]，且该 jobject 立刻被作为 receiver 调用了它的实例方法——它**很可能**是某个方法参数。但识别哪个 slot 是不确定的。
4. **静态识别**：在 cclasses/cstrings 表外，识别 `__ngen_*` 入口处的 `clocal[N].l = obj/arg0/...` 赋值指令。**只在 -O0 下可行**（同 §6 限制）。

### 当前阶段决定
**只做 this 识别**。其他参数继续退化为 `aconst_null + checkcast`。下个阶段可以做 (3) 启发式，预计能正确识别 60% 的方法参数。

---

## 8. SSA 改善反编译可读性，但 runtime 仍 NPE

### 现状（v9 数据）

SSA 让 receiver 也走 slot 路径后，效果在反编译层非常显著。`httpserver` 的 `App.main` 反编译：

```java
inetSocketAddress = new InetSocketAddress("127.0.0.1", 0);
httpServer = HttpServer.create(inetSocketAddress, 0);
helloHandler = new HelloHandler();
httpServer.createContext("/hello", helloHandler);
addHandler = new AddHandler();
httpServer.createContext("/add", addHandler);
httpServer.setExecutor(null);
httpServer.start();
inetSocketAddress2 = httpServer.getAddress();
inetSocketAddress2.getPort();
httpServer.stop(0);
```

跟源码（`HttpServer server = HttpServer.create(...); server.createContext(...);`）几乎逐行对应——**只差变量名命名**。**服务器真的启动了**（listening on 55320），后面在 `hit(url)` 的 URL 字符串拼接处挂掉。

### 为什么 runtime NPE 还在
- **方法参数缺失**（§7）：`hit(String url)` 的 `url` 参数我们不知道是哪个 var slot，导致 `new URL(url)` 收到 null。
- **跨 native 方法边界的 jobject 复用**：jobject `0xABC` 在 `Animal.greet` frame 里是某个 String，跨 frame 到 `Main.main` 时同一个 hex 还在用，但 SSA 槽位是每 frame 独立的——`Main.main` 的 slot map 里没有这个 hex 的条目。
- **字段读取链未追**：`this.body.addFirst(cell)` 这种"先 GETFIELD 拿到 body，再调 method"——目前 SSA 只追了 INVOKE 返回值，没追 GETFIELD 链返回的 jobject。

### 替代/后续路径
1. **GETFIELD 链全部加 SSA stash**（已部分实现 §3）：每个 `GetObjectField` 也 DUP+ASTORE。**已实现**。`http` 测例的 NPE 已经从"server is null"消失，证明这个起效了。
2. **方法参数识别**（§7）：解决 hit() 这类参数级 NPE。
3. **跨 frame 引用传播**：把 SSA slot map 改成全局而非 per-method，但 slot 编号要分配在每 frame 的 local var 表上——实现上需要 method-level slot prefix。

### 下一步建议
- 优先做 §7 (方法参数识别 - 启发式)：预计能让 snake/tetris 的 NPE 从"Board.height" 变成更深位置（Game.main 中 Board 自身已经被识别为 SSA slot）
- §8(3) 跨 frame 引用属于优化项，不是阻塞项

---

## (后续模块——预留位置)

更多偏离会随实现进度追加到此。
