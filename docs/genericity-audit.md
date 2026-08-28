# Genericity audit — variant- and Ghidra-specific assumptions

**Status: facts only.** This document is an inventory, not a change proposal and
not a work plan. Nothing here is fixed by the commit that adds this file. The
"suggested generic replacement" column records the shape a fix would take so
that later generality work has a starting point; it is not a commitment that
the suggestion is the right design.

## Scope

Every place in `py/`, `native/`, `ghidra/`, `jvm/` and `docs/` where the code
assumes a specific obfuscator variant, a specific compiler/toolchain, a
specific OS or CPU, or a specific decompiler's output shape.

**85 findings** across ten areas.

## How to read the table

- **Location** — path plus line or line range at the commit that introduced
  this document.
- **Assumption** — what the code takes for granted.
- **Breaks for** — the inputs on which the assumption does not hold.
- **Gated by** — whether the assumption is already parameterised. Values:
  - `Profile.<field>` — configurable through
    `py/binary_introspect/binary_introspect/profile.py`.
  - `Abi.<member>` — configurable through the arch modules under
    `py/binary_introspect/binary_introspect/arch/`.
  - `LifterOptions.<flag>` — can be switched off from the `ast-matcher` CLI.
  - `manifest` — driven by data recovered at runtime rather than a constant.
  - **none** — hardcoded; changing it requires editing the module.

A finding gated by a Profile/Abi/flag is still a finding: being switchable is
not the same as being correct by default, and several switchable knobs are
never actually reached by the shipped pipeline (see the cross-cutting section).

---

## 1. RegisterNatives discovery

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| R01 | `py/binary_introspect/binary_introspect/profile.py:47` | `RegisterNatives` sits at JNI vtable index 215 | A JVM whose `JNINativeInterface_` layout differs from the JNI 1.1+ spec ordering | `Profile.register_natives_index` | Derive the index from a JNI header parsed at analysis time rather than a module constant. |
| R02 | `py/binary_introspect/binary_introspect/jni_tables.py:90` | The call site is an indirect call whose displacement is exactly `index * pointer_size` | Compilers that materialise the slot address into a register first (`lea`/`add`, then `call reg`), or that split the load across basic blocks | `Abi.is_indirect_vtable_call` | Match on a small dataflow fact ("callee came from `*env + K`") instead of a single instruction's literal displacement. |
| R03 | `py/binary_introspect/binary_introspect/jni_tables.py:104-158` | Every `fnPtr` of a class's table is materialised within 0x600 bytes before the call site | Large tables, `-O0` builds with more spill traffic, or a table built in a separate helper function | none (`window` default) | Walk the call site's dominating basic blocks until the table base is defined instead of a fixed byte window. |
| R04 | `py/binary_introspect/binary_introspect/jni_tables.py:110-153` | The table is built on the stack: PC-relative LEA of each `fnPtr` followed by a store to a stack slot | Tables emitted as initialised data in `.rdata` (the shape `ExtractRegisterNatives.java` looks for), or built via `memcpy` from a template | none | Support both stack-built and data-resident tables, selected by the profile's harvest strategy. |
| R05 | `py/binary_introspect/binary_introspect/jni_tables.py:139,199` | `ins.operands[0].type == 1` — capstone's numeric id for an x86 register operand, written inline | Any non-x86 `Abi`, since the constant is x86's `X86_OP_REG` even though the surrounding module is documented as arch-agnostic | none (leaks past `Abi`) | Move the operand-kind test behind an `Abi` predicate alongside the other instruction matchers. |
| R06 | `py/binary_introspect/binary_introspect/jni_tables.py:155-157` | The last `nMethods` LEA targets seen are the table's entries | Interleaved construction, or a compiler that hoists unrelated function-address loads into the window | none | Track stores by stack displacement so entries are ordered by table slot rather than by emission order. |
| R07 | `py/binary_introspect/binary_introspect/jni_tables.py:165-219` | In shared-dispatch mode every `mov <nMethods-reg>, imm` starts a new class's table | A shared dispatcher that computes `nMethods` rather than loading a constant, or reuses one constant for several classes | `Profile.harvest_strategy` | Key branch boundaries on the dispatcher's own control flow (the class-name comparison) instead of on the count load. |
| R08 | `py/binary_introspect/binary_introspect/jni_tables.py:264-278` | Exactly two harvest strategies exist: `per_class` and `shared_dispatch` | Any third dispatch shape; `docs/ROADMAP.md:60-67` already records this as a known gap | `Profile.harvest_strategy` | Make the strategy a registered callable so a profile can supply its own harvester without editing this module. |
| R09 | `py/binary_introspect/binary_introspect/jni_tables.py:289-305` | A string is a plausible class name only if it contains `/` | Default-package classes, and any variant that stores class names in dotted form | none | Accept dotted and slash-separated forms and cross-check against jar-parser's class list. |
| R10 | `ghidra/scripts/ExtractRegisterNatives.java:153-230` | `JNINativeMethod[]` tables live in an initialised, readable, non-executable block as runs of three pointers | The stack-built tables that both shipped profiles actually produce — this script finds nothing for them | none | Document the script as the data-resident-table path and fall back to the disassembly harvest otherwise. |
| R11 | `py/manifest_merge/manifest_merge/core.py:57-91` | A call site's `fnAddr` list maps onto the first jar class with the same count of obfuscated natives, in declaration order | Two classes with the same native-method count (first match wins, silently), or a variant that emits the table in a different order | `manifest` (data-driven, but the matching rule is hardcoded) | Bind by the method-name pointers recovered from the table, and report ambiguity instead of taking the first match. |

## 2. ABI / register conventions

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| A01 | `py/binary_introspect/binary_introspect/arch/__init__.py:21` | Only `amd64_windows` and `amd64_sysv` are registered | AArch64, 32-bit x86, RISC-V; `docs/ROADMAP.md:49-58` records this | `Abi` registry (extensible, empty) | Ship an AArch64 `Abi` so the registry has more than one architecture family in it. |
| A02 | `py/binary_introspect/binary_introspect/arch/base.py:62-78` | An indirect vtable call is x86 Intel syntax: mnemonic `call`, operand text `[reg + 0xN]` | AArch64 `ldr`/`blr` pairs, and any capstone syntax mode other than Intel | `Abi.is_indirect_vtable_call` (overridable) | Match on decoded operands rather than on the rendered `op_str` text. |
| A03 | `py/binary_introspect/binary_introspect/arch/base.py:80-97` | "Address of a constant" is a single `lea` with a PC-relative base | AArch64 `adrp`+`add` pairs, and x86 code that computes addresses arithmetically | `Abi.decode_pc_relative_lea` (overridable) | Let the `Abi` return a multi-instruction matcher rather than a single-instruction predicate. |
| A04 | `py/binary_introspect/binary_introspect/arch/base.py:89,107,121` | `capstone.x86_const` is imported inside the base class's default methods | A non-x86 `Abi` that inherits any default method pulls in x86 constants | none | Move the x86 defaults into an x86-specific base and leave `Abi` abstract. |
| A05 | `py/binary_introspect/binary_introspect/arch/base.py:99-118` | A stack store is `mov [rsp/rbp/esp/ebp + d], reg` | Frame pointers in another register, `push`-built tables, or `str` on AArch64 | `Abi.is_stack_store` (overridable) | Define the predicate in terms of "writes to the current frame" and let each `Abi` decide which registers count. |
| A06 | `py/binary_introspect/binary_introspect/arch/base.py:120-135` | `nMethods` arrives as `mov reg, imm` into a known register | A count loaded from memory, computed, or passed on the stack | `Abi.n_methods_arg_regs` | Resolve the fourth argument by dataflow rather than by matching one instruction form. |
| A07 | `py/binary_introspect/binary_introspect/arch/amd64_windows.py:15-24`, `amd64_sysv.py:15-24` | Exactly one integer-argument register set per OS, and the OS is inferred from the container format | An ELF that uses a non-SysV convention, or a PE for a non-Microsoft ABI | `Abi.binary_matches` | Key the ABI on (format, machine, and where available the ABI note) rather than on format alone. |
| A08 | `py/binary_introspect/binary_introspect/cache_table.py:40,75-81` | The whole cache-table extractor is PE + machine `0x8664`; anything else returns an empty table | ELF and Mach-O targets, which silently lose all field/method-name resolution with no warning | none (documented in the module docstring) | Reimplement the register-state tracker against the `Abi` interface, and warn when the table comes back empty. |
| A09 | `py/binary_introspect/binary_introspect/cache_table.py:52-58,579` | JNI helper offsets are byte constants for 8-byte pointers (`GetFieldID` `0x2f0`, `NewWeakGlobalRef` `0x710`, …) | 32-bit targets, and any change to the vtable ordering | none | Compute the offsets from the same index table the lifter uses, scaled by `Abi.pointer_size`. |
| A10 | `py/binary_introspect/binary_introspect/cache_table.py:277-283` | Arguments 2/3/4 are in RDX/R8/R9 — the Microsoft x64 convention | SysV targets, where the same arguments are in RSI/RDX/RCX | none | Read the argument registers from the active `Abi`. |
| A11 | `py/binary_introspect/binary_introspect/jni_tables.py:49-70`, `cache_table.py:101,729` | Executable sections are identified by the PE characteristic `0x20000000`, the ELF flag `0x4`, or a Mach-O segment name containing `TEXT` | Mach-O sections whose segment name is not exposed by LIEF; any format-specific edge case falls through to an empty range list | none | Use LIEF's format-neutral permission accessors where available and fail loudly when no executable range is found. |
| A12 | `native/build.sh:6,14-28` | The compiler is `zig c++` at a Windows-style default path under `~/.native-obfuscator/`, and the target is always `x86_64-*` | Building the agent on a machine without that exact zig install, and any non-x86-64 host | `ZIG` env var (path only, not the target) | Derive the target triple from the host and accept any C++17 compiler. |

## 3. Ghidra pseudo-C rewrite and variable names

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| C01 | `py/ast_matcher/ast_matcher/jni_vtable.py:120-123` | JNI calls appear in the exact text `(**(code **)(*ident + 0xN))(ident, …)` | Hex-Rays, Binary Ninja, and Ghidra runs where the `JNINativeInterface_` type was applied (calls then render as `env->Fn(...)` with a different arg shape) | none | Put the decompiler-output dialect behind a named adapter, with the current regex as the Ghidra adapter. |
| C02 | `py/ast_matcher/ast_matcher/jni_vtable.py:114` | Vtable slots are 8 bytes | 32-bit targets | none | Scale by the analysed binary's pointer size. |
| C03 | `py/ast_matcher/ast_matcher/jni_vtable.py:17-111` | The `_NAMES` list matches the target JVM's `JNINativeInterface_` ordering, including recent tail entries (`GetModule`, `IsVirtualThread`, `GetStringUTFLengthAsLong`) | Nothing today, but the list is a hand-maintained copy that will drift as the JNI spec grows | none | Generate the table from the JDK's `jni.h` at build time. |
| C04 | `py/ast_matcher/ast_matcher/lifter/driver.py:168` | A JNI call is any text matching `recv -> fn (` | Output where the arrow form does not survive, e.g. a fully-typed decompile that inlines the call, or a dialect using `.` | none | Match on the parsed AST node rather than a regex over source text. |
| C05 | `py/ast_matcher/ast_matcher/lifter/driver.py:170,236-256` | Globals are named `DAT_<hex>` and the hex is the absolute address | Ghidra runs where the address was labelled, and other decompilers' naming (`dword_…`, `data_…`) | none | Let the dialect adapter supply the global-reference pattern. |
| C06 | `py/ast_matcher/ast_matcher/lifter/driver.py:258-262` | String-pool loads render as `string_pool + N`, `PTR_<sym> + N`, or `**(longlong **)PTR_<sym> + N` | Any other pointer-naming convention, and pool reads through a local temporary | `LifterOptions.resolve_string_pool_offsets` | Resolve pool offsets from the disassembly-side cache table instead of from decompiler text. |
| C07 | `py/ast_matcher/ast_matcher/lifter/driver.py:647` | Labels are named `L<n>` or `LAB_<n>` | Other decompilers' label naming; unlabelled gotos | none | Accept any statement label and let the jump-resolution pass validate targets. |
| C08 | `py/ast_matcher/ast_matcher/lifter/driver.py:795-796` | Null/zero comparisons render as one of `0`, `NULL`, `(void *)0x0`, `(jobject)0x0`, `'\0'`, `(char *)0x0` | Any cast spelling not in the list, which silently downgrades a zero-compare to a two-operand compare | none | Strip casts structurally and test the resulting constant. |
| C09 | `py/ast_matcher/ast_matcher/lifter/driver.py:829-831` | A trailing `return 0` / `return NULL` is the obfuscator's synthetic pad and can be dropped | A method whose real body ends in `return 0` — the return is deleted and replaced by a synthesised default | `LifterOptions.suppress_synthetic_fallthrough_return` | Only suppress returns that are unreachable in the recovered control-flow graph. |
| C10 | `py/ast_matcher/ast_matcher/lifter/driver.py:855-879` | Lazy cache-init blocks are recognised by a fixed token list that includes Windows SRW lock primitives (`PSRWLOCK`, `AcquireSRWLockExclusive`, `ReleaseSRWLockExclusive`) and the helper name `find_class_wo_static` | Linux/macOS builds using pthread mutexes or `std::call_once`, and any variant that names its helpers differently | `LifterOptions.skip_native_exception_guards` (flag only; the token list is a module constant) | Move the token list onto `Profile` next to `skip_if_patterns`. |
| C11 | `py/ast_matcher/ast_matcher/lifter/driver.py:202-233` | Ghidra names JNI parameters `param_1`, `param_2`, … in declaration order | Decompilers that recover real parameter names, or Ghidra runs where the signature was overridden | none | Bind parameters by position in the parsed function signature rather than by name. |
| C12 | `py/ast_matcher/ast_matcher/lifter/driver.py:335-341` | Variable names may contain `.` because Ghidra renders struct-slot access as one identifier (`local_47._23_8_`) | Not a break so much as a Ghidra-shaped tolerance baked into the identifier regex | none | Handle slot access as a parsed field expression. |
| C13 | `py/ast_matcher/ast_matcher/core.py:49-55,169,660-667` | The `.cpp` lifting path expects native-obfuscator source naming: `cstack<N>.<t>`, `clocal<N>.<t>`, `cmethods[N]`, labels `L<n>`, and symbols `__ngen_native_<name><id>` | Any other transpiler's generated source; j2cc output does not use these names | none | Treat this path as native-obfuscator-only and select it from the profile rather than from the file extension. |
| C14 | `ghidra/scripts/ApplyJ2CDataTypes.java:28-38` | The `jvalue` union uses a 64-bit pointer for its object member | 32-bit targets | none | Choose the pointer type from the program's default pointer size. |
| C15 | `ghidra/scripts/DumpJ2CDecompiledFunctions.java:86-95` | Uninteresting functions are those starting with `Rtl` or `__`, or with a lowercase second character after `_` | This is a Windows/MSVC CRT filter; on Linux it drops nothing useful and on any target it can drop legitimately-named obfuscated bodies | none | Filter by the manifest's `fnAddr` set (as `DumpFromManifest.java` already does) rather than by name prefix. |

## 4. Throw-reason strings

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| T01 | `py/binary_introspect/binary_introspect/profile.py:90-96` | Invoke hints read `Cannot invoke <owner>.<name>(<args>)` | Variants with a different message, and localised or stripped messages | `Profile.invoke_error_re` | Already parameterised; the gap is that no profile ships an alternative, so an unseen format degrades to unresolved invokes. |
| T02 | `py/binary_introspect/binary_introspect/profile.py:98-109` | Field hints read `Cannot read field "X"` / `Cannot assign field "X"`, and the owner is the enclosing class | Cross-class field access, where the owner attribution is wrong rather than merely missing | `Profile.field_error_re` | Recover the owner from the cache table and fall back to the enclosing class only when that fails. |
| T03 | `py/ast_matcher/ast_matcher/lifter/throw_reason.py:68,98` | Hint messages survive in the decompile as double-quoted C string literals | Messages passed by pool offset, which is exactly what the pool-offset resolver at `driver.py:258-262` exists to handle — the two paths do not feed each other | `LifterOptions.use_throw_reason_*` | Resolve pool-offset arguments to their string first, then run the hint parser over the resolved values. |
| T04 | `py/ast_matcher/ast_matcher/lifter/driver.py:118-134,147-161` | Hints are consumed in source order and match JNI call sites one-for-one | A body where some calls have hints and others do not — the queue desynchronises and later calls get the wrong owner/name | `LifterOptions.use_throw_reason_*` | Bind each hint to the nearest following call site by source position instead of by queue order. |
| T05 | `py/binary_introspect/binary_introspect/core.py:181-193` | The string pool is scored by density of native-obfuscator runtime tokens (`classloader == null`, `INVOKEVIRTUAL `, `AASTORE npe`, …) | A variant with different runtime strings, where the pool section may lose to CRT data in `.rdata` | none | Move the token list onto `Profile` alongside the throw-reason regexes. |
| T06 | `py/binary_introspect/binary_introspect/profile.py:245,253,266-280` | Profile detection keys on `Java_*_native_*` export names, the byte string `Cannot invoke `, and (for one profile) at most four `Java_` exports including `initClass` and `bootstrap` | A variant sharing neither marker scores 0 from both detectors and silently falls back to `generic` | `Profile.detector` | Report the detection score and the chosen profile in `binary.json` so a silent fallback is visible. |

## 5. Helper fingerprints

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| H01 | `py/binary_introspect/binary_introspect/profile.py:126-137` | `Profile.helper_fingerprints` describes helper argument shapes so the lifter can type `FUN_xxxx` results | The field is declared and documented (`docs/adding-obfuscator-profile.md:29`) but read by no code in the repository — setting it has no effect | `Profile.helper_fingerprints` (inert) | Either wire it into the lifter's argument resolver or mark it unimplemented until it is. |
| H02 | `py/binary_introspect/binary_introspect/cache_table.py:527-558` | The class-lookup helper is recognised structurally: third argument loaded from a known `cstrings` slot, plus a `NewWeakGlobalRef` wrap before the result store | A variant whose cache init uses `NewGlobalRef`, or holds the name in a different argument slot | none | Express the shape as a profile fingerprint rather than as inline code. |
| H03 | `py/binary_introspect/binary_introspect/cache_table.py:468-507` | `string_pool::get_pool()` exists as a distinct function whose body is `lea rax, [rip + pool]; ret` | Builds where the accessor is inlined (the code tolerates absence, but then the cstrings/cclasses init blocks stop propagating state) | none | Detect the pool base by dataflow from any instruction that materialises it, not from one function shape. |
| H04 | `py/binary_introspect/binary_introspect/cache_table.py:114-122` | There is one `char* string_pool` global per class namespace, and the 24 highest-scoring candidates cover them all | A binary with more than 24 obfuscated classes, where later classes lose their cache-table entries with no warning | none | Iterate all candidates above a score threshold and report how many were considered. |
| H05 | `py/ast_matcher/ast_matcher/lifter/driver.py:855-867` | Helper and lock names appear verbatim in the decompile (`find_class_wo_static`, the SRW lock primitives) | Stripped binaries where Ghidra shows only `FUN_<hex>`, which is the common case for the static path | none | Recognise the helper by its recovered fingerprint rather than by symbol name. |

## 6. Jar-parser detection (including `jnic` annotations)

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| J01 | `jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt:132-144` | The loader's register entry is a static native method whose descriptor is `(Ljava/lang/Class;)V` or `(ILjava/lang/Class;)V` | Loaders keyed by class name (`(Ljava/lang/String;)V`), by integer id alone, or with extra parameters | none | Score loader candidates instead of pattern-matching one descriptor shape. |
| J02 | `jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt:173-184` | A class is obfuscated iff its `<clinit>` invokes something on the loader class | Variants that register from a static initialiser holder class, from the constructor, or lazily on first use | none | Add the loader-call check as one signal among several rather than the sole test. |
| J03 | `jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt:183` | With no loader found, "obfuscated" degrades to "has an empty-bodied ACC_NATIVE method" | Jars with ordinary JNI methods, which are then treated as recovery targets | none | Require corroboration from the binary side before falling back. |
| J04 | `jvm/jar-parser/src/main/kotlin/j2c/jarparser/Main.kt:65` | The native payload lives in the loader class's package directory | j2cc, whose blob is at `j2cc/natives.bin` while the loader is elsewhere — already worked around downstream in `class-rebuilder` rather than fixed here | none | Locate the payload by content sniffing over jar entries. |
| J05 | `docs/ROADMAP.md:69-74`, and the absence of any annotation read in `jar-parser` | Classes obfuscated through the `jnic` `JNICInclude` / `JNICExclude` annotation mechanism are not detected at all — `ClassNode.visibleAnnotations` is never inspected anywhere in the parser | Every `jnic`-obfuscated jar; the parser reports zero obfuscated methods and the pipeline produces an unchanged jar | none | Add an annotation-driven detector as a second recognition pass. |
| J06 | `jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt:260,472-493` | The literal names `registerNativesForClass` and the `special_clinit_` prefix identify obfuscator scaffolding | Any variant using different names; the `special_clinit_` proxy is native-obfuscator-only | `manifest` for the loader class, but these two names are literals | Take both names from the manifest, as the loader class already is. |
| J07 | `jvm/class-rebuilder/src/main/kotlin/j2c/classrebuilder/Main.kt:224-241` | Obfuscator payloads are named `natives.bin` / `natives.dat`, or sit under the loader's top-level package | A variant using another payload name outside the loader's package tree — the blob is copied into the rebuilt jar | none | Strip entries the binary-introspect step actually analysed, recorded by path in the manifest. |

## 7. JVMTI agent assumptions

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| V01 | `native/src/jni_hook.cpp:1047-1050` | The agent can swap `JNIEnv::functions` wholesale on each thread and the JVM will keep using the replacement | JVMs that cache the original table per compiled call site, or reset it; non-HotSpot runtimes generally | none | State the HotSpot dependency, and verify the swap took effect before relying on the trace. |
| V02 | `native/src/jni_hook.cpp:534-536,910-1026` | Wrapping only the `V`/`A` call variants suffices because HotSpot routes variadic calls through them | A JVM that implements the variadic entry points independently, which loses those events silently | none | Wrap the variadic entries as well, or assert at startup that the assumption holds. |
| V03 | `native/src/jni_hook.cpp:910-1026` | The wrapped subset of the function table is enough: no `Float`/`Double` field accessors, no static `Boolean`/`Byte`/`Char`/`Short`/`Long`/`Float`/`Double` calls, no `CallNonvirtual` primitive variants | Bodies using those operations, whose corresponding bytecode is simply absent from the recovered method with no warning | none | Generate the full table from a list and record which entries are unwrapped. |
| V04 | `native/src/agent.cpp:132-138` | Anything under `java/`, `javax/`, `sun/`, `jdk/`, `com/sun/` is JDK noise to be suppressed | Obfuscated applications whose classes are deliberately placed under those package prefixes | none | Decide from the manifest's class list instead of a package prefix list. |
| V05 | `native/src/agent.cpp:79-83` | `ACC_NATIVE` is the literal `0x0100` | Nothing — it is the spec value — but the constant is duplicated rather than taken from `jvm.h` | none | Use the JVM header constant. |
| V06 | `native/src/jni_hook.cpp:60` | 50 000 JNI events per outermost native frame is enough | Long-running frames (game loops, request handlers), which are truncated with a single marker event | `max-frame-events` agent option | Keep as is; the finding is that the default silently caps recovery. |
| V07 | `native/src/agent.cpp:266-278` | `can_access_local_variables` and exception events are available and useful | `docs/ROADMAP.md:89-104` records that the exception events do not fire reliably when the native side catches and clears, so `tryCatchBlocks` is always empty | none | Hook `ExceptionOccurred`/`ExceptionCheck`/`ExceptionClear` in the function table, as the roadmap already proposes. |

## 8. Emulation entry discovery

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| E01 | `py/native_emulate/j2c_emu.py:587-594` | If any `Java_*` export exists, that is the complete method list and discovery stops | Hybrid binaries that export a few methods and register the rest dynamically — the dynamic ones are never found | none | Run all discovery routes and merge, rather than returning at the first that yields results. |
| E02 | `py/native_emulate/j2c_emu.py:572-584` | JNI export-name demangling only needs the `_1` / `_2` / `_3` escapes | Names using the `_0XXXX` unicode escape, and any name where the method/package split is ambiguous — the result is a slash-joined string, not a real `(owner, name)` pair | none | Implement the full JNI mangling rules and return owner and method separately. |
| E03 | `py/native_emulate/j2c_emu.py:596-599,49-50` | `JNI_OnLoad` can be emulated with a mock JavaVM whose `GetEnv` is index 6 and `AttachCurrentThread` index 4 | An `OnLoad` that uses other invocation-interface entries, or performs real work before registering | none | Model the full invocation interface and log unhandled indices. |
| E04 | `py/native_emulate/j2c_emu.py:607-614` | `--binary-json` registrar addresses come from `nativeRegistry[].fnAddrs` | Those are the registered methods' own addresses, not registrar entry points; the flag only works when the two coincide | none | Emit the registrar/call-site address in `binary.json` and read that field. |
| E05 | `py/native_emulate/j2c_emu.py:462-469` | A `JNINativeMethod` record is 24 bytes and at most 64 methods per table are read | 32-bit targets (12-byte records) and tables larger than 64 entries | none | Size the record from the pointer width and drop the fixed cap. |
| E06 | `py/native_emulate/j2c_emu.py:96-101,168` | Only PE and ELF64 are loadable; `Fmt.detect` exits on anything else and the ELF loader asserts 64-bit | Mach-O blobs, and 32-bit ELF | none | Add a Mach-O loader, and report unsupported formats as a normal error path. |
| E07 | `py/native_emulate/j2c_emu.py:302,54-81` | The CPU is x86-64 and the ABI is Win64 or SysV | AArch64 blobs, which Unicorn supports but this harness does not; the module docstring states extension needs a new `ABI`+`Fmt` pair | none (`ABI` classes exist but are not a registry) | Turn `ABI`/`Fmt` into registries selected from the parsed header. |
| E08 | `py/native_emulate/j2c_emu.py:33-47,403-458` | Only the listed JNI indices are modelled; every other index returns a fixed non-null sentinel | Methods calling an unmodelled JNI function, which continue with a bogus handle and produce plausible-looking wrong results | none | Log unmodelled indices, and make the sentinel distinguishable from a real handle. |
| E09 | `py/native_emulate/j2c_emu.py:331-337` | The only C runtime imports worth modelling are `malloc`, `calloc`, `free` | Blobs using `memcpy`, `operator new`, or platform allocators | none | Model imports by name table with an explicit unhandled-import report. |
| E10 | `py/native_emulate/j2c_emu.py:428-433,644-651` | The result is the last-filled buffer, and a single supplied `--static` value can stand in for any static field | Methods returning through another path, or reading more than one static field — both produce a confidently-wrong answer | `--static` CLI flag | Bind statics by field name only, and report when the result had to be guessed. |

## 9. Scripts and steps that require Ghidra

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| S01 | `ghidra/scripts/*.java` (all four) | Ghidra 11.x headless is installed and its script API is available | Any environment without Ghidra; the static path cannot run at all | none | Keep the dependency but isolate it behind a documented dump-JSON contract, so other decompilers can produce the same input. |
| S02 | `py/j2c_dumper_cli/j2c_dumper_cli/main.py:221,274-278` | The one-shot `recover` command never invokes Ghidra: the static path runs only when the user supplies a pre-built `--ghidra-dump` | Users following the one-shot flow, who silently get dynamic-path-only results | `--ghidra-dump` option | Detect a Ghidra install and offer to run the headless step, or state the omission in the command output. |
| S03 | `ghidra/scripts/DumpFromManifest.java:190-252` | `manifest.json` can be parsed by regex, with `name`, `desc`, `isObfuscatedNative`, `fnAddr` in that key order inside one method object, and a class header whose `name` is immediately followed by one of four known keys | Any change to the manifest writer's key order or formatting, which makes the script silently find zero targets | none | Bundle a small JSON parser, or have the Python side emit a flat target list for the script. |
| S04 | `ghidra/scripts/DumpFromManifest.java:105-107` | `fnAddr` values from binary-introspect are valid addresses in Ghidra's default address space | A binary whose Ghidra image base differs from the LIEF-computed base — every lookup lands in the wrong place | none | Carry the image base in the manifest and rebase on load. |
| S05 | `tests/e2e/test_pipeline.sh:11,20,30` | The fixture is at `../e2e-test/out/Hello.jar` outside the repository, `gradlew.bat` is tried before `gradlew`, and the venv is at `.venv/Scripts/python.exe` before the POSIX path | Any checkout without that sibling directory, and non-Windows hosts (which work, but only via the fallback branch); the static path is not exercised at all, which `docs/ROADMAP.md:106-115` already records | none | Commit a fixture, and add a Ghidra-dump JSON fixture so the lifter half is testable without Ghidra. |
| S06 | `.github/workflows/main.yml:7-24` | CI is `windows-latest`, builds only the Kotlin CLIs, and runs on manual dispatch | Everything else: no Python tests, no native agent build, no Linux coverage, nothing on push | none | Add a Linux job that runs the Python test suite and builds the agent. |

## 10. Cross-cutting plumbing

| ID | Location | Assumption | Breaks for | Gated by | Suggested generic replacement |
|---|---|---|---|---|---|
| X01 | `py/binary_introspect/binary_introspect/core.py:380-389` | The per-table `profile` and `abi` names stamped by `jni_tables.find_jni_method_tables` need not be preserved | They are dropped when the tables are flattened into `nativeRegistry`, so nothing downstream can learn which profile was detected | none | Record the detected profile and ABI at the top level of `binary.json`. |
| X02 | `py/ast_matcher/ast_matcher/lifter/driver.py:1031` | The lifter's profile is `generic` unless `--profile` is passed explicitly | The auto-detection performed during `inspect-binary` is discarded (see X01), so the static path silently runs without the variant's throw-reason regex and guard patterns | `--profile` CLI option | Read the profile name from the manifest. |
| X03 | `py/binary_introspect/binary_introspect/cli.py:57-71` and `py/j2c_dumper_cli/j2c_dumper_cli/main.py:82-89` | The orchestrator's `inspect-binary` step calls the legacy `main` entry point, which has no `--profile` parameter | `--profile` is unreachable from the one-shot flow — only the standalone `binary-introspect introspect` subcommand exposes it | none | Route the orchestrator through the subcommand and thread the profile option through. |
| X04 | `py/j2c_dumper_cli/j2c_dumper_cli/main.py:248-249` | When several native libraries are present in the jar, the one matching the host OS is the right one | Analysing a Windows-targeted blob from Linux, which picks the Linux library or falls back to the first entry | none | Let the user select, and default to the library the loader class actually loads. |
| X05 | `py/binary_introspect/binary_introspect/core.py:119-120,167` | The string pool lives in one of a fixed list of section names, and pool entries are printable ASCII only | Custom section names, and any non-ASCII string constant — which is dropped from the pool and therefore unresolvable by the lifter | none | Scan all initialised data sections and decode UTF-8 rather than filtering to ASCII. |
| X06 | `py/binary_introspect/binary_introspect/core.py:300` | Embedded class files have a major version between 45 and 100 | Class files newer than the upper bound as the JDK release train advances | none | Accept any version at or above 45 and validate by structure alone, which the parser already does. |

---

## Top 10 blockers for a new variant

Ordered by how early they stop a previously-unseen target, not by size.

1. **Loader detection accepts only two descriptor shapes** (J01, J02). If a
   variant's register entry is not `(Ljava/lang/Class;)V` or
   `(ILjava/lang/Class;)V`, or if it does not register from `<clinit>`,
   `jar-parser` reports zero obfuscated methods and every later stage has
   nothing to work on. Annotation-driven variants such as `jnic` (J05) fail
   here too, because no annotation is ever read.
2. **The detected profile never reaches the lifter** (X01, X02, X03). Profile
   auto-detection runs during binary introspection, is not written to
   `binary.json`, and the static lifter therefore defaults to `generic` —
   losing the variant's throw-reason regex and guard patterns even when the
   right profile was correctly identified moments earlier.
3. **The cache-table extractor is Windows x64 only** (A08, A09, A10). On ELF or
   Mach-O input it returns an empty table without complaint, so every
   `DAT_<hex>` reference in the decompile stays unresolved and recovered
   field and method accesses degrade to `?.?`.
4. **RegisterNatives harvesting recognises two dispatch shapes** (R07, R08). A
   third shape needs both a new `harvest_strategy` value and a new harvester
   function; the profile alone cannot express it.
5. **Only two ABIs are registered, and x86 assumptions leak past the `Abi`
   interface** (A01–A06). The abstraction exists, but the operand-kind test in
   `jni_tables.py` and the capstone x86 imports in `Abi`'s default methods mean
   a new architecture cannot be added by registering an `Abi` alone.
6. **The Ghidra output dialect is hardcoded across the lifter** (C01, C04–C08,
   C11). The vtable-call rewrite, `DAT_`/`PTR_`/`LAB_`/`param_N` naming, and
   the cast spellings in the zero-comparison list are all Ghidra-x64 literals
   spread across several modules rather than one adapter.
7. **Throw-reason hints only work on inlined string literals, in strict order**
   (T03, T04). A variant that passes messages by pool offset gets no hints at
   all, and a body where only some call sites carry hints desynchronises the
   queue and mislabels the rest.
8. **`helper_fingerprints` is inert** (H01), while the helper recognition that
   does exist is hardcoded to native-obfuscator's shapes and symbol names (H02,
   H03, H05). The documented extension point for teaching the tool about a new
   variant's helpers does nothing.
9. **Emulation stops at the first discovery route and cannot demangle fully**
   (E01, E02, E04). A binary with both static exports and dynamic registration
   yields only the exports, `--binary-json` feeds method addresses where
   registrar addresses are expected, and demangled names are not split into
   owner and method.
10. **The static path is neither automated nor tested** (S01, S02, S05, S06).
    `recover` never invokes Ghidra, the end-to-end script needs a fixture that
    is not in the repository and exercises the dynamic path only, and CI builds
    the Kotlin CLIs on Windows without running any test. A new variant's static
    behaviour therefore has no regression signal at all.

## Related existing notes

`docs/ROADMAP.md` already records four of these areas as known gaps
(architectures at lines 49-58, novel dispatch strategies at 60-67, `jnic`
annotations at 69-74, and the Ghidra test dependency at 106-115).
`docs/adding-obfuscator-profile.md:107-122` lists four hardcoded items in
Chinese; findings A01–A06, C01, C11 and R05 are the line-level form of that
list, and H01 adds one the list does not mention — the `helper_fingerprints`
knob it documents is not read by any code.
