# j2c_emu — emulation-based recovery path

A third recovery path for the **"Java → C/C++ via JNI" obfuscator family**
(native-obfuscator, j2cc, derivatives), complementing j2c-dumper's **dynamic**
(JVMTI) and **static** (Ghidra) paths. It runs the obfuscated native blob under a
CPU emulator (Unicorn) with a mock JNI environment, so it observes the
**C-rewritten logic that JNI tracing cannot see** — comparisons, arithmetic, and
the decrypted string tables.

Why it exists: these obfuscators lift every platform-independent algorithm
(crypto, string ops, comparisons, the `<clinit>` string table) into pure C and
only bounce back to the JVM via JNI to touch managed objects. So dynamic JNI
tracing recovers the *shape* but never the *secrets*; the static path needs
Ghidra + clean control flow. Emulation sidesteps both: it doesn't need a runnable
target (no JDK-version or anti-debug issues) and it actually executes the hidden C
(so control-flow flattening / MBA that defeat a decompiler don't matter).

## Why it generalizes
It rests on the **JVM-fixed JNI ABI**, not on any obfuscator's choices:
- the `JNIEnv`/`JavaVM` function-table layout is the JNI spec (`GetArrayLength`
  is always vtable index 171, `RegisterNatives` 215, `ExceptionCheck` 228, …);
- native methods are reached by `Java_*` export symbols **or** `RegisterNatives`.

So the same engine works across the family; only two things are
platform-specific (and abstracted): the object format and the calling convention.

## Install
```
python -m pip install unicorn
```

## Commands
```bash
# 1) recover every native method (name, sig, fnPtr) — entry points auto-discovered
python j2c_emu.py recover lib.so|natives.dll
#    discovery order: Java_* exports  ->  JNI_OnLoad emulation (mock JavaVM)
#                     ->  --registrar 0x.. / --binary-json (j2cc regc dispatch)

# 2) dump the decrypted string constants of a function (alphabet, secret, msgs)
python j2c_emu.py strings natives.dll --fn 0x10a23e30

# 3) oracle: call a recovered native method as a pure function
python j2c_emu.py call natives.dll --fn 0x10a3fb10 \
       --arg-bytes "AAAABBBBCCCC" --static "v=@alphabet.txt"
#    --arg-bytes  -> a byte[] arg ;  --arg-str -> a String arg
#    --static field=value | field=@file  -> supply a static field (e.g. an
#                                           alphabet with shell-hostile chars)
```

## Verified (end-to-end)
| target | backend | discovery | result |
|---|---|---|---|
| `CrackMe-NJ2C natives.dll` (j2cc) | PE / Win64 | `--registrar` / `--binary-json` | main, e, b recovered; `strings` dumps the alphabet, `Enter Password: `, and the secret `Q89A0-KGQQ^0x|o`; `call e("AAAABBBBCCCC")` → `W0oLW0AMW/AEW|^E` |
| `libt.so` (JNI_OnLoad+RegisterNatives) | ELF / System-V | `JNI_OnLoad` emulation | enc, dec recovered; `call enc("AAAA")` → `BBBB`, `dec("BBBB")` → `AAAA` |
| `libj.so` (`Java_*` export) | ELF / System-V | `Java_*` exports | `com/acme/Crypto/scramble` recovered; `call scramble("hello")` (^0x20) → `HELLO` |

## Scope / limits
- x86-64 only; PE/Win64 and ELF/System-V backends. (Unicorn supports more
  arches; add an `ABI` + `Fmt` pair to extend, e.g. ARM64 / Mach-O.)
- Methods that depend on global state set up elsewhere (cached `jmethodID`s,
  lazily-populated static fields) need that state supplied via `--static`, or a
  warmup run. Self-contained methods that read their tables directly (e.g. the
  crackme's `e`, both test `.so`s) work standalone; ones that call back into JVM
  library methods through cached IDs (e.g. `b`'s `String.indexOf`) need a warmup.
- Hardened targets (anti-emulation timing/CPUID checks, self-modifying code,
  nested bytecode VMs) and non-JNI AOT native code are out of scope for the JNI
  lens; the emulation harness still applies but needs per-case work.
- It recovers constants and gives an executable oracle; turning the algorithm
  back into clean Java is still manual RE — but with the oracle that's
  input→output probing instead of reading flattened MBA.
