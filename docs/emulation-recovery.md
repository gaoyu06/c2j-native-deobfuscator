# Emulation recovery path — usage guide

> Command reference & verified test matrix live next to the code in
> [`py/native_emulate/README.md`](../py/native_emulate/README.md). This page is
> the **how-to**: when to reach for emulation and the loop you run.

## What it is

A third recovery path that **runs the obfuscated native blob under a CPU
emulator (Unicorn) with a mock JNI environment**, instead of tracing a live JVM
(dynamic path) or pattern-matching a Ghidra decompile (static path).

Because it actually *executes* the C, it sees the things the obfuscator pushed
out of JNI's view:

- inlined comparisons (the password check that never calls `String.equals`),
- the decrypted `<clinit>` string tables (alphabets, secrets, messages),
- arithmetic / control flow that control-flow-flattening + MBA hide from a
  decompiler (the emulator runs the bytes; it doesn't try to structure them).

It needs **neither a runnable target nor Ghidra**, which is exactly the gap
between the other two paths.

## When to reach for it

- The jar won't run in your environment (wrong JDK, anti-debug, missing deps).
- The logic is rewritten to pure C — comparisons, crypto, string transforms —
  so the dynamic trace shows the shape but not the secret.
- Ghidra can't cleanly structure the function (flattening / MBA), so the static
  lifter falls back to stubs.
- You need the decrypted string constants (the `<clinit>` table the other paths
  leave as `Foo.a(0,17)` indices).

## The loop

```
recover   →   strings   →   call (oracle)   →   reverse the algorithm
   │            │               │
 method      decrypted       feed inputs,
 list +      constants       observe outputs
 fnPtrs      (alphabet,
             secret, …)
```

1. **`recover`** — list every native method `(name, sig, fnPtr)`. Entry points
   are auto-discovered (`Java_*` exports → `JNI_OnLoad` emulation → explicit
   `--registrar` / `--binary-json`). Gives you the addresses to target.
2. **`strings`** — emulate a method and dump its decrypted constants. This is
   usually where the secret/alphabet/messages fall out.
3. **`call`** — invoke a method as a pure function. Feed inputs, capture the
   output buffer. Turns "read 10k lines of flattened MBA" into "probe I/O".
4. **Reverse** — with constants + an oracle, work out the algorithm and (if you
   want a clean jar) re-express it in Java.

See the worked example end-to-end (a j2cc CrackMe cracked from `recover` to
password) and the exact commands in
[`py/native_emulate/README.md`](../py/native_emulate/README.md).

## This is a thinking tool, not a button

Emulation gives you constants and an executable oracle; it does **not** auto-emit
clean bytecode. Expect to:

- read the Ghidra decompile of the target `fnPtr` to understand the algorithm,
- supply state the method depends on (`--static field=value` for a static field
  it reads; a warmup run for cached `jmethodID`s) — see the `b` vs `e` note in
  the reference,
- extend the harness for your target: a new arch/ABI (`ABI`+`Fmt` pair), an
  extra JNI function the method uses, or a tweak to the result-capture heuristic.

This is the deliberate trade: it is a **universal approach** for the whole
"Java → C/JNI" family precisely because it rests on the fixed JNI ABI — but a
universal approach always needs per-case adaptation. A capable coding agent does
this adaptation well; running the scripts blind will not.

## Prerequisites

```bash
python -m pip install unicorn        # into the j2c-dumper py venv
```

Get a registrar address for j2cc-style dispatch (not needed for native-
obfuscator `Java_*` / `JNI_OnLoad`):

```bash
python -m j2c_dumper_cli.main inspect-binary natives.bin -o binary.json
python py/native_emulate/j2c_emu.py recover natives.bin --binary-json binary.json
```
