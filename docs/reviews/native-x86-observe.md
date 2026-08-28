# Native x86 observation engine review

Reviewed:

- PR: https://github.com/gaoyu06/c2j-native-deobfuscator/pull/7
- Branch: `cursor/native-x86-plugin-abi-5384`
- Head at review time: `9755bd2e164554247c7a76b9e5694a11eada6055`
- Base: `main` at `3843ec174510b52e643df2cb2f82a0d4cb57388e`

Scope of this pass: the user-mode observation engine added on top of the
plugin ABI — `src/host/observe_linux.c`, the host CLI in
`src/host/main.c`, the event bus (`src/host/event_bus.c`), and the ABI
header. The earlier ABI-only review lives in
[`native-x86-abi.md`](native-x86-abi.md); this document does not repeat
it.

The engine observes program **structure** only — module bases, symbol
names and addresses, and control-flow edges. It reads no argument bytes,
buffer contents, keys or return values, and there is no kernel component,
no traffic interception, and no payload or key capture anywhere in this
change. The fixes below keep that boundary intact while closing four
defects in the live path.

Verdict at review time: **must-fix** (four items). All four are now
addressed on this branch; evidence is recorded per item.

---

## Must-fix findings and fixes

### 1. Live error paths must restore bytes, detach, and fail loudly

**Finding.** In the live (ptrace) pass, several error exits left the
target in an unsafe or misreported state:

- The `waitpid` immediately after `PTRACE_ATTACH` returned an error
  without detaching, so the attachment could remain in place.
- Every restore and detach call ignored its result (`(void)…`), and the
  function always returned `NX86_OK`. A failed byte-restore or a failed
  detach — leaving an `INT3` in the target or the process still traced —
  was reported as success.
- Error breaks inside the event loop fell through to the same
  unconditional `NX86_OK`.

This violated the rule that a command must never report success while a
breakpoint or the attachment may still be active.

**Fix.**

- Added `remove_breakpoints_and_detach()`, which restores every armed
  entry and return breakpoint and then detaches, and reports whether the
  target is provably clean afterwards. A ptrace op that fails with
  `ESRCH` (the tracee already exited) is treated as clean because nothing
  it held can still be active; any other failure is a leak.
- The main cleanup path now calls that helper and, on a reported leak,
  fails the run with `NX86_ERR_INTERNAL`. The closing note reads "live
  pass did not complete cleanly …" instead of "live pass complete" when
  the run did not end cleanly.
- The post-attach `waitpid` failure now detaches best-effort and returns
  an error.
- Error breaks in the loop set an error status; benign ends (target
  exited, event/time budget reached) stay `NX86_OK`. A ptrace read that
  fails with `ESRCH` is reclassified as "target ended", not an error.
- `main.c` maps any non-`NX86_OK` observation status to a non-zero exit
  code and the closing line "shutdown with errors".

**Evidence.** Smoke-test section 6 injects a detach failure on the live
path; the command exits non-zero, prints "shutdown with errors", and does
not print "shutdown ok". The clean live run (section 3) still returns
`NX86_OK` and "shutdown ok".

### 2. Attach refusal must fall back or fail — not silently succeed

**Finding.** When `PTRACE_ATTACH` was refused, the engine emitted a note
and returned `NX86_ERR_UNSUPPORTED` (-3), but the CLI ignored that status
and still printed "shutdown ok" and exited 0. It also did **not** run the
read-only pass, even though the documentation
([`plugins/crypto-libraries.md`](../plugins/crypto-libraries.md)) states
that a refused attach falls back to the read-only module/symbol pass. So
the tool claimed success while doing nothing.

**Fix.** On a refused attach the engine now runs the documented read-only
fallback: parse `/proc/PID/maps` and read ELF symbol tables from disk, no
ptrace and no breakpoints. It emits an honest note naming the refusal and
the fallback, and returns `NX86_OK` only when that pass actually
produced its records. Independently, `main.c` now fails the command on
any observation error, so the "-3 + exit 0 + shutdown ok" combination can
no longer occur: either the fallback runs and success is real, or the
command exits non-zero.

**Evidence.** Smoke-test section 4 forces the refusal path and asserts:
exit 0, an "attach was refused" note that names the read-only fallback,
module-load and symbol records present, no live `phase=enter` records, and
a clean "shutdown ok". A deterministic, environment-independent test seam
(`NX86_TEST_INJECT=attach-refused`, inert unless the variable is set)
drives it so the case is covered even where ptrace is permitted.

### 3. Read only the registers the return needs; keep `note.text` textual

**Finding (registers).** The live path used `PTRACE_GETREGS`, which copies
the entire general-register file — including the argument registers
(`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`) and the return-value register
(`rax`) — into the host's address space. The documentation states these
registers are never read. Copying them wholesale contradicts that claim,
even though only `rip` and `rsp` were used.

**Fix.** The engine now reads exactly two registers, one word at a time,
with `PTRACE_PEEKUSER`: the instruction pointer (to identify which
breakpoint was hit) and the stack pointer (to locate the return address).
The instruction pointer is rewound with a single `PTRACE_POKEUSER`; no
other register is read or written, and the full register file is never
fetched. This matches the documented "never reads argument registers"
guarantee at the mechanism level rather than by convention. File and
call-site comments were updated to name the two registers explicitly.

**Finding (`note.text`).** A diagnostic note's `text` is a borrowed
string of arbitrary length. Nothing stopped a producer from using it as a
side channel to move a buffer past the metadata-only record model.

**Fix.** `note.text` is documented in the ABI header as host/status text
only, explicitly not a data channel. The host adds a cheap guard on the
plugin-authored event path (`nx86_bus_republish`): a note whose `text`
exceeds `NX86_NOTE_TEXT_MAX` (512 bytes) is rejected with
`NX86_ERR_INVALID_ARG`. Host-authored status notes are well under that
bound, so the check only bites an attempt to smuggle a large payload.

**Evidence.** Live observation still reports correct entry/return call
sites after the register change (smoke-test section 3). The changed files
compile clean under `gcc` and `clang` with `-Wall -Wextra -Wpedantic
-Werror`. The metadata-only assertion in the smoke test (no
content-like field in the output) continues to hold.

### 4. `--pid` must be a strict positive integer

**Finding.** `--pid` was parsed with `strtol(arg, NULL, 10)`, and
attachment was gated on `pid >= 0`. `--pid -1` produced `pid == -1`,
which fell through to the synthetic (no-target) mode as if no `--pid` had
been given; `--pid 0` and trailing garbage like `--pid 12x` were also
accepted.

**Fix.** Added `parse_positive_pid()`, which requires the whole argument
to be a base-10 integer in `[1, INT_MAX]` with no sign, no trailing text,
and no overflow. A separate `pid_set` flag distinguishes "no `--pid`"
(synthetic mode) from "`--pid` given". A malformed `--pid` prints an error
and exits with code 2; it never falls through to synthetic mode.

**Evidence.** Smoke-test section 5 rejects `--pid` values `-1`, `0`,
`12x`, `abc`, and empty (each exits non-zero and never prints "shutdown
ok"), and confirms a well-formed value still parses.

---

## Boundary notes

- No kernel code, no driver, and no kernel image are introduced or
  shipped by this change. The optional
  [`privileged-observer.md`](../privileged-observer.md) boundary document
  is untouched.
- No TLS interception, no traffic capture, and no payload or key capture
  is added. Well-known library exports are still only *named* and
  *observed* at entry/return, never read.
- The test seam (`NX86_TEST_INJECT`) exists solely to exercise the
  refusal and cleanup-failure paths deterministically. It is read from an
  environment variable, is inert unless set, and injects no behaviour into
  production runs.

## Verification summary

- `bash native-x86/smoke-test.sh` — pass (CMake build). Sections 1–3
  (synthetic, ABI checks, live observation) pass; new sections 4–6
  (attach-refusal fallback, strict `--pid`, detach-failure) pass.
- `bash native-x86/smoke-test.sh --no-cmake` — pass (direct build).
- `gcc` and `clang`, `-std=c99 -Wall -Wextra -Wpedantic -Werror` — the
  changed sources compile without diagnostics.
