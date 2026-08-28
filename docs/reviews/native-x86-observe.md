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

---

## Re-review of `594d21f` — remaining must-fix items

An independent re-review of head `594d21f` confirmed the four findings
above are closed and did not regress (attach refusal runs the read-only
`/proc/PID/maps` + on-disk ELF fallback and reports it honestly; no
`GETREGS`, only RIP/RSP via `PEEKUSER`/`POKEUSER`; the 512-byte
plugin-note cap is present; strict `--pid` rejects `-1`, `0`, `12x`,
`abc`, and empty with exit 2; plugins stay name/address-only with no real
cryptography in the fixture and no Java/JNI types in the ABI). It then
found four further leftovers, all fixed on this branch.

### R1. Live cleanup was still incomplete on some error exits

**Finding.** In `run_live()`:

- A non-`ESRCH` `PTRACE_CONT` failure set `target_alive = 0`, which
  *skipped* the restore+detach cleanup even though breakpoints had already
  been inserted — leaving an `INT3` in the target while the run still
  reported success.
- The RIP rewind (`PTRACE_POKEUSER`) before each step was discarded with
  `(void)`. A failed rewind leaves execution one byte past the `INT3`.
- `bp_step_over()` / `bp_step_off()` returning `-1` (a failed restore,
  single-step, or re-arm) was ignored; only the "target exited" return
  (`1`) was handled. A breakpoint byte could be left in place, or the
  attachment altered, with the run still reported as clean.

**Fix.** Every one of those failures now stops the loop and falls through
to `remove_breakpoints_and_detach()` with `run_status` set to
`NX86_ERR_INTERNAL`, so the closing note reads "live pass did not complete
cleanly …" and `main.c` exits non-zero ("shutdown with errors"). A ptrace
op that fails with `ESRCH` (the tracee is gone) is still treated as clean.
For the return path, a failed step leaves the one-shot return breakpoint
marked active so the cleanup helper restores it rather than skipping it.

**Evidence.** Smoke-test section 8 injects a step-over failure on the live
path; the run emits one `phase=enter`, then the "did not complete cleanly"
note, `observation ended with status -6`, and `shutdown with errors`, and
never prints `shutdown ok`. The clean live run (section 3) still returns
`NX86_OK` and `shutdown ok`.

### R2. Module-scan failure was ignored in the live pass

**Finding.** `run_live()` called `scan_all_modules()` with `(void)`, so a
failure to read `/proc/PID/maps` (or an allocation failure) while attached
was ignored and the pass continued as if it had succeeded.

**Fix.** A scan failure in the live pass now emits an error note, detaches
cleanly through the helper, and returns `NX86_ERR_INTERNAL`. The
read-only fallback (`--no-live` and the attach-refusal path) already
checked the same return value and surfaces `NX86_ERR_UNSUPPORTED` on
failure, so no code path silently ignores a scan failure.

### R3. Safety bounds must parse strictly, like `--pid`

**Finding.** `--max-events` and `--max-seconds` went through
`strtoul(arg, NULL, 10)` with no validation: `--max-seconds abc` yielded
`0` and *disabled* the timeout, and `--max-events -1` wrapped to a huge
value read as effectively unlimited. Garbage silently became "unlimited".

**Fix.** Added `parse_nonneg_u32()`, which requires the whole argument to
be base-10 digits with no leading sign, no trailing text, and no overflow
of `uint32_t`. A malformed value prints an error and exits `2`; an
explicit `0` keeps its documented meaning (no event / no time budget).

**Evidence.** Smoke-test section 7 rejects `abc`, `-1`, `5x`, and empty
for both options (each exits non-zero and never prints `shutdown ok`), and
confirms valid values (including `0`) still parse and run to a clean
shutdown.

### R4. Docs overstated the content guarantee and used non-neutral wording

**Finding.** The docs claimed content capture is impossible "by
construction of the plugin ABI" while `note.text` exists as a 512-byte
free-text field — a host/status channel that *could* hold ~512 bytes.
`docs/native-x86-module.md` also used the non-neutral phrase "attack that
residue".

**Fix.** `docs/native-x86-module.md`, `docs/plugin-abi.md`, and
`docs/plugins/crypto-libraries.md` now state the actual rule: no event
field is defined to carry a payload; the one free-text field, a note's
`text`, is host/status text only; plugins and the host must not place
keys, buffers, or payloads in it; and the host enforces a fixed
`NX86_NOTE_TEXT_MAX` (512-byte) length cap — policy plus a bound, not a
structural impossibility. The "attack" wording is replaced with neutral
phrasing ("make sense of that residue"). `docs/privileged-observer.md` is
left untouched.

### Re-review boundary notes

- Still metadata-only: module/symbol/call-site names and addresses only.
  No keys, buffers, payloads, interception, or kernel/driver source was
  added, and the public ABI grew no Java/JNI types.
- The `NX86_TEST_INJECT` seam now matches fault names by exact token
  rather than substring and gains a `step-over-fail` fault for R1's test.
  It remains read from an environment variable, inert unless set, and
  injects nothing into production runs.

### Re-review verification

- `bash native-x86/smoke-test.sh` — pass (exit 0), CMake build. Sections
  1–8 all pass: 1 synthetic, 2 ABI checks, 3 live observation
  (`PASS(live)`), 4 attach-refusal fallback, 5 strict `--pid`, 6
  detach-failure, 7 malformed safety bounds, 8 live step failure.
- `bash native-x86/smoke-test.sh --no-cmake` — pass (exit 0), direct
  build; same sections 1–8.
- `gcc` (13.3.0) and `clang` (18.1.3), `-std=c99 -Wall -Wextra -Wpedantic
  -Werror` — the changed `observe_linux.c` and `main.c`, and a full host
  link, compile without diagnostics.

---

## Re-review of `9a7b0bd` — remaining must-fix items

A second independent re-review of head `9a7b0bd` confirmed the eight items
above stayed closed and did not regress (attach-refusal still falls back to
the read-only `/proc/PID/maps` + on-disk ELF pass and reports it honestly;
no `GETREGS`, only RIP/RSP via `PEEKUSER`/`POKEUSER`; the 512-byte
plugin-note cap is present; strict `--pid` and `--max-events` /
`--max-seconds` parsing; module-scan failure surfaced in the live pass;
step-over failure fails the run; the `NX86_TEST_INJECT` seam matches by
exact token and is inert unless set). It then found four further leftovers,
all fixed on this branch.

### S1. In-loop `PTRACE_CONT` failures were discarded

**Finding.** Four `PTRACE_CONT` calls inside `run_live()`'s event loop —
the signal-forward resume, the resume after an entry breakpoint, the resume
after a return breakpoint, and the resume for a trap the engine did not set
— were all issued as `(void)ptrace(PTRACE_CONT, …)`. A resume that fails
for anything other than `ESRCH` can leave the target stopped with a
breakpoint byte still in place, yet the run continued and could still report
a clean success.

**Fix.** All four now go through a single `cont_or_fail()` helper. A
non-`ESRCH` failure returns `-1`; the caller sets `run_status =
NX86_ERR_INTERNAL` and breaks out of the loop, so control falls through to
`remove_breakpoints_and_detach()` (restoring every placed breakpoint and
detaching) and the closing note reads "live pass did not complete cleanly
…". An `ESRCH` failure — the tracee is already gone — clears the alive flag
and ends the loop cleanly, since nothing it held can still be active. The
initial pre-loop `PTRACE_CONT` already checked its result and is unchanged.

**Evidence.** Smoke-test section 9 injects a resume failure
(`NX86_TEST_INJECT=cont-fail`, exact-token, inert unless set) on the live
path: the run emits one `phase=enter`, then the "did not complete cleanly"
note, `observation ended with status -6`, and `shutdown with errors`, and
never prints `shutdown ok`. The clean live run (section 3) still returns
`NX86_OK` and `shutdown ok`.

### S2. Breakpoint-arming (`bp_insert`) failures were ignored

**Finding.** The entry-arming loop inserted one `INT3` per resolved watched
export but ignored `bp_insert()`'s result: only successful inserts set
`armed`. If every insert failed the loop still fell through and the run
could later report a clean live success with nothing actually armed; if
some failed, the pass proceeded partially armed with the failures unrecorded.

**Fix.** The loop now counts failures. Any non-`ESRCH` insert failure makes
the run restore whatever did arm, detach through
`remove_breakpoints_and_detach()`, emit an honest "could not arm one or more
watched-export breakpoints …" note, and return `NX86_ERR_INTERNAL` rather
than continue. This covers both "some watches failed to arm" and "every
watch failed to arm". An `ESRCH` mid-arming (the tracee exited) ends the
pass cleanly because nothing it held is active. The pre-existing
"no watched export resolved" case (`n_bps == 0`) is still a clean read-only
outcome and is checked before the arming loop.

**Evidence.** Smoke-test section 10 injects an arming failure
(`NX86_TEST_INJECT=insert-fail`, exact-token, inert unless set): the run
resolves symbols, then prints the "could not arm" note, `observation ended
with status -6`, and `shutdown with errors`, with no `phase=enter` and no
`shutdown ok`.

### S3. Multithreaded targets must refuse the live pass

**Finding.** The live pass places process-wide `INT3` breakpoints and steps
over them, which is only safe in a single-threaded target: a second thread
could execute a patched entry while the engine has restored the byte to
single-step another. The engine placed breakpoints without checking the
thread count.

**Fix (preview policy, not a thread-group tracer).** Before it attaches or
places any breakpoint, `run_live()` counts the entries in `/proc/PID/task`
via `count_task_threads()`. A target with more than one thread is refused
the live pass entirely — no `PTRACE_ATTACH`, no breakpoints — and runs the
documented read-only module/symbol fallback with an honest note that live
observation is single-thread only. A single-threaded target is unaffected
and still gets the full live entry/return pass. No `PTRACE_O_TRACECLONE`,
no attaching every thread, and no new debugger feature was added.

**Evidence.** A second fixture, `tests/fixtures/fixture_target_mt.c`, spawns
an idle worker thread and only then publishes its pid, so `/proc/PID/task`
reliably shows two threads. Smoke-test section 11 runs the host against it
and asserts: exit 0, the "more than one thread … single-thread only" note,
module-load and symbol records from the read-only pass, no `phase=enter`,
no content-like field, and a clean `shutdown ok`. Because the refusal
happens before any attach, this section is environment-independent (it does
not need ptrace to be permitted). The single-thread fixture still reports
`PASS(live)` in section 3.

### S4. Docs overstated the note cap as a side-channel defence

**Finding.** `docs/native-x86-module.md` still said the 512-byte
`NX86_NOTE_TEXT_MAX` cap meant `note.text` "cannot be used as a side
channel." That is false: the cap bounds only the length, not the content,
and a determined plugin can put arbitrary text in 512 bytes.

**Fix.** That passage now states the actual rule: the cap only bounds the
field's *length*; what keeps `text` from becoming a data channel is policy
(host/status text only; no keys, buffers or payloads; the host never parses
`note.text` as data and rejects over-long notes); and a determined plugin
can still place up to 512 bytes of arbitrary text — the cap limits *how
much*, not *what*. `docs/plugin-abi.md` and `docs/plugins/crypto-libraries.md`
already framed the cap honestly ("policy plus a bound, not a structural
impossibility") and were left as-is. `docs/privileged-observer.md` is
untouched.

### Second re-review boundary notes

- Still metadata-only: module/symbol/call-site names and addresses only.
  No keys, buffers, payloads, interception, or kernel/driver source was
  added, and the public ABI grew no Java/JNI types.
- The single-thread policy is a refusal-and-fallback gate, not a new
  tracing capability. Multithreaded targets get strictly less (read-only),
  never more.
- The `NX86_TEST_INJECT` seam gains `cont-fail` and `insert-fail`, matched
  by exact token and inert unless the environment variable is set; they
  inject nothing into production runs. The multithread refusal is exercised
  by a real two-thread fixture, not an inject.

### Second re-review verification

- `bash native-x86/smoke-test.sh` — pass (exit 0), CMake build. Sections
  1–11 all pass: 1 synthetic, 2 ABI checks, 3 live observation
  (`PASS(live)`), 4 attach-refusal fallback, 5 strict `--pid`, 6
  detach-failure, 7 malformed safety bounds, 8 live step failure, 9 live
  `PTRACE_CONT` failure, 10 breakpoint-arming failure, 11 multithreaded
  refusal + read-only fallback.
- `bash native-x86/smoke-test.sh --no-cmake` — pass (exit 0), direct build;
  same sections 1–11.
- `gcc` (13.3.0) and `clang` (18.1.3), `-std=c99 -Wall -Wextra -Wpedantic
  -Werror` — the changed `observe_linux.c`, the new
  `tests/fixtures/fixture_target_mt.c`, and a full host link compile
  without diagnostics.
