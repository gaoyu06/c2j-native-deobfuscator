# Independent review — PR #4 "generic-first method discovery without Ghidra"

- PR: https://github.com/gaoyu06/c2j-native-deobfuscator/pull/4
- Branch reviewed: `cursor/generic-first-discovery-ca12` @ `4a4cda7` (base `main` @ `3843ec1`)
- Scope of review: independent correctness and generality audit. No feature work.
  Two small review-fix commits were pushed to the branch (help-text mismatch and
  two regression tests); see "Review-fix commits" below.

## Ship verdict

**No — not as the default release**, but the design is sound and it is a
reasonable draft to land on a development branch. The generic path genuinely
discovers method tables from JNI-specification structure, and Ghidra is
successfully demoted to optional. The blockers are about *proving* the behavior
and one default-behavior/doc gap on the optional Ghidra lifter, not about the
core approach.

## Was Ghidra demoted to optional?

Yes, and this is the strongest part of the PR. Verified end-to-end:

- `inspect-binary`, `static-lite`, `merge-manifest`, and `synth-stubs` produce a
  method list, manifest, and restoration stubs with no decompiler. Confirmed by
  running the real `introspect()` against a freshly built SysV `.so` (see
  "Tests I ran").
- Help text, stub notes (`stub_recovery.py`), the `static-reverse` command, and
  `ast_matcher/cli.py` all now describe Ghidra as an optional method-body plugin.
- README (both languages) and `docs/generic-recovery.md` frame Ghidra as
  optional. The only remaining "requires Ghidra" string is in `docs/ROADMAP.md`
  and it accurately describes a CI limitation of the static-path e2e tests, not
  a tool requirement.

## Checklist findings

1. **Structural discovery (not a single text pattern): YES.** `RegisterNatives`
   is found at JNI vtable index 215 (`JNI_REGISTER_NATIVES_INDEX`) by inspecting
   Capstone *operands* (`Abi.is_indirect_vtable_call`, `vtable_slot_load`,
   `indirect_branch_register`), not by regex over rendered text. The old
   `re.search(r"\[\w+\s*\+ ...\]", ins.op_str)` was replaced. Harvest uses the
   ABI argument registers (`methods_arg_regs`, `n_methods_arg_regs`),
   executable-range LEAs for fnPtrs, static `JNINativeMethod[]` name/descriptor
   validation, and `Java_*` exports as a second spec-defined mechanism.

2. **Both ABIs / ELF empty result:**
   - SysV amd64 proven end-to-end on a real ELF (split load + tail `jmp`,
     `.data.rel.ro` static table, relocation-resolved fnPtrs).
   - Windows amd64 harvest proven by the parametrized unit test (correct
     `r8`/`r9d`/`call [rax+0x6b8]` encodings). The PE section/export *loading*
     path is not exercised by any test (no PE toolchain here), but it is
     structurally analogous to the ELF path, which I confirmed loads correctly
     with the installed `lief`.
   - **Silent-empty risk on ELF:** `_exec_ranges` and `_mapped_ranges` read only
     `b.sections`. A section-header-stripped `.so` (only PT_LOAD segments) yields
     empty ranges and a silent `[]` with no diagnostic. There is no segment
     fallback. Unsupported arches (aarch64/arm ELF) also return `[]` silently via
     `detect_abi() is None`. See Should-fix.

3. **Variant heuristics conservative under generic: YES.** All gated and off for
   `generic`: throw-reason parsers return `[]` when the regex is `None`
   (`throw_reason.py`); exception/cache guard cleanup and Ghidra vtable rewriting
   are gated on `profile.enable_exception_guard_heuristics` /
   `profile.rewrite_ghidra_vtable_calls` (`driver.py`); cache-table extraction is
   gated on `profile.extract_cache_table` (`core.py`); `skip_if_patterns=[]`.

4. **Schema / CLI back-compat: YES (with a caveat).** Old and new `binary.json`
   both validate against `schemas/binary.schema.json` (checked with
   `jsonschema`). `schemaVersion` stays `1`. `analysis` is additive. Caveat: the
   schema loosened `nativeRegistry` items to have *no* required fields and no
   `oneOf` per record shape, so it now accepts almost anything — fine for
   back-compat, weak as validation. Help text no longer implies Ghidra is
   required for `inspect-binary`/`recover`.

5. **Tests — behavior vs wiring, and gaps:** The behavior tests are real (static
   table decode for both ABIs, operand-based call detection, split tail call,
   `Java_*` export binding, named-table binding). Config/wiring tests cover
   profile fallback and specific-profile-wins. Gaps (before my commits):
   - No test exercised the `lief` *loading* path — nothing called `introspect()`
     or `find_jni_method_tables(b, ...)` with a real binary, so section/export
     reading, ABI auto-detect, and relocation resolution were unproven by CI.
   - No `_harvest_dispatch` (shared_dispatch) test; no malformed-table negative
     test; no Mach-O; no false-binding/ambiguity test.
   - The PR body claims "an optimized ELF fixture: two tables aligned," but **no
     binary fixture is committed**, so that claim is not reproducible from the
     repo.
   I added synthetic tests for the shared_dispatch split and malformed-table
   conservatism (both matched observed behavior). An end-to-end real-binary
   fixture is still missing (see Should-fix).

6. **Regressions vs `native_obfuscator` / `j2cc`:**
   - *Discovery* does not regress: `per_class` -> `_harvest_call`,
     `shared_dispatch` -> `_harvest_dispatch`; profile regexes/skip patterns/flags
     are preserved; auto-detect still selects the variant for matching binaries.
   - *Optional Ghidra lifter default changed:* `lift_ghidra_dump()` defaults to
     `generic` and **cannot auto-detect** the variant from a pseudo-C dump. On
     `main`, the default applied vtable-rewrite and exception-guard skipping
     unconditionally; under the new conservative `generic` they are off. So the
     README's own static-path example (which omits `--profile`) now yields
     rawer, less-lifted output than before. Users must pass
     `--profile native_obfuscator` / `j2cc`. See Must-fix / Should-fix.

7. **Over-claims:** README and `docs/generic-recovery.md` are careful and match
   the code. Two mismatches: (a) `ast_matcher` `--profile` help said "auto-detect
   when omitted" while the lifter hardcodes `generic` — fixed in this branch;
   (b) the PR description's committed-ELF-fixture claim is not backed by the repo.

8. **Safety: OK.** Emulation is in-process Unicorn CPU emulation; the dynamic
   path is the pre-existing JVMTI agent; `_run_native_emulate` shells out with a
   list-form `subprocess.run` (no shell string). No new process injection, no
   privileged/kernel code.

## Must-fix before merge

1. **Prove the loading path with a committed end-to-end test.** The whole
   "generic-first" claim rests on `lief` section/export reading + ABI detect +
   relocation resolution, none of which the committed tests touch. Add a small
   checked-in fixture (a tiny PIC `.so`, and ideally a PE `.dll`) plus a test that
   runs `introspect()` and asserts the recovered `(name, desc, fnAddr)` table. I
   verified this works locally against a freshly built SysV `.so`, but CI does
   not prove it.
2. **Resolve the Ghidra-lifter default regression.** Either make the documented
   static-path example pass an explicit `--profile`, or have the lifter derive
   the profile (e.g., from `binary.json`/manifest `analysis.profile`) instead of
   silently defaulting to conservative `generic`. As written, following the
   README verbatim produces weaker lifting than `main` for a `native_obfuscator`
   target.

## Should-fix

- **ELF segment fallback.** Fall back to PT_LOAD segments when section headers
  are absent, or at least emit a diagnostic instead of a silent empty registry on
  section-stripped ELF / unsupported arch.
- **False-binding risk in `manifest_merge`.** Count-only positional matching binds
  an unnamed stack table to the *first* class with a matching native-method count
  (confirmed: two 1-native-method classes + one 1-addr table binds class A,
  leaves B null). Under generic, stack tables are the common case, so this is
  elevated. Also, an *ambiguous named* table is correctly skipped by the exact
  matcher but then re-bound arbitrarily by the positional fallback, undoing the
  ambiguity guard. Consider leaving ambiguous/collision cases unbound (or flagged
  `ambiguousBinding`) rather than guessing.
- **Tighten the schema** for `nativeRegistry` records (per-`source` `oneOf` or a
  minimal required set) so it validates the new shapes rather than accepting
  anything.
- **PR description** references a committed ELF fixture that is not in the repo;
  either commit it or remove the claim.
- `add_emulated_registry` matches an existing table by exact `fnAddrs` list
  equality (order + identical hex formatting). Robust today, but brittle if either
  producer changes address formatting or ordering.

## Residual risk

- PE loading path and Mach-O are unproven by tests.
- Encrypted/relocated/runtime-decrypted method tables not reachable by emulation
  still yield nothing under generic (acknowledged in docs).
- Positional binding can silently mis-assign when multiple classes share a native
  method count (see Should-fix).
- Linear-sweep disassembly of whole executable sections can desync on embedded
  data; false-positive call sites are harmless (harvest filters them), but missed
  sites in desynced regions are possible.

## Review-fix commits pushed to this branch

- `70cd7a4` docs(lifter): correct `--profile` help; the lifter defaults to
  `generic` and does not auto-detect from a pseudo-C dump.
- `26e4b2d` test(generic): add coverage for the shared_dispatch branch split and
  malformed-table conservatism.

## Tests I ran

- `pytest` across `binary_introspect`, `manifest_merge`, `ast_matcher`:
  **14 passed** (12 pre-existing + 2 added). The 3 existing test files are the
  entire committed suite.
- Built a real SysV `.so` (`gcc -O2 -shared -fPIC`) whose `RegisterNatives`
  compiled to the split `mov rax,[rax+0x6b8]; jmp rax` tail call with a static
  `.data.rel.ro` table, then ran `binary_introspect.core.introspect()`: it
  recovered both methods with correct names, descriptors, and
  relocation-resolved addresses (`profile=generic`, `abi=amd64-sysv`,
  `methodDiscovery=jni-spec`).
- Verified `lief` (installed 1.0.0) loads real ELF sections/relocations via
  `_exec_ranges` / `_mapped_ranges` / `_relocation_targets`.
- Validated old- and new-shape `binary.json` against `schemas/binary.schema.json`
  with `jsonschema` (both valid).
- Probed `manifest_merge.merge()` for the count-collision and ambiguous-named
  cases documented above.
- Not run: the Gradle/JVM build (this PR changes only Python, docs, and the
  schema) and the Windows PE loading path (no PE toolchain available here).

---

# Re-review — after must-fix commits

- Branch re-reviewed: `cursor/generic-first-discovery-ca12` @ `2638079` (base
  `main` @ `3843ec1`).
- New commits since the first review: `f686fd9` (real-ELF discovery test +
  fixtures), `488a19d` (lifter derives profile from the analysis artifact),
  `2638079` (skip the positional fallback for ambiguous named tables).
- Scope: verify the two must-fix items from the first review and check for new
  regressions. No feature work was needed — both must-fixes are satisfied.
- Delivery note: the PR review write path is not available from this
  environment (read-only access to the upstream repository), so this re-review
  is recorded here per the review instructions.

## Ship verdict (re-review)

**Ship as a draft / development merge.** Both original must-fixes are resolved
and the full committed Python suite passes (21 tests, up from 14). The two
items that previously kept this off the default-release path are cleared. What
remains are the should-fix / residual items already listed in the first review;
none of them is a must-fix, so they do not block a draft/dev merge. One of them
(unnamed count-only positional mis-binding) is worth closing before this becomes
the *default* release, because the generic path makes stack-built tables the
common case — see below.

## Must-fix 1 — prove the loading path with a committed end-to-end test: SATISFIED

- A real fixture is now checked into git: `libjni_registrar.so` (13,832-byte
  ELF 64-bit SysV shared object, x86-64, not stripped) alongside its source
  `jni_registrar.c` for reproducibility. `git ls-files` confirms both are
  tracked.
- `test_introspect_real_elf_resolves_static_jni_table_relocations` calls the
  real `binary_introspect.core.introspect()` on that `.so` — i.e. `lief.parse`,
  format/arch detection, section reading, ABI detection, and relocation
  resolution. It is not a mocked parser and not a synthetic byte buffer; the
  earlier parametrized tests build fake instruction bytes, but this one loads
  the committed binary.
- The relocation path is genuinely exercised, not incidentally satisfied. In
  the on-disk image the function-pointer slots of the static `JNINativeMethod[]`
  table (at `0x3ee0`) read as `0x0` (unrelocated), yet `introspect()` recovers
  `fnAddrs = ["0x1000", "0x1010"]` with names/descriptors `alpha ()V` /
  `beta (I)I`. The addresses can only come from applying the ELF relocations,
  so a broken relocation path would fail this assertion rather than silently
  pass. Reported `abi = amd64-sysv`, `arch = x86_64`, `analysis = {profile:
  generic, methodDiscovery: jni-spec}`.
- Residual (unchanged from first review): the PE (`.dll`) and Mach-O loading
  paths still have no committed fixture/test. The ELF loading path — the one the
  "generic-first" claim most depends on — is now proven in CI.

## Must-fix 2 — resolve the lifter default regression: SATISFIED

- The chosen fix is profile derivation, not doc-only. `manifest_merge.merge()`
  now carries `analysis` (including `profile`) from `binary.json` into
  `manifest.json`; the lifter driver selects
  `get_profile(profile_name or manifest.analysis.profile or "generic")`. Order
  is correct: an explicit `--profile` wins, then the recorded artifact profile,
  then conservative `generic`.
- End-to-end the documented flows now recover the pre-PR strength without the
  user re-typing the variant: `recover` and `inspect-binary` auto-detect the
  variant (`_detect_native_obfuscator` scores 0.9 vs generic's 0.01), write it
  to `binary.json.analysis.profile`, `merge-manifest` propagates it, and
  `static-reverse` / `ast_matcher.cli` (invoked with `--manifest` and no
  `--profile`) derive it. `static-lite`'s own example deliberately passes
  `--profile generic` because it is the generic-path example; a variant target
  passed to `static-lite` propagates that variant the same way.
- `generic` remains conservative. It has `invoke_error_re = None`,
  `field_error_re = None`, empty `skip_if_patterns`, and
  `enable_exception_guard_heuristics` / `rewrite_ghidra_vtable_calls` /
  `extract_cache_table` all `False`. The throw-reason parsers short-circuit to
  `[]` when the regex is `None` (`throw_reason.py`), so throw-reason recovery is
  genuinely off under true `generic`. Deriving `native_obfuscator` re-enables
  exactly those knobs, matching `main`.
- CLI/help text and both READMEs plus `docs/generic-recovery.md` now describe
  the derivation and the precedence, so following the docs verbatim no longer
  yields weaker-than-`main` lifting for a `native_obfuscator` target.
- No dangling reference left behind: `detect_profile` was dropped from the
  lifter driver's imports and is not referenced anywhere in `ast_matcher`.

## Ambiguity guard (`2638079`)

- **Named ambiguous tables: fixed.** When a named table's `(name, desc)`
  signature matches more than one class, the exact matcher records the site in
  `ambiguous_named_sites` and the positional count fallback now skips it.
  Verified directly: two 1-native-method classes with the same signature plus a
  1-address named table leave both classes unbound (`boundTo = None`, no
  `fnAddr` assigned) instead of the fallback arbitrarily binding the first.
  `test_ambiguous_named_table_is_not_rebound_by_position` covers this.
- **Unnamed count-only collisions: still mis-bind (residual, not a must-fix).**
  A table that carries only `fnAddrs` and no method names still binds by count
  to the *first* class with a matching native-method count. Verified: two
  1-native-method classes with a single count-only 1-address table bind the
  first class and leave the second null. This is the same should-fix flagged in
  the first review; the new commit intentionally scopes itself to the *named*
  ambiguity. It is the item most worth closing before a default release, since
  generic makes stack/count-only tables common — but it was never a must-fix.

## Tests run (this re-review)

- Installed the workspace's declared deps (`lief` 1.0.0, `capstone` 5.0.7,
  `tree-sitter`/`tree-sitter-c`, `click`) and the three editable packages, then
  ran the full committed suite from `py/` with the repo's `pyproject.toml`
  config: **21 passed** (was 14 at first review — +7 from the three new
  commits). Suites: `binary_introspect/tests`, `manifest_merge/tests`,
  `ast_matcher/tests`.
- Extra manual probes (outside the suite): dumped the raw on-disk table bytes to
  confirm relocation dependence; exercised `merge()` for the named-ambiguous and
  unnamed count-only cases; validated old- and new-shape `manifest.json` against
  the updated `schemas/manifest.schema.json` with `jsonschema` (both valid — the
  schema has no `additionalProperties: false`, and `analysis` is now declared).

## No new regressions found

- `f686fd9` adds only tests and fixtures — no production code touched.
- `488a19d` is additive: `manifest.json` gains an `analysis` object (defaults to
  `{}` when there is no binary report), the schema declares it, and the lifter
  derivation only changes behavior when `--profile` is omitted *and* the
  artifact records a profile. Old-shape manifests still validate and still fall
  back to `generic`.
- `2638079` only narrows the positional fallback (skips ambiguous named sites);
  the existing single-candidate named-binding and count-binding tests still
  pass.

## Leftover risks (carried over; none are must-fix)

- Unnamed count-only positional binding can still silently mis-assign a stack
  table to the wrong class when multiple classes share a native-method count.
- PE (`.dll`) and Mach-O loading paths remain unproven by committed tests; only
  the ELF path has a real fixture.
- Section-header-stripped ELF / unsupported arch still yields a silent empty
  registry (no PT_LOAD segment fallback, no diagnostic).
- Encrypted / runtime-decrypted method tables unreachable by emulation still
  recover nothing under generic (acknowledged in docs).

## Re-review-fix commits

None. Both must-fixes were already satisfied by `f686fd9`, `488a19d`, and
`2638079`; no additional code changes were required on this branch.
