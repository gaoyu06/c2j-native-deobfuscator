# Privileged observer (optional, documentation only)

Status: **not implemented, and nothing in this repository implements
it.** There is no kernel source, no driver project, no build target and
no binary. This document exists so the option is described honestly
before anyone starts, and so the boundary around it is written down.

Read [native-x86-module.md](native-x86-module.md) first; the non-goals
listed there apply here in full and are not relaxed by privilege.

---

## What it would be

A separate, optional component that observes at a higher privilege level
than the user-mode host, for authorized diagnostics on software the user
owns or is otherwise permitted to analyze. Its only job would be to
produce the same generic records the user-mode path produces —
module loads, symbol resolutions, call sites — in situations where a
user-mode observer structurally cannot see them.

It would sit **behind the same plugin ABI**
([plugin-abi.md](plugin-abi.md)). Consumers would not know which
observer produced a record, and would gain no new record types from it.
If a privileged observer would need a new event kind, that is a signal
it has drifted outside the intent described here.

## Why it is optional, and stays optional

- **Nothing depends on it.** JAR recovery does not need `native-x86/`;
  `native-x86/` does not need a privileged observer. Two independent
  layers of "safe to ignore".
- **It cannot be shipped usefully.** See the operator burden below: on a
  stock, fully locked-down desktop the component simply will not load,
  and the project has no intention of changing that.
- **The user-mode path is the product.** If a diagnostic can be done in
  user mode, it should be, and the privileged path should never become
  the default answer to "the user-mode observer missed something".

## What the user would have to do

The component would be **unsigned**. No signed driver is provided, and
distributing one is not planned. Loading unsigned privileged code
requires the machine owner to weaken a platform security guarantee
themselves, deliberately and visibly:

- On Windows: enabling test signing, or booting with driver-signature
  enforcement disabled. Both are global machine states, both are visible
  to the user (a desktop watermark, a changed boot configuration), and
  both may disable other protections — including features that other
  software depends on.
- On Linux: a locally built out-of-tree module, or a local signing key
  enrolled by the machine owner. On a Secure Boot machine with kernel
  lockdown, unsigned modules do not load at all.

This project would never automate those steps, ship a helper that
performs them, or work around them. If the operating system says no,
the answer is no. Nothing here is a bypass of a signing or integrity
check; the only supported route is the machine owner explicitly changing
their own machine's configuration and understanding what they gave up.

## Intent, at a high level

Observe-only, and structural:

- Report the same record kinds the user-mode observer reports.
- Report **program structure** — which image, at which base, which
  symbol, which call site — never program data.
- Stay passive. No modification of the observed target's code, memory,
  data or control flow. No blocking, filtering, injecting or rewriting
  of anything.

Any mechanism detail beyond that statement of intent is intentionally
absent. This is a boundary document, not an implementation guide, and
it should stay that way until there is a concrete, reviewed reason for
the component to exist at all.

## Explicit non-goals

Privilege does not unlock anything that is off-limits in user mode. The
following are excluded here, permanently, and no pull request should
propose them under this heading:

- **No stealth.** No hiding the observer from the target, from the OS,
  from a debugger or from the user. No anti-debug evasion, no
  anti-analysis countermeasures, no attempt to be hard to notice. The
  component is meant to be obvious.
- **No signature or integrity bypass.** Nothing to defeat code signing,
  driver-signature enforcement, secure boot, licensing or tamper checks.
  The user relaxes their own machine's policy or the component does not
  run.
- **No hidden loaders.** No injection, no self-installing service, no
  persistence, no packing or obfuscation of the component itself, and no
  loading of code the user did not name.
- **No interception or modification.** No TLS interception, no traffic
  capture or rewriting, no credential or key capture, no alteration of
  what the target computes. Well-known cryptographic library entry points
  (OpenSSL, CNG, AES primitives) may be *named* and *observed* at
  entry/return as points of interest — the same metadata-only way the
  user-mode host does (see
  [plugins/crypto-libraries.md](plugins/crypto-libraries.md)). Capturing
  the content those functions move, or altering their behaviour, is not
  in scope at any privilege level.
- **No data exfiltration.** Records stay on the machine that produced
  them; the component has no network behaviour.

## Support burden (the reason to say no)

If this component existed, the project would inherit:

- **Per-kernel maintenance.** Privileged interfaces are not stable
  across kernel or OS releases the way user-mode APIs are. Every update
  is a potential rebuild, retest and re-release.
- **Crash blast radius.** A user-mode bug ends a process. A privileged
  bug takes the machine down, and the resulting reports are hard to
  reproduce and hard to triage.
- **Unreproducible environments.** Bug reports would arrive from
  machines in a security configuration the maintainers cannot mirror in
  CI, and CI cannot test the component at all — no hosted runner will
  load an unsigned privileged module.
- **Support questions that are not about this project.** "Test signing
  broke feature X" and "my machine will not boot" become inbox items.
- **Review load.** Every contribution would need review against the
  non-goals above, by someone qualified to judge privileged code.
- **Reputational and distribution risk.** An unsigned privileged
  component attracts both malware heuristics and use cases this project
  refuses to serve.

The honest summary: the cost is high, permanent, and paid by
maintainers, while the benefit applies to a narrow set of cases. A
concrete, repeated diagnostic need that user-mode observation provably
cannot serve is the minimum bar for revisiting this.

## Decision status

Open, and reserved for a human. Nothing about it is settled by the
skeleton in `native-x86/`, and the user-mode ABI does not assume it will
ever exist.
