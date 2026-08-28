# Optional observer contract

This contract is optional and **off by default**. It is not required for
JAR recovery. This project provides **no kernel binary and no kernel source**,
whether signed or unsigned, and has no kernel build target.

Use this path only after user-mode tools have demonstrated a real visibility
gap. If an operator later needs higher-privilege visibility, the operator must
provide and maintain their own component, enable the operating system's
official test-signing or debug configuration themselves, and test-sign that
component under their own policy. This repository neither changes that policy
nor supplies a component to load.

Official platform documentation:

- Microsoft:
  [The TESTSIGNING boot configuration option](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
- Linux kernel:
  [Kernel module signing facility](https://docs.kernel.org/admin-guide/module-signing.html)
  and
  [Kernel lockdown](https://docs.kernel.org/admin-guide/LSM/lockdown.html)

These links describe the supported platform mechanisms. This project does not
reproduce or automate their configuration steps.

## JSON-lines record contract

An operator-provided component may write one UTF-8 JSON object per line. The
only supported record is a module inventory entry:

```json
{"kind":"module-load","process_id":4242,"module_name":"libexample.so","base_address":4194304,"image_size":135168}
```

Every field is required:

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | Always `module-load`. |
| `process_id` | integer | Positive operating-system process identifier. |
| `module_name` | string | Module file name, without file contents. |
| `base_address` | integer | Non-negative load base address. |
| `image_size` | integer | Positive mapped image span in bytes. |

Addresses and sizes are JSON integers, not hexadecimal strings. Additional
fields are not part of this contract. In particular, records have no
`content`, `payload`, raw-byte, argument, return-value, or memory-value field.

This is the JSON-lines representation of the existing user-mode
`module-load` event kind documented in `docs/plugin-abi.md`. Its fields map to
the ABI's module-load event as follows:

| JSON-lines | User-mode module-load event |
|---|---|
| `process_id` | `process_id` |
| `module_name` | `name` |
| `base_address` | `base_address` |
| `image_size` | `image_size` |

The contract does not add an event kind or grant a consumer any additional
operation. Consumers should validate every line independently and reject
unknown kinds or malformed values.

## Userspace contract smoke test

`privileged-observer/mock_observer.py` is a Linux userspace mock, not a
privileged component. Given `--pid` and the explicit
`--i-own-this-process` confirmation, it reads `/proc/<pid>/maps`, verifies
that `/proc/<pid>` is owned by the current effective user, and emits the
records above. It refuses targets owned by any other user.

The mock exists only to exercise parsing and consumer compatibility. It does
not enable test-signing or debug configuration and does not increase process
visibility.

## Non-goals

- No concealment or obscuring of any component or activity.
- No observation of a third-party process that the operator does not own.
- No process modification, code loading, or control-flow changes.
- No content or payload collection.
- No signature-policy workarounds or automated security-policy changes.

Do not enable or build an operator-owned higher-privilege component merely as
a precaution. First demonstrate that the supported user-mode tools cannot
produce the required module inventory.
