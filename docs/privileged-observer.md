# Optional privileged-observer userspace module

This advanced module is optional and **off by default**. It is a userspace
plugin host for JNI-native transpiled JAR recovery; it is not a kernel feature
and is not required for JVMTI, process inspection, or library instrumentation.

This repository ships **no kernel image and no kernel source**. If an operator
needs a higher-privilege backend, they must enable their operating system's
debug or test-signing configuration themselves and build and maintain that
backend out of tree. This repository does not include that backend or automate
those operating-system settings.

## Build and run the Linux backend

The shipped backend reads `/proc/<pid>/maps`. It only reports module path and
mapped address metadata.

```sh
make -C privileged-observer
python3 privileged-observer/observer.py \
  --pid "$$" \
  --i-enable-privileged-observer \
  --i-own-this-process
```

Both confirmation flags are mandatory. The host refuses to load a plugin
without `--i-enable-privileged-observer`, and it refuses a live PID without
`--i-own-this-process`. It also verifies that `/proc/<pid>` belongs to the
current effective user; the Linux plugin independently verifies ownership
before reading the map. Every refusal exits non-zero.

Use `--plugin PATH` to select another compatible userspace plugin. Selecting a
plugin does not bypass either confirmation or the same-user check.

## Versioned plugin ABI

`privileged-observer/include/privileged_observer_plugin.h` defines ABI version
1. A shared-library plugin exports:

```c
const struct po_plugin_v1 *po_plugin_query(uint32_t host_abi_version);
```

The host requests exactly the ABI version it understands and rejects a null,
mismatched, or undersized descriptor. Plugins declare a capability bitmask.
The shipped `linux-proc-maps` plugin declares only `maps-read`; the v1 callback
can emit only a path, base address, and end address.

The ABI contains no process-memory read operation and no channel for keys,
buffers, payloads, or TLS interception. A future on-disk ELF symbol provider
can use a separately versioned metadata capability; v1 does not read or emit
symbols.

## JSON-lines module records

The host normalizes map entries into one UTF-8 JSON object per line:

```json
{"base_address":4194304,"end_address":4329472,"image_size":135168,"kind":"module-load","module_name":"libexample.so","path":"/usr/lib/libexample.so","process_id":4242}
```

All fields are required. Addresses and sizes are JSON integers.

| Field | Meaning |
|---|---|
| `kind` | Always `module-load`. |
| `process_id` | Positive operating-system process identifier. |
| `module_name` | Final component of the mapped module path. |
| `path` | Mapped module path reported by the operating system. |
| `base_address` | Start of the normalized module address range. |
| `end_address` | Exclusive end of the normalized module address range. |
| `image_size` | `end_address - base_address`. |

These are module/map names and addresses only. There are no content,
argument-value, return-value, or raw-memory fields.

## Relationship to native-x86

This module owns the optional privileged-observer contract. The
[native-x86 work in #7](https://github.com/gaoyu06/c2j-native-deobfuscator/pull/7)
is user-mode observation. The two may represent compatible `module-load`
metadata, but this module does not replace native-x86 or make it
higher-privilege.

## Non-goals

- Observing a process that the operator does not own.
- Modifying a process or changing its control flow.
- Collecting process memory, content, or transport data.
- Changing operating-system security policy.
