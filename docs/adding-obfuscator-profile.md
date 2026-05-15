# 适配新的 native obfuscator 变体

j2c-dumper 的静态分析路径用 **profile** 来描述每种混淆器变体的差异。
内置两个：

- `native_obfuscator` — radioegor146/native-obfuscator + 任何兼容的
  衍生（保留 `"Cannot invoke X.Y.Z(args)"` 错误字符串格式 + 每类一次
  RegisterNatives）
- `j2cc` — me.x150.j2cc 单一共享 `initClass` 派发

任何 native-obfuscator-family-compatible 的二进制都可以**开箱即用**自动检测。
要处理一个新变体（例如 BiscuitObfuscator、未来某 obfuscator-X），只需
新建一个 profile。

## 一、profile 包含什么

`py/binary_introspect/binary_introspect/profile.py` 里的
`Profile` 数据类定义了所有可调旋钮：

| 字段 | 干嘛 |
|---|---|
| `name` | CLI 名字 (`--profile <name>`) |
| `arch_filter` / `os_filter` | 只在指定架构/系统启用 (e.g. `("x86_64",) / ("windows",)`) |
| `register_natives_index` | JNI vtable 里 RegisterNatives 的索引，默认 215 |
| `harvest_strategy` | `"per_class"` (每个类一次 RegisterNatives) 或 `"shared_dispatch"` (j2cc 那种共享 dispatch) |
| `invoke_error_re` | 错误字符串正则，定义命名组 `owner` / `name` / `args` |
| `skip_if_patterns` | 一组 `(cond_re, body_re)` — 匹配到的 if 语句被 lifter 丢弃（视为 native-side bookkeeping） |
| `detector` | 可选 callable，给出 0..1 的分数表示当前 binary 是否匹配这个 profile |
| `helper_fingerprints` | 把 Ghidra 输出里的 `FUN_xxxx` 助手按 (参数形状 → 语义) 绑回去 |

## 二、最小变体：仅改错误字符串格式

假设有个 obfuscator-X，错误信息格式从 `"Cannot invoke X.Y.Z(args)"`
改成了 `"Failed to call X.Y.Z(args)"`。这种情况只需复用 native_obfuscator
profile 改一个字段：

```python
# my_profiles/obfuscator_x.py
import re
from binary_introspect.profile import Profile, register_profile

register_profile(Profile(
    name="obfuscator_x",
    description="ObfuscatorX (custom throw-format)",
    arch_filter=("x86_64",),
    invoke_error_re=re.compile(
        r"^Failed\s+to\s+call\s+"
        r"(?P<owner>[\w.$]+)\.(?P<name>[\w$<>]+)"
        r"\((?P<args>[^)]*)\)$"
    ),
    skip_if_patterns=[],   # 不跳过任何 if guards
))
```

放在 `PYTHONPATH` 上即可，启动时 `import` 一下：

```bash
PYTHONPATH=./my_profiles python -c "import obfuscator_x" \
    binary-introspect introspect ./mybin.dll -o binary.json --profile obfuscator_x
```

## 三、深度变体：新 harvest 策略

如果新变体的 RegisterNatives 不是"每个类一次"也不是"j2cc 共享 dispatch"，
而比如**每个类的方法表是 .rdata 里的一个数组、由 init 函数直接传入**——
你需要新加一个 `harvest_strategy` 值并在 `jni_tables.py` 里实现对应函数。

步骤：

1. 在 `profile.py` 的 `harvest_strategy` 字段文档里加上新策略名
2. 在 `jni_tables.py` 的 `find_jni_method_tables` 里加上新分支：
   ```python
   if profile.harvest_strategy == "rdata_table":
       branches = _harvest_rdata_table(cs, site, exec_rngs, profile)
       # ...
   ```
3. 实现 `_harvest_rdata_table` 函数

## 四、自定义检测

`detector` 是个 `Callable[[lief.Binary], float]`：

```python
def my_detect(b):
    # 检查 obfuscator-X 标志性的导出名 / 字符串
    if b.format != lief.Binary.FORMATS.PE: return 0.0
    if any("__obfx_init" in s.name for s in b.exported_symbols): return 0.9
    return 0.0

register_profile(Profile(..., detector=my_detect))
```

自动检测时所有 profile 的 score 取最大值。要让自己的 profile 在歧义场景胜出，
返回 ≥0.9 的高 score。

## 五、运行时强制选择

任何场景下都可以用 `--profile <name>` 跳过自动检测：

```bash
binary-introspect introspect mybin.dll -o binary.json --profile obfuscator_x
binary-introspect introspect mybin.dll -o binary.json --profile generic   # 完全不带任何变体偏好
```

`binary-introspect introspect --list-profiles` 列出已注册的全部 profile。

## 六、当前未参数化、需要 PR 才能扩展的部分

下面这些目前还在硬编码 / 通过假设隐式存在，要支持新变体的话需要改源码：

1. **架构 / ABI**：`mov r9d, imm` 拿 nMethods 是 **Windows x64** 专用。
   Linux SysV x64 是 `rcx`，ARM64 是 `w3`。在 `jni_tables.py:_harvest_call`
   / `_harvest_dispatch` 的寄存器枚举里。
2. **`call qword ptr [reg + 0x6B8]` 指令模式**：默认 Intel 语法 x64 形式。
   ARM 反汇编完全不同。在 `_find_register_natives_calls` 里。
3. **`(**(code **)(*reg + 0xN))(...)` 的 vtable rewrite**：写死了 Ghidra
   x64 输出格式。其他反编译器（IDA Hex-Rays、Binary Ninja）会用别的语法。
4. **Ghidra `local_X` / `lVarN` 变量命名**：lifter 里没显式假设但 regex
   形态隐含依赖。

如果你想接入一个 ARM64 / Linux 二进制的变体，欢迎提 PR 添加 ABI profile
配置项；上面这四个点是接入新架构必须先解决的。
